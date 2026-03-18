// Unified Fuzzing Server — handles TLS, HTTP/2, and QUIC server-side scenarios.
// TLS scenarios (categories A–Y): raw TCP server, per-scenario accept-and-execute.
// HTTP/2 scenarios (categories AA–AJ, side: 'server'): persistent HTTP/2 server,
//   waits for each client connection and calls scenario.serverHandler().
// QUIC scenarios (categories QA–QL, side: 'server'): persistent UDP server,
//   waits for client packets and executes serverHandler or actions.
const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const { Logger } = require('./logger');
const { PcapWriter } = require('./pcap-writer');
const { sendFIN, sendRST, configureSocket, RawTCPSocket, isRawAvailable } = require('./tcp-tricks');
const { parseRecords, buildAlert } = require('./record');
const { ContentType, HandshakeType, AlertLevel, AlertDescription } = require('./constants');
const { validateClientHello, validateServerFlight, validateClientKeyExchange } = require('./tls-validate');
const { gradeResult, computeOverallGrade } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { generateServerCert } = require('./cert-gen');
const { QuicFuzzerServer } = require('./quic-fuzzer-server');

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

// QUIC scenarios have two-letter categories starting with 'Q' (QA–QL, QS, QSCAN)
// Single-letter 'Q' is a TLS category (ClientHello Field Mutations)
function isQuicScenario(scenario) {
  return typeof scenario.category === 'string' && scenario.category.length >= 2
    && scenario.category[0] === 'Q' && /^Q[A-Z]/.test(scenario.category);
}

// Raw TCP category codes start with 'R' followed by A-H (RA–RH)
function isTcpScenario(scenario) {
  return typeof scenario.category === 'string' && scenario.category.length === 2
    && scenario.category[0] === 'R' && scenario.category[1] >= 'A' && scenario.category[1] <= 'H';
}

// H2 scenarios have a serverHandler function; TLS scenarios use actions()
function isH2Scenario(scenario) {
  return !isQuicScenario(scenario) && !isTcpScenario(scenario) && typeof scenario.serverHandler === 'function';
}

class UnifiedServer {
  constructor(opts = {}) {
    this.port = opts.port || 4433;
    this.hostname = opts.hostname || 'localhost';
    this.timeout = opts.timeout || 10000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.pcap = opts.pcapFile ? new PcapWriter(opts.pcapFile, {
      role: 'server',
      serverPort: opts.port || 4433,
      clientPort: 49152 + Math.floor(Math.random() * 16000),
    }) : null;
    this.dut = opts.dut || null;
    this.aborted = false;

    // Active server instances
    this.tlsServer = null;   // net.Server (created per TLS scenario)
    this.h2Server = null;    // http2.Server (persistent, shared across H2 scenarios)
    this.quicServer = null;  // QuicFuzzerServer (persistent, shared across QUIC scenarios)
    this._h2StopResolve = null;
    this._h2ScenarioActive = false;

    // Callback fired when a per-scenario server starts listening.
    // Used by local mode to trigger the well-behaved client connection.
    this._onListening = null;

    // TLS cert — DER format for raw handshake scenarios
    if (opts.cert) {
      this.certDER = opts.cert;
      this.certInfo = opts.certInfo || {};
    } else {
      const gen = generateServerCert(this.hostname);
      this.certDER = gen.certDER;
      this.certInfo = gen;
    }

    // H2 cert — PEM format for Node's http2 module
    if (opts.certInfo && opts.certInfo.certPEM) {
      this.h2CertPEM = opts.certInfo.certPEM;
      this.h2KeyPEM = opts.certInfo.keyPEM;
      this.h2Fingerprint = opts.certInfo.fingerprint;
    } else {
      const h2gen = generateServerCert(this.hostname);
      this.h2CertPEM = derToPem(h2gen.certDER);
      this.h2KeyPEM = h2gen.privateKeyPEM;
      this.h2Fingerprint = h2gen.fingerprint;
    }
  }

  abort() {
    this.aborted = true;
    if (this.tlsServer) this.tlsServer.close();
    if (this.h2Server) this.h2Server.close();
    if (this.quicServer) { this.quicServer.abort(); this.quicServer = null; }
    if (this._h2StopResolve) { this._h2StopResolve(); this._h2StopResolve = null; }
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
  }

  close() {
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
  }

  getCertInfo() {
    return {
      hostname: this.hostname,
      fingerprint: this.certInfo.fingerprint || 'N/A',
      h2Fingerprint: this.h2Fingerprint,
    };
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };

    if (scenario.side === 'client') {
      this.logger.error(`Skipping client-side scenario "${scenario.name}" in server mode`);
      return { scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Client-side scenario cannot run in server mode' };
    }

    if (isTcpScenario(scenario)) return this._runRawTCPScenario(scenario);
    if (isQuicScenario(scenario)) return this._runQuicScenario(scenario);
    if (scenario.useNodeTLS) return this._runNodeTLSServer(scenario);
    return isH2Scenario(scenario)
      ? this._runH2Scenario(scenario)
      : this._runTLSScenario(scenario);
  }

  async runScenarios(scenarios) {
    const results = [];
    for (const scenario of scenarios) {
      if (this.aborted) break;
      const result = await this.runScenario(scenario);
      results.push(result);
      await this._sleep(500);
    }
    const report = computeOverallGrade(results);
    this.logger.summary(results);
    return { results, report };
  }

  // ── Run a scenario on an already-connected socket (used by cluster workers) ─
  runScenarioOnSocket(scenario, socket) {
    this.logger.scenario(scenario.name, scenario.description);
    if (isH2Scenario(scenario)) return this._execH2OnSocket(scenario, socket);
    if (scenario.useNodeTLS) return this._execNodeTLSOnSocket(scenario, socket);
    return this._execTLSOnSocket(scenario, socket);
  }

  // Execute an HTTP/2 server scenario on a pre-connected raw TCP socket
  _execH2OnSocket(scenario, socket) {
    return new Promise((resolve) => {
      this.logger.info(`Handling HTTP/2 scenario "${scenario.name}" on IPC socket`);

      // Create a temporary HTTP/2 server instance to perform TLS and handle the session.
      const h2Server = http2.createSecureServer({
        key: this.h2KeyPEM,
        cert: this.h2CertPEM,
        allowHTTP1: true,
      });

      let resolved = false;
      const finish = (result) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timeout);
        h2Server.close();
        resolve(result);
      };

      const timeout = setTimeout(() => {
        this.logger.error(`Scenario "${scenario.name}" timed out — no HTTP/2 stream received`);
        if (!socket.destroyed) socket.destroy();
        finish({
          scenario: scenario.name, status: 'TIMEOUT',
          response: 'No HTTP/2 stream received within 10s',
        });
      }, 10000);

      // Capture the real TLS socket before HTTP/2 wraps it in a Proxy.
      // This allows writeRawFrame() to write directly without hitting
      // ERR_HTTP2_NO_SOCKET_MANIPULATION.
      let rawSocket = null;
      h2Server.on('connection', (sock) => {
        rawSocket = sock;
      });

      h2Server.on('session', (session) => {
        if (rawSocket) {
          session._rawSocket = rawSocket;
          rawSocket = null;
        }
        session.on('error', (err) => {
          this.logger.info(`H2 session error (expected in fuzz): ${err.message}`);
        });
      });

      h2Server.on('stream', (stream, headers) => {
        clearTimeout(timeout);
        this.logger.info(`HTTP/2 stream received on IPC socket — executing handler`);

        // Catch stream errors to prevent worker crashes
        stream.on('error', (err) => {
          this.logger.info(`H2 stream error (expected in fuzz): ${err.message}`);
        });

        const log = (msg) => this.logger.info(msg);
        try {
          scenario.serverHandler(stream, stream.session, log);
          const res = {
            scenario: scenario.name, description: scenario.description, category: scenario.category,
            status: 'PASSED', expected: scenario.expected, verdict: 'AS EXPECTED',
            response: `Handler executed (cluster worker)`,
          };
          res.finding = gradeResult(res, scenario);
          this.logger.result(scenario.name, 'PASSED', res.response, 'AS EXPECTED');

          // Wait for stream to finish before resolving and closing server
          stream.on('finish', () => finish(res));
          // Safety fallback
          setTimeout(() => finish(res), 2000);
        } catch (e) {
          this.logger.error(`Scenario handler error: ${e.message}`);
          finish({ scenario: scenario.name, status: 'ERROR', response: e.message });
        }
      });

      h2Server.on('error', (err) => {
        this.logger.error(`Temporary H2 server error: ${err.message}`);
        finish({ scenario: scenario.name, status: 'ERROR', response: err.message });
      });

      // Resume socket (may be paused from pauseOnConnect) and hand off to http2 server
      socket.resume();
      h2Server.emit('connection', socket);
    });
  }

  // Execute raw TLS fuzz actions on a pre-connected socket
  _execTLSOnSocket(scenario, socket) {
    return new Promise(async (resolve) => {
      const pcap = this.pcap;
      configureSocket(socket);
      socket.resume(); // unpause if transferred via IPC with pauseOnConnect
      this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);
      if (pcap) pcap.writeTCPHandshake();

      const actions = scenario.actions({ serverCert: this.certDER, hostname: this.hostname });
      let connectionClosed = false;
      let recvBuffer = Buffer.alloc(0);
      let lastResponse = '';
      let rawResponse = null;
      let status = 'PASSED';

      socket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
      socket.on('end', () => {
        this.logger.tcpEvent('received', 'FIN');
        if (pcap) pcap.writeFIN('received');
      });
      socket.on('close', () => { connectionClosed = true; });
      socket.on('error', (err) => {
        if (!connectionClosed) this.logger.error(`Client error: ${err.message}`);
        connectionClosed = true;
      });

      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'send': {
            if (connectionClosed || socket.destroyed) {
              this.logger.error('Cannot send: connection closed'); status = 'DROPPED'; break;
            }
            try {
              socket.write(action.data);
              this.logger.sent(action.data, action.label);
              if (pcap) pcap.writeTLSData(action.data, 'sent');
            } catch (e) { this.logger.error(`Write failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'recv': {
            const alreadyReceived = recvBuffer;
            recvBuffer = Buffer.alloc(0);
            const dataFromWait = await this._waitForData(socket, action.timeout || this.timeout, () => connectionClosed);
            recvBuffer = Buffer.alloc(0);
            const data = Buffer.concat([alreadyReceived, dataFromWait || Buffer.alloc(0)]);
            if (data && data.length > 0) {
              this.logger.received(data);
              if (pcap) pcap.writeTLSData(data, 'received');
              lastResponse = this._describeTLSResponse(data); rawResponse = data;
            } else if (connectionClosed) {
              lastResponse = 'Connection closed'; status = 'DROPPED';
            } else {
              lastResponse = 'Timeout'; status = 'TIMEOUT';
            }
            break;
          }

          case 'delay': await this._sleep(action.ms); break;

          case 'fin': {
            this.logger.tcpEvent('sent', action.label || 'FIN');
            if (pcap) pcap.writeFIN('sent');
            try { await sendFIN(socket); } catch (_) {}
            break;
          }

          case 'rst': {
            this.logger.tcpEvent('sent', action.label || 'RST');
            if (pcap) pcap.writeRST('sent');
            sendRST(socket); connectionClosed = true;
            break;
          }

          case 'validate': {
            if (!rawResponse || rawResponse.length === 0) {
              this.logger.error(`Validation failed (${action.label}): no data received`);
              if (action.alertOnFail && socket && !socket.destroyed && !connectionClosed) {
                const alert = buildAlert(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
                try { socket.write(alert); this.logger.sent(alert, 'Alert(fatal, UNEXPECTED_MESSAGE)'); } catch (_) {}
              }
              status = 'DROPPED';
              break;
            }
            const { records: valRecords } = parseRecords(rawResponse);
            let valid = true;

            if (action.expect.recordType !== undefined) {
              const matching = valRecords.filter(r => r.type === action.expect.recordType);
              if (matching.length === 0) {
                valid = false;
              } else if (action.expect.expectedSequence) {
                const actualTypes = [];
                for (const rec of matching) {
                  let off = 0;
                  while (off + 4 <= rec.payload.length) {
                    actualTypes.push(rec.payload[off]);
                    const msgLen = (rec.payload[off + 1] << 16) | (rec.payload[off + 2] << 8) | rec.payload[off + 3];
                    off += 4 + msgLen;
                  }
                }
                const expected = action.expect.expectedSequence;
                if (actualTypes.length !== expected.length) {
                  valid = false;
                } else {
                  for (let i = 0; i < expected.length; i++) {
                    if (actualTypes[i] !== expected[i]) { valid = false; break; }
                  }
                }
              } else if (action.expect.handshakeTypes) {
                const hsTypes = new Set();
                for (const rec of matching) {
                  let off = 0;
                  while (off + 4 <= rec.payload.length) {
                    hsTypes.add(rec.payload[off]);
                    const msgLen = (rec.payload[off + 1] << 16) | (rec.payload[off + 2] << 8) | rec.payload[off + 3];
                    off += 4 + msgLen;
                  }
                }
                for (const expected of action.expect.handshakeTypes) {
                  if (!hsTypes.has(expected)) { valid = false; break; }
                }
              }
            }

            let contentAlertDesc = AlertDescription.UNEXPECTED_MESSAGE;
            if (valid && action.expect.contentValidate) {
              const validators = { clientHello: validateClientHello, serverFlight: validateServerFlight, clientKeyExchange: validateClientKeyExchange };
              const fn = validators[action.expect.contentValidate];
              if (fn) {
                const result = fn(rawResponse);
                if (!result.valid) {
                  valid = false;
                  contentAlertDesc = result.alertDescription || AlertDescription.UNEXPECTED_MESSAGE;
                  this.logger.error(`Content validation failed (${action.label}): ${result.reason}`);
                }
              }
            }

            if (!valid) {
              this.logger.error(`Validation failed (${action.label}): unexpected TLS message`);
              const alertDesc = contentAlertDesc;
              if (action.alertOnFail && socket && !socket.destroyed && !connectionClosed) {
                const { AlertDescriptionName } = require('./constants');
                const alertName = AlertDescriptionName[alertDesc] || 'UNEXPECTED_MESSAGE';
                const alert = buildAlert(AlertLevel.FATAL, alertDesc);
                try { socket.write(alert); this.logger.sent(alert, `Alert(fatal, ${alertName})`); } catch (_) {}
                if (pcap) pcap.writeTLSData(alert, 'sent');
                status = 'tls-alert-server';
              } else {
                status = 'DROPPED';
              }
            } else {
              this.logger.info(`Validation passed: ${action.label}`);
            }
            break;
          }
        }

        if (action.type === 'validate' && (status === 'DROPPED' || status === 'tls-alert-server')) break;
        if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
      }

      if (!socket.destroyed) socket.destroy();

      if (status === 'PASSED' && lastResponse && /^ClientHello\(/.test(lastResponse)) {
        lastResponse = 'Handshake completed';
      }
      if (lastResponse && /^Alert\(fatal/i.test(lastResponse)) {
        status = 'tls-alert-client';
      }

      const computed = computeExpected(scenario);
      const expected = 'expected' in scenario ? scenario.expected : computed.expected;
      const expectedReason = scenario.expectedReason || computed.reason;
      const verdict = this._computeVerdict(status, expected, lastResponse);
      const result = {
        scenario: scenario.name, description: scenario.description, category: scenario.category,
        status, expected, verdict,
        response: lastResponse || status,
      };
      result.finding = gradeResult(result, scenario);
      this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, false, result.finding);
      resolve(result);
    });
  }

  // Execute a well-behaved (Node TLS) scenario on a pre-connected raw TCP socket
  _execNodeTLSOnSocket(scenario, rawSocket) {
    return new Promise((resolve) => {
      rawSocket.resume(); // unpause if transferred via IPC with pauseOnConnect

      const tlsSocket = new tls.TLSSocket(rawSocket, {
        isServer: true,
        key: this.h2KeyPEM,
        cert: this.h2CertPEM,
        ALPNProtocols: ['h2', 'http/1.1'],
      });

      let lastResponse = '';
      let responded = false;

      tlsSocket.on('secure', () => {
        this.logger.info(`[node-tls] TLS client connected (${tlsSocket.getProtocol()})`);
      });

      tlsSocket.on('data', (data) => {
        if (responded) return;
        responded = true;
        this.logger.received(data);
        lastResponse = 'Client data: ' + data.length + ' bytes';
        try {
          tlsSocket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
        } catch (_) {}
      });

      tlsSocket.on('end', () => {
        if (!responded) { responded = true; lastResponse = 'Client disconnected (no data)'; }
      });

      tlsSocket.on('error', (err) => {
        if (!responded) {
          responded = true;
          lastResponse = err.message || 'TLS handshake failed';
          const result = {
            scenario: scenario.name, description: scenario.description, category: scenario.category,
            status: 'DROPPED', expected: 'PASSED', verdict: 'AS EXPECTED',
            response: lastResponse,
          };
          result.finding = gradeResult(result, scenario);
          this.logger.result(scenario.name, 'DROPPED', lastResponse, 'AS EXPECTED');
          resolve(result);
        }
      });

      setTimeout(() => {
        if (!responded) { responded = true; lastResponse = 'Client connected but no data'; }
        if (!tlsSocket.destroyed) tlsSocket.destroy();
        const computed = computeExpected(scenario);
        const expected = 'expected' in scenario ? scenario.expected : computed.expected;
        const verdict = this._computeVerdict('PASSED', expected, lastResponse);
        const result = {
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          status: 'PASSED', expected, verdict,
          response: lastResponse || 'PASSED',
        };
        result.finding = gradeResult(result, scenario);
        this.logger.result(scenario.name, 'PASSED', lastResponse, verdict);
        resolve(result);
      }, 3000);
    });
  }

  // ── TLS server scenario ─────────────────────────────────────────────────────
  _runTLSScenario(scenario) {
    return new Promise((resolve) => {
      this.logger.scenario(scenario.name, scenario.description);

      let resolved = false;
      const resolveOnce = (result) => {
        if (resolved) return;
        resolved = true;
        if (this.tlsServer) {
          const srv = this.tlsServer;
          this.tlsServer = null;
          srv.getConnections((_, count) => {
            if (count > 0) this.logger.info(`Closing ${count} lingering connection(s)`);
          });
          srv.close(() => resolve(result));
          setTimeout(() => resolve(result), 5000);
        } else {
          resolve(result);
        }
      };

      let acceptTimer = null;

      const connectionHandler = (socket) => {
        clearTimeout(acceptTimer);
        this._execTLSOnSocket(scenario, socket).then(resolveOnce);
      };

      this.tlsServer = net.createServer({ allowHalfOpen: true }, connectionHandler);

      const listenWithRetry = (retriesLeft) => {
        this.tlsServer.listen(this.port, '0.0.0.0', () => {
          this.logger.info(`Fuzzer server listening on 0.0.0.0:${this.port} — waiting for connection...`);
          if (this._onListening) this._onListening();
          acceptTimer = setTimeout(() => {
            const computed = computeExpected(scenario);
            resolveOnce({
              scenario: scenario.name, description: scenario.description, category: scenario.category,
              status: 'TIMEOUT',
              expected: 'expected' in scenario ? scenario.expected : computed.expected,
              verdict: 'N/A',
              response: 'No client connected (accept timeout)',
            });
          }, 30000);
        });

        this.tlsServer.on('error', (err) => {
          if (err.code === 'EADDRINUSE' && retriesLeft > 0) {
            this.logger.info(`Port ${this.port} still in use, retrying in 500ms...`);
            this.tlsServer.close();
            this.tlsServer = net.createServer({ allowHalfOpen: true }, connectionHandler);
            setTimeout(() => listenWithRetry(retriesLeft - 1), 500);
            return;
          }
          this.logger.error(`Server error: ${err.message}`);
          clearTimeout(acceptTimer);
          resolveOnce({ scenario: scenario.name, description: scenario.description, status: 'ERROR', response: err.message });
        });
      };

      listenWithRetry(5);
    });
  }

  // ── Node.js TLS server (real OpenSSL-backed TLS for well-behaved counterpart) ──
  _runNodeTLSServer(scenario) {
    return new Promise((resolve) => {
      this.logger.scenario(scenario.name, scenario.description);

      let resolved = false;
      let server;
      const resolveOnce = (result) => {
        if (resolved) return;
        resolved = true;
        if (server) {
          const srv = server;
          server = null;
          srv.close(() => resolve(result));
          setTimeout(() => resolve(result), 500);
        } else {
          resolve(result);
        }
      };

      let acceptTimer = null;

      const secureConnHandler = (socket) => {
        clearTimeout(acceptTimer);
        this.logger.info(`[node-tls] TLS client connected (${socket.getProtocol()})`);

        let lastResponse = '';
        let responded = false;

        socket.on('data', (data) => {
          if (responded) return;
          responded = true;
          this.logger.received(data);
          lastResponse = 'Client data: ' + data.length + ' bytes';
          try {
            socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
          } catch (_) {}
        });

        socket.on('end', () => {
          if (!responded) {
            responded = true;
            lastResponse = 'Client disconnected (no data)';
          }
        });

        socket.on('error', () => {});

        setTimeout(() => {
          if (!responded) {
            responded = true;
            lastResponse = 'Client connected but no data';
          }
          if (!socket.destroyed) socket.destroy();
          const computed = computeExpected(scenario);
          const expected = 'expected' in scenario ? scenario.expected : computed.expected;
          const verdict = this._computeVerdict('PASSED', expected, lastResponse);
          const result = {
            scenario: scenario.name, description: scenario.description, category: scenario.category,
            status: 'PASSED', expected, verdict,
            response: lastResponse || 'PASSED',
          };
          result.finding = gradeResult(result, scenario);
          this.logger.result(scenario.name, 'PASSED', lastResponse, verdict);
          resolveOnce(result);
        }, 3000);
      };

      const tlsErrorHandler = (err, socket) => {
        clearTimeout(acceptTimer);
        this.logger.info(`[node-tls] TLS client error: ${err.message}`);
        if (socket && !socket.destroyed) socket.destroy();

        let response = 'TLS handshake failed';
        if (err.message) response = err.message;

        const result = {
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          status: 'DROPPED', expected: 'PASSED', verdict: 'AS EXPECTED',
          response,
        };
        result.finding = gradeResult(result, scenario);
        this.logger.result(scenario.name, 'DROPPED', response, 'AS EXPECTED');
        resolveOnce(result);
      };

      const createNodeTLSServer = () => {
        const srv = tls.createServer({
          key: this.h2KeyPEM, cert: this.h2CertPEM,
          rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'],
        });
        srv.on('secureConnection', secureConnHandler);
        srv.on('tlsClientError', tlsErrorHandler);
        return srv;
      };

      server = createNodeTLSServer();

      const listenNodeTLS = (retriesLeft) => {
        server.listen(this.port, '0.0.0.0', () => {
          this.logger.info(`[node-tls] TLS server listening on port ${this.port}`);
          if (this._onListening) this._onListening();
          acceptTimer = setTimeout(() => {
            const computed = computeExpected(scenario);
            resolveOnce({
              scenario: scenario.name, description: scenario.description, category: scenario.category,
              status: 'TIMEOUT', expected: computed.expected, verdict: 'N/A',
              response: 'No client connected (accept timeout)',
            });
          }, 30000);
        });

        server.on('error', (err) => {
          if (err.code === 'EADDRINUSE' && retriesLeft > 0) {
            this.logger.info(`Port ${this.port} still in use, retrying in 500ms...`);
            server.close();
            server = createNodeTLSServer();
            setTimeout(() => listenNodeTLS(retriesLeft - 1), 500);
            return;
          }
          this.logger.error(`[node-tls] Server error: ${err.message}`);
          clearTimeout(acceptTimer);
          resolveOnce({ scenario: scenario.name, description: scenario.description, status: 'ERROR', response: err.message });
        });
      };

      listenNodeTLS(5);
    });
  }

  // ── HTTP/2 server scenario ──────────────────────────────────────────────────

  /**
   * Start the HTTP/2 server if not already running.
   * Call this explicitly for passive server mode (no scenarios).
   */
  async startH2() {
    if (this.h2Server) return;

    this.h2Server = http2.createSecureServer({
      key: this.h2KeyPEM,
      cert: this.h2CertPEM,
      allowHTTP1: true,
    });

    this.h2Server.on('error', (err) => { this.logger.error(`HTTP/2 server error: ${err.message}`); });

    // Capture the real TLS socket before the HTTP/2 session wraps it in a Proxy.
    // This allows writeRawFrame() to write directly without hitting
    // ERR_HTTP2_NO_SOCKET_MANIPULATION or native assertion crashes.
    this.h2Server.on('connection', (socket) => {
      this._h2RawSocket = socket;
    });

    this.h2Server.on('session', (session) => {
      // Attach the raw socket to the session for writeRawFrame() to use
      if (this._h2RawSocket) {
        session._rawSocket = this._h2RawSocket;
        this._h2RawSocket = null;
      }
      const remoteAddr = session.socket ? session.socket.remoteAddress : 'unknown';
      this.logger.info(`HTTP/2 session from ${remoteAddr}`);
      session.on('error', (err) => { this.logger.error(`Session error: ${err.message}`); });
      session.on('close', () => { this.logger.info(`Session closed from ${remoteAddr}`); });
    });

    // Default handler: when a scenario is active, dispatch to its handler.
    // When a scenario is waiting, queue the stream.
    // When idle (passive mode), respond 200.
    this._h2PendingStreams = [];
    this._h2StreamHandler = null;

    this.h2Server.on('stream', (stream, headers) => {
      // 1. If a scenario is waiting for its first stream, give it directly
      if (this._h2StreamHandler) {
        const handler = this._h2StreamHandler;
        this._h2StreamHandler = null;
        handler(stream);
        return;
      }

      // 2. Queue streams that arrive between scenarios (client connected early)
      if (this._h2WaitingForStream) {
        this._h2PendingStreams.push(stream);
        return;
      }

      // 3. Passive mode default response
      const method = headers[':method'] || 'UNKNOWN';
      const path = headers[':path'] || '/';
      this.logger.info(`HTTP/2 request: ${method} ${path}`);
      try { stream.respond({ ':status': 200, 'content-type': 'text/plain' }); stream.end('HTTP/2 OK'); } catch (_) {}
    });

    await new Promise((resolve, reject) => {
      this.h2Server.listen(this.port, '0.0.0.0', () => {
        this.logger.info(
          `HTTP/2 server listening on 0.0.0.0:${this.port} | ` +
          `cert SHA256=${this.h2Fingerprint.slice(0, 16)}...`
        );
        resolve();
      });
      this.h2Server.once('error', reject);
    });
  }

  async _runH2Scenario(scenario) {
    if (!this.h2Server) await this.startH2();
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, scenario.description);
    this.logger.info(`Waiting for client to connect on port ${this.port}...`);
    // Signal that the server is ready for a client connection
    if (this._onListening) this._onListening();

    // Signal that we're about to wait, so the default handler queues streams
    this._h2WaitingForStream = true;

    return new Promise((resolve) => {
      const finish = (result) => {
        this._h2ScenarioActive = false;
        this._h2WaitingForStream = false;
        this._h2StreamHandler = null;
        resolve(result);
      };

      const handleStream = (stream) => {
        this._h2ScenarioActive = true;
        clearTimeout(scenarioTimeout);

        // Prevent unhandled stream errors from crashing the process
        stream.on('error', (err) => {
          this.logger.info(`Stream error (expected during fuzz): ${err.message}`);
        });

        const remoteAddr = stream.session && stream.session.socket
          ? stream.session.socket.remoteAddress : 'unknown';
        this.logger.info(`Client connected from ${remoteAddr} — executing scenario handler`);

        const log = (msg) => this.logger.info(msg);
        try {
          scenario.serverHandler(stream, stream.session, log);
          const res = {
            scenario: scenario.name, description: scenario.description, category: scenario.category,
            status: 'PASSED', expected: scenario.expected, verdict: 'AS EXPECTED',
            response: `Handler executed (client: ${remoteAddr})`,
          };
          res.finding = gradeResult(res, scenario);
          this.logger.result(
            scenario.name, 'PASSED', res.response, 'AS EXPECTED',
            scenario.expectedReason || '', false, res.finding
          );
          finish(res);
        } catch (e) {
          this.logger.error(`Scenario handler error: ${e.message}`);
          const res = {
            scenario: scenario.name, description: scenario.description, category: scenario.category,
            status: 'ERROR', expected: scenario.expected, verdict: 'N/A',
            response: e.message,
          };
          res.finding = gradeResult(res, scenario);
          finish(res);
        }
      };

      const scenarioTimeout = setTimeout(() => {
        this._h2StreamHandler = null;
        this.logger.error(`Scenario "${scenario.name}" timed out — no client connected.`);
        finish({
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          severity: 'high', status: 'TIMEOUT',
          expected: scenario.expected, verdict: 'N/A',
          response: 'No client connected within 60s',
          compliance: null, finding: 'timeout', hostDown: false, probe: null,
        });
      }, 60000);

      // Check if a stream was queued (client connected between scenarios)
      if (this._h2PendingStreams && this._h2PendingStreams.length > 0) {
        const queued = this._h2PendingStreams.shift();
        this.logger.info('Using queued stream from early client connection');
        handleStream(queued);
        return;
      }

      // Register ourselves as the current stream handler
      this._h2StreamHandler = (stream) => { handleStream(stream); };
    });
  }

  /**
   * Returns a promise that resolves when abort() is called.
   * Use for passive H2 server mode (no scenarios — just listening).
   */
  waitForStop() {
    return new Promise((resolve) => {
      if (this.aborted) return resolve();
      this._h2StopResolve = resolve;
    });
  }

  // ── Raw TCP server scenario ────────────────────────────────────────────────

  async _runRawTCPScenario(scenario) {
    if (!isRawAvailable()) {
      this.logger.error(`Skipping raw TCP scenario "${scenario.name}" — raw sockets not available`);
      return {
        scenario: scenario.name, description: scenario.description, category: scenario.category,
        status: 'SKIPPED', expected: scenario.expected, verdict: 'N/A',
        response: 'Raw sockets not available (requires CAP_NET_RAW on Linux)',
      };
    }

    this.logger.scenario(scenario.name, scenario.description);

    // Server-side raw TCP: accept a connection on the normal TCP server,
    // then use a RawTCPSocket for raw actions on the established connection.
    return new Promise((resolve) => {
      let acceptTimer = null;

      this.tlsServer = net.createServer({ allowHalfOpen: true }, async (socket) => {
        clearTimeout(acceptTimer);
        configureSocket(socket);
        this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);

        const actions = scenario.actions({ serverCert: this.certDER, hostname: this.hostname });
        let connectionClosed = false;
        let recvBuffer = Buffer.alloc(0);
        let lastResponse = '';
        let status = 'PASSED';

        // Create a RawTCPSocket for raw operations on this connection
        let rawSocket = null;
        try {
          rawSocket = new RawTCPSocket({
            srcIP: socket.localAddress,
            dstIP: socket.remoteAddress,
            srcPort: socket.localPort,
            dstPort: socket.remotePort,
            logger: this.logger,
          });
          if (this.pcap) {
            rawSocket.onPacket = (packet, dir) => this.pcap.writeRawPacket(packet, dir);
          }
          // The raw socket state is ESTABLISHED since we accepted via net.Server
          rawSocket.state = 'ESTABLISHED';
        } catch (e) {
          this.logger.error(`Failed to create raw socket: ${e.message}`);
        }

        socket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
        socket.on('end', () => { connectionClosed = true; });
        socket.on('close', () => { connectionClosed = true; });
        socket.on('error', () => { connectionClosed = true; });

        for (const action of actions) {
          if (this.aborted) { status = 'ABORTED'; break; }

          switch (action.type) {
            case 'rawSend': {
              if (!rawSocket) { status = 'ERROR'; lastResponse = 'No raw socket'; break; }
              try {
                await rawSocket.sendSegment({
                  flags: action.flags || '',
                  data: action.data,
                  seqOffset: action.seqOffset,
                  ackOffset: action.ackOffset,
                  window: action.window,
                  urgentPointer: action.urgentPointer,
                });
                this.logger.fuzz(action.label || `Raw TCP [${action.flags}]`);
              } catch (e) {
                this.logger.error(`Raw send failed: ${e.message}`);
                status = 'ERROR';
              }
              break;
            }

            case 'send': {
              if (connectionClosed || socket.destroyed) {
                this.logger.error('Cannot send: connection closed'); status = 'DROPPED'; break;
              }
              try {
                socket.write(action.data);
                this.logger.sent(action.data, action.label);
              } catch (e) { this.logger.error(`Write failed: ${e.message}`); status = 'DROPPED'; }
              break;
            }

            case 'recv': {
              const alreadyReceived = recvBuffer;
              recvBuffer = Buffer.alloc(0);
              const dataFromWait = await this._waitForData(socket, action.timeout || this.timeout, () => connectionClosed);
              recvBuffer = Buffer.alloc(0); // clear data already captured by _waitForData
              const data = Buffer.concat([alreadyReceived, dataFromWait || Buffer.alloc(0)]);
              if (data && data.length > 0) {
                this.logger.received(data);
                lastResponse = this._describeTLSResponse(data);
              } else if (connectionClosed) {
                lastResponse = 'Connection closed'; status = 'DROPPED';
              } else {
                lastResponse = 'Timeout'; status = 'TIMEOUT';
              }
              break;
            }

            case 'delay': await this._sleep(action.ms); break;

            case 'fin': {
              this.logger.tcpEvent('sent', action.label || 'FIN');
              try { await sendFIN(socket); } catch (_) {}
              break;
            }

            case 'rst': {
              this.logger.tcpEvent('sent', action.label || 'RST');
              sendRST(socket); connectionClosed = true;
              break;
            }

            case 'tcpProbe': {
              const alive = await RawTCPSocket.probe(socket.remoteAddress, socket.remotePort, 2000);
              this.logger.info(`TCP probe: ${alive ? 'alive' : 'dead'}`);
              break;
            }
          }

          if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
        }

        if (!socket.destroyed) socket.destroy();
        if (rawSocket && !rawSocket.destroyed) rawSocket.destroy();

        const computed = computeExpected(scenario);
        const expected = 'expected' in scenario ? scenario.expected : computed.expected;
        const expectedReason = scenario.expectedReason || computed.reason;
        const verdict = this._computeVerdict(status, expected, lastResponse);
        const result = {
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          status, expected, verdict,
          response: lastResponse || status,
        };
        result.finding = gradeResult(result, scenario);
        this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, false, result.finding);

        if (this.tlsServer) {
          this.tlsServer.close();
          this.tlsServer = null;
        }
        resolve(result);
      });

      this.tlsServer.listen(this.port, '0.0.0.0', () => {
        this.logger.info(`Raw TCP server listening on 0.0.0.0:${this.port} — waiting for connection...`);
        acceptTimer = setTimeout(() => {
          const computed = computeExpected(scenario);
          if (this.tlsServer) {
            this.tlsServer.close();
            this.tlsServer = null;
          }
          resolve({
            scenario: scenario.name, description: scenario.description, category: scenario.category,
            status: 'TIMEOUT',
            expected: 'expected' in scenario ? scenario.expected : computed.expected,
            verdict: 'N/A',
            response: 'No client connected (accept timeout)',
          });
        }, 30000);
      });

      this.tlsServer.on('error', (err) => {
        this.logger.error(`Server error: ${err.message}`);
        clearTimeout(acceptTimer);
        resolve({ scenario: scenario.name, description: scenario.description, status: 'ERROR', response: err.message });
      });
    });
  }

  // ── QUIC server scenario ───────────────────────────────────────────────────

  async startQuic() {
    if (this.quicServer) return;

    // Server-side QUIC scenarios send raw crafted packets to connecting clients.
    // They need the raw UDP QuicFuzzerServer, not quiche (which is a compliant
    // implementation that can't produce malformed frames).
    this.quicServer = new QuicFuzzerServer({
      port: this.port,
      hostname: this.hostname,
      timeout: this.timeout,
      delay: this.delay,
      logger: this.logger,
    });
    await this.quicServer.start();
  }

  async _runQuicScenario(scenario) {
    if (!this.quicServer) await this.startQuic();
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };
    // Signal that the server is ready for a client connection
    if (this._onListening) this._onListening();
    return this.quicServer.runScenario(scenario);
  }

  // ── Shared helpers ──────────────────────────────────────────────────────────

  _describeTLSResponse(data) {
    const { records } = parseRecords(data);
    if (records.length === 0) return `Raw data (${data.length} bytes)`;

    // Check for alerts first — most important signal
    for (const r of records) {
      if (r.type === ContentType.ALERT && r.raw.length >= 7) {
        const level = r.raw[5] === AlertLevel.FATAL ? 'fatal' : 'warning';
        const { AlertDescriptionName } = require('./constants');
        const desc = AlertDescriptionName[r.raw[6]] || `Unknown(${r.raw[6]})`;
        return `Alert(${level}, ${desc})`;
      }
    }

    // Check for ServerHello or ClientHello — extract negotiated details
    for (const r of records) {
      if (r.type === ContentType.HANDSHAKE && r.payload.length >= 1) {
        const hsType = r.payload[0];
        if (hsType === HandshakeType.SERVER_HELLO && r.payload.length >= 40) {
          const { CipherSuiteName, VersionName, getServerHelloVersion } = require('./constants');
          const realVersion = getServerHelloVersion(r.payload);
          const sidLen = r.payload[38];
          const csOffset = 39 + sidLen;
          if (csOffset + 1 < r.payload.length) {
            const cs = (r.payload[csOffset] << 8) | r.payload[csOffset + 1];
            const vName = VersionName[realVersion] || `0x${realVersion.toString(16)}`;
            const csName = CipherSuiteName[cs] || `0x${cs.toString(16)}`;
            return `ServerHello(${vName}, ${csName})`;
          }
          const vName = VersionName[realVersion] || `0x${realVersion.toString(16)}`;
          return `ServerHello(${vName})`;
        }
        if (hsType === HandshakeType.CLIENT_HELLO && r.payload.length >= 40) {
          const bodyVersion = (r.payload[4] << 8) | r.payload[5];
          const { VersionName } = require('./constants');
          const vName = VersionName[bodyVersion] || `0x${bodyVersion.toString(16)}`;
          return `ClientHello(${vName})`;
        }
      }
    }

    // Fallback: describe record types
    const { describeTLS } = require('./logger');
    return records.map(r => describeTLS(r.raw)).join(' + ');
  }

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';

    // TLS alert statuses are always expected — server/client responded per protocol
    if (status === 'tls-alert-server' || status === 'tls-alert-client') return 'AS EXPECTED';

    // Response-aware verdict: coherent TLS responses indicate proper behavior
    if (response) {
      if (/^ServerHello\(/i.test(response)) return 'AS EXPECTED';
      if (/^ClientHello\(/i.test(response)) return 'AS EXPECTED';
      if (/^Handshake completed/i.test(response)) return 'AS EXPECTED';
    }

    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    return effective === expected ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  _waitForData(socket, timeout, isClosedFn) {
    return new Promise((resolve) => {
      let buf = Buffer.alloc(0);
      let timer;
      let settled = false;

      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.removeListener('data', onData);
        resolve(buf.length > 0 ? buf : null);
      };

      const onData = (data) => {
        buf = Buffer.concat([buf, data]);
        clearTimeout(timer);
        timer = setTimeout(done, 200);
      };

      socket.on('data', onData);
      timer = setTimeout(done, timeout);

      const checkClosed = setInterval(() => {
        if (isClosedFn() || socket.destroyed) {
          clearInterval(checkClosed);
          setTimeout(done, 100);
        }
      }, 50);
    });
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = { UnifiedServer };
