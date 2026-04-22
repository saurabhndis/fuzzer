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
const { Barrier } = require('./barrier');
const { PcapWriter } = require('./pcap-writer');
const { sendFIN, sendRST, configureSocket, RawTCPSocket, isRawAvailable } = require('./tcp-tricks');
const { parseRecords, buildAlert } = require('./record');
const { ContentType, HandshakeType, AlertLevel, AlertDescription } = require('./constants');
const { validateClientHello, validateServerFlight, validateClientKeyExchange } = require('./tls-validate');
const { gradeResult, computeOverallGrade } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { generateServerCert } = require('./cert-gen');
const { QuicFuzzerServer } = require('./quic-fuzzer-server');
const { SHUTDOWN_HOSTNAME, SHUTDOWN_PATH } = require('./shutdown-signal');

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = (b64.match(/.{1,64}/g) || []).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

function isShutdownSNI(data) {
  if (!data || data.length < 5) return false;
  // Look for TLS ClientHello and extract SNI if possible (simple search for hostname)
  const str = data.toString('utf8');
  return str.includes(SHUTDOWN_HOSTNAME);
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
    this.pcapFileBase = opts.pcapFile || null;
    this.mergePcap = opts.mergePcap || false;
    this.pcap = null;
    this.dut = opts.dut || null;
    this.aborted = false;
    // Set by the controller via /abort-scenario when the peer has finished and
    // wants this side to release any outstanding recv. Also set by /stop.
    // Action loops and _waitForData check it to bail out of awaits promptly.
    this._scenarioAborted = false;
    // Cross-peer sync primitive; see lib/barrier.js.
    this.barrier = new Barrier(this.logger, 'server');

    // Active server instances (all persistent — started once, reused across scenarios)
    this.tcpServer = null;   // net.Server (shared across TLS, NodeTLS, Custom, RawTCP scenarios)
    this.h2Server = null;    // http2.Server (shared across H2 scenarios)
    this.quicServer = null;  // QuicFuzzerServer (shared across QUIC scenarios)
    this._h2StopResolve = null;
    this._h2ScenarioActive = false;
    this.activeSockets = new Set();

    // TCP connection routing — incoming connections are always queued; each scenario
    // consumes one from the queue or waits for the next arrival.
    this._tcpConnectionHandler = null;   // callback for the next connection
    this._tcpPendingConnections = [];    // queued connections not yet claimed

    // Callback fired when a scenario is ready for a client connection.
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
    if (this.tcpServer) { try { this.tcpServer.close(); } catch (_) {} this.tcpServer = null; }
    if (this.h2Server) { try { this.h2Server.close(); } catch (_) {} this.h2Server = null; }
    if (this.quicServer) { this.quicServer.abort(); this.quicServer = null; }
    if (this._h2StopResolve) { this._h2StopResolve(); this._h2StopResolve = null; }
    this._tcpConnectionHandler = null;
    while (this._tcpPendingConnections.length > 0) {
      const s = this._tcpPendingConnections.shift();
      try { if (!s.destroyed) s.destroy(); } catch (_) {}
    }

    for (const socket of this.activeSockets) {
      try { if (!socket.destroyed) socket.destroy(); } catch (_) {}
    }
    this.activeSockets.clear();

    if (this.pcap) { this.pcap.close(); this.pcap = null; }
  }

  close() {
    this.abort();
  }

  getCertInfo() {
    return {
      hostname: this.hostname,
      fingerprint: this.certInfo.fingerprint || 'N/A',
      h2Fingerprint: this.h2Fingerprint,
      certDER: this.certDER,
      certPEM: this.h2CertPEM,
      keyPEM: this.h2KeyPEM,
      privateKeyPEM: this.certInfo.privateKeyPEM,
    };
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };

    // Fresh scenario — clear any abort flag set by a previous peer-done
    // and reject any lingering barriers from the previous run.
    this._scenarioAborted = false;
    if (this.barrier) this.barrier.releaseAll('new scenario start');

    if (scenario.side === 'client') {
      this.logger.error(`Skipping client-side scenario "${scenario.name}" in server mode`);
      return { scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Client-side scenario cannot run in server mode' };
    }

    // Initialize per-scenario PCAP if a base filename was provided
    if (this.pcapFileBase) {
      const path = require('path');
      const ext = path.extname(this.pcapFileBase) || '.pcap';
      const base = this.pcapFileBase.endsWith(ext)
        ? this.pcapFileBase.slice(0, -ext.length)
        : this.pcapFileBase;
      
      const pcapFilename = this.mergePcap 
        ? this.pcapFileBase 
        : `${base}.${scenario.name}.server${ext}`;

      try {
        const { clientIP, serverIP } = require('./pcap-writer').resolveIPs(this.hostname);

        this.pcap = new PcapWriter(pcapFilename, {
          role: 'server',
          append: this.mergePcap,
          clientIP,
          serverIP,
          serverPort: this.port,
          clientPort: 49152 + Math.floor(Math.random() * 16000),
        });
      } catch (e) {
        this.logger.error(`Failed to initialize PCAP: ${e.message}`);
        this.pcap = null;
      }
    }

    // Safety timeout: no scenario should ever take more than 90 seconds
    const result = await new Promise((resolve) => {
      let resolved = false;
      const timer = setTimeout(() => {
        if (resolved) return;
        resolved = true;
        this.logger.error(`Scenario ${scenario.name} forced timeout after 90s`);
        this.abort(); // Attempt to break the hang
        this.aborted = false; // Reset so next scenario can run
        resolve({
          scenario: scenario.name,
          description: scenario.description,
          status: 'TIMEOUT',
          response: 'Forced timeout (90s safety limit)',
        });
      }, 90000);

      const finish = (r) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timer);
        resolve(r);
      };

      const run = async () => {
        let r;
        if (isTcpScenario(scenario)) r = await this._runRawTCPScenario(scenario);
        else if (isQuicScenario(scenario)) r = await this._runQuicScenario(scenario);
        else if (scenario.useNodeTLS) r = await this._runNodeTLSServer(scenario);
        else if (scenario.useCustomServer) r = await this._runCustomServerScenario(scenario);
        else if (isH2Scenario(scenario)) r = scenario.useRawTLS ? await this._runH2RawTLSScenario(scenario) : await this._runH2Scenario(scenario);
        else r = await this._runTLSScenario(scenario);
        finish(r);
      };

      run().catch((e) => {
        finish({
          scenario: scenario.name,
          description: scenario.description,
          status: 'ERROR',
          response: e.message,
        });
      });
    });

    if (this.pcap) {
      this.pcap.close();
      this.pcap = null;
    }
    return result;
  }

  async runScenarios(scenarios) {
    const results = [];
    // Group scenarios by transport so we don't churn the listener (TCP↔H2↔QUIC).
    // Each protocol switch tears down one server, sleeps 100–300ms, then starts
    // another. Stable-sorted batches keep the listener up across many scenarios.
    const ordered = this._groupByTransport(scenarios);
    for (const scenario of ordered) {
      if (this.aborted) break;
      // Ensure no leftover sockets/servers from previous scenario leak FDs
      this._cleanupBetweenScenarios();
      const result = await this.runScenario(scenario);
      results.push(result);
      await this._sleep(500);
    }
    const report = computeOverallGrade(results);
    this.logger.summary(results);
    return { results, report };
  }

  // Stable sort scenarios into transport groups so the listener stays up for
  // long runs of the same type. Order: TCP/TLS → H2 → QUIC. Within each group
  // the original order is preserved.
  _groupByTransport(scenarios) {
    const rank = (s) => {
      if (isQuicScenario(s)) return 2;
      if (isH2Scenario(s)) return 1;
      return 0; // TCP/TLS/raw — everything that runs on the shared TCP listener
    };
    return scenarios
      .map((s, i) => ({ s, i, r: rank(s) }))
      .sort((a, b) => (a.r - b.r) || (a.i - b.i))
      .map(x => x.s);
  }

  _cleanupBetweenScenarios() {
    // Destroy any lingering sockets from the previous scenario
    for (const socket of this.activeSockets) {
      try { if (!socket.destroyed) socket.destroy(); } catch (_) {}
    }
    this.activeSockets.clear();
    // Reset TCP connection routing — pending connections are preserved since
    // the client may have already sent the next connection.
    this._tcpConnectionHandler = null;
    // Drain dead sockets from the pending queue. PCAP scenarios in particular
    // can leave RST'd sockets behind that the next scenario would otherwise
    // pull off the queue and immediately fail/timeout on. Live sockets stay
    // queued so a fast client connecting between scenarios isn't dropped.
    if (Array.isArray(this._tcpPendingConnections) && this._tcpPendingConnections.length > 0) {
      const live = [];
      for (const sock of this._tcpPendingConnections) {
        if (sock && !sock.destroyed && sock.readable && sock.writable) {
          live.push(sock);
        } else {
          try { if (sock && !sock.destroyed) sock.destroy(); } catch (_) {}
        }
      }
      this._tcpPendingConnections = live;
    }
    // Note: tcpServer, h2Server, quicServer stay alive (persistent)
  }

  // ── Persistent TCP server (shared across TLS, NodeTLS, Custom, RawTCP scenarios) ──

  async startTcp() {
    if (this.tcpServer) return;

    this._tcpPendingConnections = [];
    this._tcpConnectionHandler = null;

    const createServer = () => {
      const srv = net.createServer({ allowHalfOpen: true }, (socket) => {
        // If a scenario is actively waiting for a connection, deliver it directly
        if (this._tcpConnectionHandler) {
          const handler = this._tcpConnectionHandler;
          this._tcpConnectionHandler = null;
          this.activeSockets.add(socket);
          socket.on('close', () => this.activeSockets.delete(socket));
          handler(socket);
          return;
        }

        // Otherwise always queue — the next scenario will consume it.
        // This prevents connections from being destroyed in the gap between
        // one scenario finishing and the next calling _waitForTcpConnection().
        this._tcpPendingConnections.push(socket);
      });

      srv.on('error', (err) => {
        if (err.code !== 'EADDRINUSE') {
          this.logger.error(`TCP server error: ${err.message}`);
        }
      });

      return srv;
    };

    this.tcpServer = createServer();

    await new Promise((resolve, reject) => {
      const listenWithRetry = (srv, retriesLeft) => {
        if (this.aborted) return;
        const bindAddr = this.bindAddress || (this.hostname === 'localhost' ? '::' : this.hostname);
        srv.listen(this.port, bindAddr, () => {
          this.logger.info(`TCP server listening on ${bindAddr}:${this.port}`);
          resolve();
        });

        srv.once('error', (err) => {
          if (this.aborted) return;
          if (err.code === 'EADDRINUSE' && retriesLeft > 0) {
            if (retriesLeft % 5 === 0) {
              this.logger.info(`Port ${this.port} in use, retrying (${retriesLeft} left)...`);
            }
            srv.close();
            const nextSrv = createServer();
            this.tcpServer = nextSrv;
            setTimeout(() => listenWithRetry(nextSrv, retriesLeft - 1), 500);
            return;
          }
          reject(err);
        });
      };

      listenWithRetry(this.tcpServer, 30);
    });
  }

  _waitForTcpConnection(timeoutMs = 60000, expectData = true) {
    return new Promise((resolve, reject) => {
      // Attach data + end/close + timer listeners to a socket that's already
      // accepted. A connected-but-silent peer (pre-connect + FIN) must still
      // resolve — otherwise the scenario hangs until the global watchdog.
      const attachReadiness = (socket, sourceLabel) => {
        let settled = false;
        const finish = (action) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          socket.removeListener('data', onData);
          socket.removeListener('end', onClose);
          socket.removeListener('close', onClose);
          socket.removeListener('error', onClose);
          action();
        };
        const onData = (data) => {
          if (isShutdownSNI(data)) {
            finish(() => {
              this.logger.info(`Shutdown signal received on ${sourceLabel} TCP socket (SNI: ${SHUTDOWN_HOSTNAME})`);
              this.abort();
              reject(new Error('Server shutdown by client signal'));
            });
            return;
          }
          finish(() => {
            socket.unshift(data);
            if (sourceLabel === 'queued') this.logger.info('Using queued connection from early client');
            this.activeSockets.add(socket);
            socket.on('close', () => this.activeSockets.delete(socket));
            resolve(socket);
          });
        };
        const onClose = () => {
          finish(() => {
            // Peer connected then closed without sending data. Resolve with the
            // socket so the scenario records 'Connection closed' rather than
            // hanging on this promise.
            this.activeSockets.add(socket);
            socket.on('close', () => this.activeSockets.delete(socket));
            resolve(socket);
          });
        };
        const timer = setTimeout(() => {
          finish(() => reject(new Error('No client data (accept timeout)')));
        }, timeoutMs);

        socket.on('data', onData);
        socket.on('end', onClose);
        socket.on('close', onClose);
        socket.on('error', onClose);
      };

      // Check queue first — client may have already connected
      if (this._tcpPendingConnections.length > 0) {
        const queued = this._tcpPendingConnections.shift();

        if (!expectData) {
          this.activeSockets.add(queued);
          queued.on('close', () => this.activeSockets.delete(queued));
          resolve(queued);
          return;
        }

        attachReadiness(queued, 'queued');
        return;
      }

      const acceptTimer = setTimeout(() => {
        this._tcpConnectionHandler = null;
        reject(new Error('No client connected (accept timeout)'));
      }, timeoutMs);

      this._tcpConnectionHandler = (socket) => {
        clearTimeout(acceptTimer);

        if (!expectData) {
          this.activeSockets.add(socket);
          socket.on('close', () => this.activeSockets.delete(socket));
          resolve(socket);
          return;
        }

        attachReadiness(socket, 'new');
      };
    });
  }

  async _ensureServerType(type) {
    if (type === 'tcp') {
      if (this.h2Server) {
        this.logger.info('Closing H2 server for TCP scenarios');
        try { this.h2Server.close(); } catch (_) {}
        this.h2Server = null;
        await this._sleep(100);
      }
      if (this.quicServer) {
        this.logger.info('Closing QUIC server for TCP scenarios');
        try { this.quicServer.abort(); } catch (_) {}
        this.quicServer = null;
        await this._sleep(200);
      }
      await this.startTcp();
    } else if (type === 'h2') {
      if (this.tcpServer) {
        this.logger.info('Closing TCP server for H2 scenarios');
        try { this.tcpServer.close(); } catch (_) {}
        this.tcpServer = null;
        await this._sleep(100);
      }
      if (this.quicServer) {
        this.logger.info('Closing QUIC server for H2 scenarios');
        try { this.quicServer.abort(); } catch (_) {}
        this.quicServer = null;
        await this._sleep(200);
      }
      await this.startH2();
    }
    // QUIC: the @currentspace/http3 QuicheServer binds BOTH UDP and TCP on the
    // same port (for Alt-Svc fallback), so we must close H2/TCP first.
    if (type === 'quic') {
      if (this.h2Server) {
        this.logger.info('Closing H2 server for QUIC scenarios');
        try { this.h2Server.close(); } catch (_) {}
        this.h2Server = null;
        await this._sleep(200);
      }
      if (this.tcpServer) {
        this.logger.info('Closing TCP server for QUIC scenarios');
        try { this.tcpServer.close(); } catch (_) {}
        this.tcpServer = null;
        await this._sleep(200);
      }
    }
  }

  // ── Run a scenario on an already-connected socket (used by cluster workers) ─
  runScenarioOnSocket(scenario, socket) {
    this.logger.scenario(scenario.name, scenario.description);
    if (isH2Scenario(scenario)) return scenario.useRawTLS ? this._execH2RawTLSOnSocket(scenario, socket) : this._execH2OnSocket(scenario, socket);
    if (scenario.useNodeTLS) return this._execNodeTLSOnSocket(scenario, socket);
    if (scenario.useCustomServer) return this._execCustomServerOnSocket(scenario, socket);
    return this._execTLSOnSocket(scenario, socket);
  }

  // Execute a custom application protocol scenario (SMTP, LDAP, FTP) on a raw TCP socket
  async _execCustomServerOnSocket(scenario, socket) {
    let status = 'PASSED';
    let lastResponse = '';

    try {
      if (this.pcap) this.pcap.writeTCPHandshake();
      const result = await scenario.serverHandler(socket, this.logger, this.pcap);
      status = result.status || 'PASSED';
      lastResponse = result.response || '';
    } catch (e) {
      this.logger.error(`[custom-server] Error: ${e.message}`);
      status = 'ERROR';
      lastResponse = e.message;
    } finally {
      if (!socket.destroyed) socket.destroy();
    }

    const expected = scenario.expected || 'PASSED';
    const verdict = status === expected ? 'AS EXPECTED' : 'UNEXPECTED';
    const { CATEGORY_SEVERITY } = require('./scenarios');
    const { gradeResult } = require('./grader');

    const resultObj = {
      scenario: scenario.name, description: scenario.description, category: scenario.category,
      severity: CATEGORY_SEVERITY[scenario.category] || 'low',
      status, expected, verdict,
      response: lastResponse || status,
    };
    resultObj.finding = gradeResult(resultObj, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict);
    return resultObj;
  }

  // Execute an HTTP/2 server scenario on a pre-connected raw TCP socket
  _execH2OnSocket(scenario, socket) {
    return new Promise((resolve) => {
      this.logger.info(`Handling HTTP/2 scenario "${scenario.name}" on IPC socket`);

      // Create a temporary HTTP/2 server instance to handle the session.
      const h2Server = http2.createServer({
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

  // Execute an HTTP/2 server scenario using raw TLS (no http2.createSecureServer)
  // This allows writeRawFrame() to write directly through the TLS socket.
  _execH2RawTLSOnSocket(scenario, socket) {
    return new Promise((resolve) => {
      this.logger.info(`Handling raw-TLS HTTP/2 scenario "${scenario.name}" on IPC socket`);

      let resolved = false;
      const finish = (result) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timeout);
        resolve(result);
      };

      const timeout = setTimeout(() => {
        this.logger.error(`Scenario "${scenario.name}" timed out (raw TLS)`);
        if (!socket.destroyed) socket.destroy();
        finish({
          scenario: scenario.name, status: 'TIMEOUT',
          response: 'No HTTP/2 preface received within 10s (raw TLS)',
        });
      }, 10000);

      // Upgrade the raw TCP socket to TLS
      const tlsSocket = new tls.TLSSocket(socket, {
        isServer: true,
        key: this.h2KeyPEM,
        cert: this.h2CertPEM,
        ALPNProtocols: ['h2'],
      });

      tlsSocket.on('error', (err) => {
        this.logger.info(`TLS socket error (raw TLS): ${err.message}`);
        finish({ scenario: scenario.name, status: 'ERROR', response: `TLS error: ${err.message}` });
      });

      // HTTP/2 connection preface is 24 bytes
      const H2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
      let buf = Buffer.alloc(0);
      let prefaceReceived = false;
      let settingsReceived = false;
      let streamId = null;

      const processData = (data) => {
        buf = Buffer.concat([buf, data]);

        // Step 1: Read the 24-byte HTTP/2 connection preface
        if (!prefaceReceived) {
          if (buf.length < 24) return;
          const preface = buf.slice(0, 24);
          if (!preface.equals(H2_PREFACE)) {
            this.logger.error('Invalid HTTP/2 connection preface');
            finish({ scenario: scenario.name, status: 'ERROR', response: 'Invalid H2 preface' });
            tlsSocket.destroy();
            return;
          }
          buf = buf.slice(24);
          prefaceReceived = true;
          this.logger.info('Received HTTP/2 connection preface');
        }

        // Step 2: Read frames (9-byte header + payload)
        while (buf.length >= 9) {
          const frameLen = (buf[0] << 16) | (buf[1] << 8) | buf[2];
          const frameType = buf[3];
          const frameFlags = buf[4];
          const frameStreamId = buf.readUInt32BE(5) & 0x7FFFFFFF;
          const totalLen = 9 + frameLen;

          if (buf.length < totalLen) return; // wait for more data

          const framePayload = buf.slice(9, totalLen);
          buf = buf.slice(totalLen);

          // SETTINGS frame (type 0x04)
          if (frameType === 0x04 && frameStreamId === 0) {
            if (frameFlags & 0x01) {
              // SETTINGS ACK from client
              this.logger.info('Received client SETTINGS ACK');
            } else {
              // Client SETTINGS — send our SETTINGS + ACK
              settingsReceived = true;
              this.logger.info('Received client SETTINGS, sending server SETTINGS + ACK');

              // Server SETTINGS (empty)
              const serverSettings = Buffer.from([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
              // SETTINGS ACK
              const settingsAck = Buffer.from([0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]);
              tlsSocket.write(Buffer.concat([serverSettings, settingsAck]));
            }
            continue;
          }

          // WINDOW_UPDATE frame (type 0x08) — acknowledge but don't act
          if (frameType === 0x08) {
            this.logger.info(`Received WINDOW_UPDATE on stream ${frameStreamId}`);
            continue;
          }

          // HEADERS frame (type 0x01) — extract stream ID and trigger scenario
          if (frameType === 0x01) {
            streamId = frameStreamId;
            this.logger.info(`Received HEADERS on stream ${streamId} — executing scenario handler`);

            // Remove data listener before calling handler (handler will write raw frames)
            tlsSocket.removeListener('data', processData);

            // Create mock session and stream objects for the scenario handler
            const mockSession = { _tlsSocket: tlsSocket, socket: tlsSocket };
            const mockStream = {
              id: streamId,
              respond: (headers) => {
                // Build a minimal HEADERS response frame with HPACK-encoded :status
                const status = headers[':status'] || 200;
                let headerBlock;
                if (status === 200) {
                  headerBlock = Buffer.from([0x88]); // indexed :status 200
                } else {
                  // Literal :status with value
                  const statusStr = String(status);
                  const statusBuf = Buffer.from(statusStr);
                  headerBlock = Buffer.alloc(2 + statusBuf.length);
                  headerBlock[0] = 0x48; // literal indexed, name index 8 (:status)
                  headerBlock[1] = statusBuf.length;
                  statusBuf.copy(headerBlock, 2);
                }
                const frame = Buffer.alloc(9 + headerBlock.length);
                frame.writeUIntBE(headerBlock.length, 0, 3);
                frame[3] = 0x01; // HEADERS
                frame[4] = 0x04; // END_HEADERS
                frame.writeUInt32BE(streamId, 5);
                headerBlock.copy(frame, 9);
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.write(frame);
              },
              end: (data) => {
                if (data) {
                  const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
                  const frame = Buffer.alloc(9 + payload.length);
                  frame.writeUIntBE(payload.length, 0, 3);
                  frame[3] = 0x00; // DATA
                  frame[4] = 0x01; // END_STREAM
                  frame.writeUInt32BE(streamId, 5);
                  payload.copy(frame, 9);
                  if (tlsSocket && !tlsSocket.destroyed) tlsSocket.write(frame);
                } else {
                  // Empty DATA with END_STREAM
                  const frame = Buffer.alloc(9);
                  frame[3] = 0x00; // DATA
                  frame[4] = 0x01; // END_STREAM
                  frame.writeUInt32BE(streamId, 5);
                  if (tlsSocket && !tlsSocket.destroyed) tlsSocket.write(frame);
                }
              },
              on: (event, cb) => { /* no-op for mock stream */ },
              destroy: () => { if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy(); },
            };

            const log = (msg) => this.logger.info(msg);
            try {
              scenario.serverHandler(mockStream, mockSession, log);
              const res = {
                scenario: scenario.name, description: scenario.description, category: scenario.category,
                status: 'PASSED', expected: scenario.expected, verdict: 'AS EXPECTED',
                response: 'Handler executed via raw TLS (cluster worker)',
              };
              res.finding = gradeResult(res, scenario);
              this.logger.result(scenario.name, 'PASSED', res.response, 'AS EXPECTED');

              // Give time for frames to be written and client to respond
              setTimeout(() => {
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
                finish(res);
              }, 2000);
            } catch (e) {
              this.logger.error(`Scenario handler error (raw TLS): ${e.message}`);
              if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
              finish({ scenario: scenario.name, status: 'ERROR', response: e.message });
            }
            return; // stop processing buffer
          }

          // Other frame types — log and continue
          this.logger.info(`Received frame type=${frameType} stream=${frameStreamId} len=${frameLen}`);
        }
      };

      tlsSocket.on('data', processData);
      socket.resume();
    });
  }

  // Execute raw TLS fuzz actions on a pre-connected socket
  _execTLSOnSocket(scenario, socket) {
    return new Promise((resolve) => {
      this.activeSockets.add(socket);
      const finish = (result) => {
        this.activeSockets.delete(socket);
        if (!socket.destroyed) socket.destroy();
        resolve(result);
      };

      const pcap = this.pcap;
      configureSocket(socket);
      socket.resume(); // unpause if transferred via IPC with pauseOnConnect
      this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);
      if (pcap) pcap.writeTCPHandshake();

      const actionFn = scenario.serverActions || scenario.actions;
      const actions = actionFn({ serverCert: this.certDER, hostname: this.hostname });
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

      const run = async () => {
        for (const action of actions) {
          if (this.aborted || this._scenarioAborted || connectionClosed) {
            if (this.aborted) status = 'ABORTED';
            else if (this._scenarioAborted && status === 'PASSED') status = 'PEER_DONE';
            break;
          }

          switch (action.type) {
            case 'barrier': {
              try {
                await this.barrier.wait(scenario.name, action.label, action.timeout || 10000);
              } catch (e) {
                this.logger.error(`Barrier '${action.label}' failed: ${e.message}`);
                status = 'BARRIER_TIMEOUT';
              }
              break;
            }

            case 'peer-done': {
              try { this.logger.peerDone && this.logger.peerDone(scenario.name, 'server'); } catch (_) {}
              break;
            }

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
              // One tick so any pending 'data' events queued behind 'close'
              // can drain before we decide the buffer is empty.
              await new Promise(r => setImmediate(r));
              const tailBuffer = recvBuffer;
              recvBuffer = Buffer.alloc(0);
              const data = Buffer.concat([alreadyReceived, dataFromWait || Buffer.alloc(0), tailBuffer]);
              if (data && data.length > 0) {
                this.logger.received(data);
                if (pcap) pcap.writeTLSData(data, 'received');
                lastResponse = this._describeTLSResponse(data); rawResponse = data;
              } else if (connectionClosed) {
                // Preserve a previously observed alert status — don't clobber
                // tls-alert-* with DROPPED just because a later recv saw FIN.
                if (status !== 'tls-alert-server' && status !== 'tls-alert-client') {
                  lastResponse = 'Connection closed'; status = 'DROPPED';
                }
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
        finish(result);
      };

      run().catch((e) => {
        this.logger.error(`Raw TLS scenario failed: ${e.message}`);
        finish({
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          status: 'ERROR', expected: scenario.expected || 'PASSED', verdict: 'UNEXPECTED',
          response: e.message,
        });
      });
    });
  }

  _execNodeTLSOnSocket(scenario, rawSocket) {
    return new Promise((resolve) => {
      this.activeSockets.add(rawSocket);
      let finishCalled = false;
      const finish = (result) => {
        if (finishCalled) return;
        finishCalled = true;
        this.activeSockets.delete(rawSocket);
        if (!rawSocket.destroyed) rawSocket.destroy();
        resolve(result);
      };

      if (this.aborted) {
        return finish({ scenario: scenario.name, status: 'ABORTED', response: 'Aborted' });
      }

      const tlsSocket = new tls.TLSSocket(rawSocket, {
        isServer: true,
        key: this.h2KeyPEM,
        cert: this.h2CertPEM,
        ALPNProtocols: ['h2', 'http/1.1'],
      });
      this.activeSockets.add(tlsSocket);

      rawSocket.resume(); // unpause if transferred via IPC with pauseOnConnect

      let lastResponse = '';
      let responded = false;

      tlsSocket.on('secure', () => {
        this.logger.info(`[node-tls] TLS client connected (${tlsSocket.getProtocol()})`);
      });

      tlsSocket.on('data', (data) => {
        if (responded) return;
        this.logger.received(data);
        const log = (msg) => this.logger.info(msg);

        if (typeof scenario.serverHandler === 'function') {
          responded = true;
          try {
            scenario.serverHandler(tlsSocket, log, data);
            const res = {
              scenario: scenario.name, description: scenario.description, category: scenario.category,
              status: 'PASSED', expected: scenario.expected || 'PASSED', verdict: 'AS EXPECTED',
              response: `Handler executed (node-tls)`,
            };
            res.finding = gradeResult(res, scenario);
            this.logger.result(scenario.name, 'PASSED', res.response, 'AS EXPECTED');
            
            // Allow handler to finish sending data before closing
            setTimeout(() => finish(res), 2000);
          } catch (e) {
            this.logger.error(`Scenario handler error: ${e.message}`);
            finish({ scenario: scenario.name, status: 'ERROR', response: e.message });
          }
          return;
        }

        responded = true;
        lastResponse = 'Client data: ' + data.length + ' bytes';
        try {
          tlsSocket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
        } catch (_) {}
      });

      tlsSocket.on('end', () => {
        if (!responded) { responded = true; lastResponse = 'Client disconnected (no data)'; }
        const computed = computeExpected(scenario);
        const expected = 'expected' in scenario ? scenario.expected : computed.expected;
        const verdict = this._computeVerdict('PASSED', expected, lastResponse);
        finish({
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          status: 'PASSED', expected, verdict,
          response: lastResponse || 'PASSED',
        });
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
          finish(result);
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
        finish(result);
      }, 3000);
    });
  }

  // ── TLS server scenario ─────────────────────────────────────────────────────
  async _runTLSScenario(scenario) {
    await this._ensureServerType('tcp');
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, scenario.description);
    this.logger.info(`Waiting for client to connect on port ${this.port}...`);
    if (this._onListening) this._onListening();

    try {
      const socket = await this._waitForTcpConnection(60000);
      return await this._execTLSOnSocket(scenario, socket);
    } catch (e) {
      const computed = computeExpected(scenario);
      return {
        scenario: scenario.name, description: scenario.description, category: scenario.category,
        status: 'TIMEOUT',
        expected: 'expected' in scenario ? scenario.expected : computed.expected,
        verdict: 'N/A',
        response: e.message,
      };
    }
  }

  async _runCustomServerScenario(scenario) {
    await this._ensureServerType('tcp');
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, scenario.description);
    if (this._onListening) this._onListening();

    try {
      const socket = await this._waitForTcpConnection(this.timeout, false);
      return await this._execCustomServerOnSocket(scenario, socket);
    } catch (e) {
      return {
        scenario: scenario.name, description: scenario.description, category: scenario.category,
        status: 'TIMEOUT',
        response: e.message,
      };
    }
  }

  // ── Node.js TLS server (real OpenSSL-backed TLS for well-behaved counterpart) ──
  async _runNodeTLSServer(scenario) {
    await this._ensureServerType('tcp');
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, scenario.description);
    if (this._onListening) this._onListening();

    try {
      const socket = await this._waitForTcpConnection(60000, false);
      return await this._execNodeTLSOnSocket(scenario, socket);
    } catch (e) {
      const computed = computeExpected(scenario);
      return {
        scenario: scenario.name, description: scenario.description, category: scenario.category,
        status: 'TIMEOUT',
        expected: 'expected' in scenario ? scenario.expected : computed.expected,
        verdict: 'N/A',
        response: e.message,
      };
    }
  }

  // ── HTTP/2 server scenario ──────────────────────────────────────────────────

  /**
   * Start the HTTP/2 server if not already running.
   * Call this explicitly for passive server mode (no scenarios).
   */
  async startH2() {
    if (this.h2Server) return;

    const setupH2Server = () => {
      const srv = http2.createServer({
        allowHTTP1: true,
      });

      srv.on('error', (err) => { this.logger.error(`HTTP/2 server error: ${err.message}`); });

      // Capture the real TLS socket before the HTTP/2 session wraps it in a Proxy.
      srv.on('connection', (socket) => {
        this._h2RawSocket = socket;
      });

      srv.on('session', (session) => {
        this.activeSockets.add(session);
        session.on('close', () => this.activeSockets.delete(session));
        session.on('error', () => this.activeSockets.delete(session));

        if (this._h2RawSocket) {
          session._rawSocket = this._h2RawSocket;
          this._h2RawSocket = null;
        }
        const remoteAddr = session.socket ? session.socket.remoteAddress : 'unknown';
        this.logger.info(`HTTP/2 session from ${remoteAddr}`);
        session.on('error', (err) => { this.logger.error(`Session error: ${err.message}`); });
        session.on('close', () => {
          this.logger.info(`Session closed from ${remoteAddr}`);
          if (this._h2SessionCloseHandler) this._h2SessionCloseHandler();
        });

        session.on('stream', (stream) => {
          this.activeSockets.add(stream);
          stream.on('close', () => this.activeSockets.delete(stream));
          stream.on('error', () => this.activeSockets.delete(stream));
          if (this.aborted) {
            try { stream.destroy(); } catch (_) {}
          }
        });
      });

      srv.on('stream', (stream, headers) => {
        const method = headers[':method'] || 'UNKNOWN';
        const path = headers[':path'] || '/';

        // Check for shutdown signal in HTTP/2 headers
        if (path === SHUTDOWN_PATH) {
          try { stream.respond({ ':status': 200 }); stream.end('Shutting down'); } catch (_) {}
          this.logger.info(`Shutdown signal received on HTTP/2 stream (Path: ${SHUTDOWN_PATH})`);
          this.abort();
          return;
        }

        if (this._h2StreamHandler) {
          const handler = this._h2StreamHandler;
          this._h2StreamHandler = null;
          handler(stream);
          return;
        }

        if (this._h2WaitingForStream) {
          this._h2PendingStreams.push(stream);
          return;
        }

        this.logger.info(`HTTP/2 request: ${method} ${path}`);
        try { stream.respond({ ':status': 200, 'content-type': 'text/plain' }); stream.end('HTTP/2 OK'); } catch (_) {}
      });
      
      return srv;
    };

    this._h2PendingStreams = [];
    this._h2StreamHandler = null;
    this.h2Server = setupH2Server();

    await new Promise((resolve, reject) => {
      const listenWithRetry = (srv, retriesLeft) => {
        if (this.aborted) return;
        const bindAddr = this.bindAddress || (this.hostname === 'localhost' ? '::' : this.hostname);
        srv.listen(this.port, bindAddr, () => {
          this.logger.info(
            `HTTP/2 server listening on ${bindAddr}:${this.port} | ` +
            `cert SHA256=${this.h2Fingerprint.slice(0, 16)}...`
          );
          resolve();
        });

        srv.once('error', (err) => {
          if (this.aborted) return;
          if (err.code === 'EADDRINUSE' && retriesLeft > 0) {
            if (retriesLeft % 5 === 0) {
              this.logger.info(`HTTP/2 port ${this.port} in use, retrying (${retriesLeft} left)...`);
            }
            srv.close();
            const nextSrv = setupH2Server();
            this.h2Server = nextSrv;
            setTimeout(() => listenWithRetry(nextSrv, retriesLeft - 1), 500);
            return;
          }
          reject(err);
        });
      };
      
      listenWithRetry(this.h2Server, 30);
    });
  }

  async _runH2Scenario(scenario) {
    await this._ensureServerType('h2');
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
        this._h2SessionCloseHandler = null;
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

      // Race guard: a stream may have arrived between the queue check above
      // and this handler registration. Re-check and drain if so — otherwise
      // the stream sits in _h2PendingStreams until the 60s scenario timeout.
      if (this._h2PendingStreams.length > 0) {
        const queued = this._h2PendingStreams.shift();
        const h = this._h2StreamHandler;
        this._h2StreamHandler = null;
        this.logger.info('Draining stream arrived during handler registration');
        h(queued);
        return;
      }

      // Detect session-close-without-stream (e.g. probe clients that connect
      // TCP but never send an HTTP/2 request).  Finish early instead of
      // waiting the full 60 s timeout.
      this._h2SessionCloseHandler = () => {
        if (this._h2StreamHandler) {
          // Stream handler is still registered → no stream was delivered
          clearTimeout(scenarioTimeout);
          this._h2StreamHandler = null;
          this._h2SessionCloseHandler = null;
          this.logger.info('Session closed without sending a stream — finishing early');
          finish({
            scenario: scenario.name, description: scenario.description, category: scenario.category,
            status: 'PASSED', expected: scenario.expected, verdict: 'AS EXPECTED',
            response: 'Client connected and disconnected (no stream — probe-style)',
          });
        }
      };
    });
  }

  // Run an H2 server scenario using raw TLS (persistent server path)
  async _runH2RawTLSScenario(scenario) {
    // For raw TLS scenarios, we need a fresh TLS server (not the persistent http2 server)
    // because we can't share the http2.createSecureServer with raw TLS writes.
    this.logger.scenario(scenario.name, scenario.description);
    this.logger.info(`Starting raw TCP server for scenario "${scenario.name}" on port ${this.port}...`);

    // Stop any existing H2 server to free the port
    if (this.h2Server) {
      await new Promise((resolve) => {
        this.h2Server.close(() => resolve());
        // Force-close after 2s
        setTimeout(resolve, 2000);
      });
      this.h2Server = null;
    }

    // Signal that the server is ready for a client connection
    if (this._onListening) this._onListening();

    return new Promise((resolve) => {
      const H2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');

      const tlsServer = net.createServer({});

      let resolved = false;
      const finish = (result) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(scenarioTimeout);
        try { tlsServer.close(); } catch (_) {}
        resolve(result);
      };

      const scenarioTimeout = setTimeout(() => {
        this.logger.error(`Scenario "${scenario.name}" timed out — no client connected (raw TLS).`);
        finish({
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          severity: 'high', status: 'TIMEOUT',
          expected: scenario.expected, verdict: 'N/A',
          response: 'No client connected within 60s (raw TLS)',
          compliance: null, finding: 'timeout', hostDown: false, probe: null,
        });
      }, 60000);

      tlsServer.on('connection', (tlsSocket) => {
        this.logger.info(`Client connected via raw TLS for "${scenario.name}"`);
        let buf = Buffer.alloc(0);
        let prefaceReceived = false;

        tlsSocket.on('error', (err) => {
          this.logger.info(`TLS socket error: ${err.message}`);
        });

        const processData = (data) => {
          buf = Buffer.concat([buf, data]);

          if (!prefaceReceived) {
            if (buf.length < 24) return;
            const preface = buf.slice(0, 24);
            if (!preface.equals(H2_PREFACE)) {
              this.logger.error('Invalid HTTP/2 connection preface (raw TLS)');
              finish({ scenario: scenario.name, status: 'ERROR', response: 'Invalid H2 preface' });
              tlsSocket.destroy();
              return;
            }
            buf = buf.slice(24);
            prefaceReceived = true;
          }

          while (buf.length >= 9) {
            const frameLen = (buf[0] << 16) | (buf[1] << 8) | buf[2];
            const frameType = buf[3];
            const frameFlags = buf[4];
            const frameStreamId = buf.readUInt32BE(5) & 0x7FFFFFFF;
            const totalLen = 9 + frameLen;

            if (buf.length < totalLen) return;

            buf = buf.slice(totalLen);

            if (frameType === 0x04 && frameStreamId === 0) {
              if (!(frameFlags & 0x01)) {
                // Client SETTINGS — send server SETTINGS + ACK
                const serverSettings = Buffer.from([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
                const settingsAck = Buffer.from([0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]);
                tlsSocket.write(Buffer.concat([serverSettings, settingsAck]));
              }
              continue;
            }

            if (frameType === 0x08) continue; // WINDOW_UPDATE

            if (frameType === 0x01) {
              const streamId = frameStreamId;
              this.logger.info(`Received HEADERS on stream ${streamId} — executing handler (raw TLS)`);
              tlsSocket.removeListener('data', processData);

              const mockSession = { _tlsSocket: tlsSocket, socket: tlsSocket };
              const mockStream = {
                id: streamId,
                respond: (headers) => {
                  const status = headers[':status'] || 200;
                  let headerBlock;
                  if (status === 200) {
                    headerBlock = Buffer.from([0x88]);
                  } else {
                    const statusStr = String(status);
                    const statusBuf = Buffer.from(statusStr);
                    headerBlock = Buffer.alloc(2 + statusBuf.length);
                    headerBlock[0] = 0x48;
                    headerBlock[1] = statusBuf.length;
                    statusBuf.copy(headerBlock, 2);
                  }
                  const frame = Buffer.alloc(9 + headerBlock.length);
                  frame.writeUIntBE(headerBlock.length, 0, 3);
                  frame[3] = 0x01;
                  frame[4] = 0x04;
                  frame.writeUInt32BE(streamId, 5);
                  headerBlock.copy(frame, 9);
                  if (tlsSocket && !tlsSocket.destroyed) tlsSocket.write(frame);
                },
                end: (data) => {
                  if (data) {
                    const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
                    const frame = Buffer.alloc(9 + payload.length);
                    frame.writeUIntBE(payload.length, 0, 3);
                    frame[3] = 0x00;
                    frame[4] = 0x01;
                    frame.writeUInt32BE(streamId, 5);
                    payload.copy(frame, 9);
                    if (tlsSocket && !tlsSocket.destroyed) tlsSocket.write(frame);
                  } else {
                    const frame = Buffer.alloc(9);
                    frame[3] = 0x00;
                    frame[4] = 0x01;
                    frame.writeUInt32BE(streamId, 5);
                    if (tlsSocket && !tlsSocket.destroyed) tlsSocket.write(frame);
                  }
                },
                on: (event, cb) => {},
                destroy: () => { if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy(); },
              };

              const log = (msg) => this.logger.info(msg);
              try {
                scenario.serverHandler(mockStream, mockSession, log);
                const res = {
                  scenario: scenario.name, description: scenario.description, category: scenario.category,
                  status: 'PASSED', expected: scenario.expected, verdict: 'AS EXPECTED',
                  response: 'Handler executed via raw TLS',
                };
                res.finding = gradeResult(res, scenario);
                this.logger.result(
                  scenario.name, 'PASSED', res.response, 'AS EXPECTED',
                  scenario.expectedReason || '', false, res.finding
                );
                setTimeout(() => {
                  if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
                  finish(res);
                }, 2000);
              } catch (e) {
                this.logger.error(`Scenario handler error (raw TLS): ${e.message}`);
                if (tlsSocket && !tlsSocket.destroyed) tlsSocket.destroy();
                const res = {
                  scenario: scenario.name, description: scenario.description, category: scenario.category,
                  status: 'ERROR', expected: scenario.expected, verdict: 'N/A',
                  response: e.message,
                };
                res.finding = gradeResult(res, scenario);
                finish(res);
              }
              return;
            }
          }
        };

        tlsSocket.on('data', processData);
      });

      tlsServer.on('error', (err) => {
        this.logger.error(`Raw TLS server error: ${err.message}`);
        finish({ scenario: scenario.name, status: 'ERROR', response: err.message });
      });

      const bindAddr = this.bindAddress || (this.hostname === 'localhost' ? '::' : this.hostname);
      tlsServer.listen(this.port, bindAddr, () => {
        this.logger.info(`Raw TLS server listening on ${bindAddr}:${this.port}`);
      });
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

    await this._ensureServerType('tcp');
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, scenario.description);
    if (this._onListening) this._onListening();

    try {
      const socket = await this._waitForTcpConnection(10000);
      return await this._execRawTCPOnSocket(scenario, socket);
    } catch (e) {
      const computed = computeExpected(scenario);
      return {
        scenario: scenario.name, description: scenario.description, category: scenario.category,
        status: 'TIMEOUT',
        expected: 'expected' in scenario ? scenario.expected : computed.expected,
        verdict: 'N/A',
        response: e.message,
      };
    }
  }

  // Execute raw TCP fuzz actions on a pre-connected socket
  async _execRawTCPOnSocket(scenario, socket) {
    this.activeSockets.add(socket);
    configureSocket(socket);
    socket.resume();
    this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);

    const actionFn = scenario.serverActions || scenario.actions;
    const actions = actionFn({ serverCert: this.certDER, hostname: this.hostname });
    let connectionClosed = false;
    let recvBuffer = Buffer.alloc(0);
    let lastResponse = '';
    let status = 'PASSED';

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
      if (this._scenarioAborted) { if (status === 'PASSED') status = 'PEER_DONE'; break; }

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
          recvBuffer = Buffer.alloc(0);
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
    this.activeSockets.delete(socket);

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
    return result;
  }

  // ── QUIC server scenario ───────────────────────────────────────────────────

  async startQuic(scenario) {
    // Well-behaved/baseline scenarios without manual handlers use the native quiche engine (HTTP/3)
    const needQuiche = scenario && scenario.useQuiche && !scenario.serverHandler;

    // If already running the correct engine, do nothing
    if (this.quicServer) {
      const isQuiche = this.quicServer.constructor.name === 'QuicheServer';
      if (isQuiche === !!needQuiche) return;
      
      // Wrong engine — close and restart
      this.logger.info(`Switching QUIC engine from ${isQuiche ? 'Quiche' : 'Fuzzer'} to ${needQuiche ? 'Quiche' : 'Fuzzer'}...`);
      this.quicServer.abort();
      this.quicServer = null;
    }

    if (needQuiche) {
      let quicheLib = null;
      try {
        quicheLib = require('@currentspace/http3');
      } catch (e) {
        console.error('\n[FATAL] The @currentspace/http3 native module is required for QUIC server tests but could not be loaded.');
        console.error(`Error details: ${e.message}\n`);
        process.exit(1);
      }

      const { QuicheServer } = require('./quic-engines/quiche-server');
      this.quicServer = new QuicheServer({
        port: this.port,
        hostname: this.hostname,
        timeout: this.timeout,
        delay: this.delay,
        logger: this.logger,
        quicheLibrary: quicheLib,
        keyPEM: this.h2KeyPEM,
        certPEM: this.h2CertPEM,
        pcapFile: this.pcapFileBase,
        mergePcap: this.mergePcap,
        protocol: 'udp',
      });
      await this.quicServer.start();
      return;
    }

    // Server-side QUIC scenarios send raw crafted packets to connecting clients.
    // They need the raw UDP QuicFuzzerServer, not quiche (which is a compliant
    // implementation that can't produce malformed frames).
    this.quicServer = new QuicFuzzerServer({
      port: this.port,
      hostname: this.hostname,
      bindAddress: this.bindAddress,
      timeout: this.timeout,
      delay: this.delay,
      logger: this.logger,
      pcapFile: this.pcapFileBase,
      mergePcap: this.mergePcap,
      protocol: 'udp',
    });
    await this.quicServer.start();
  }

  async _runQuicScenario(scenario) {
    await this._ensureServerType('quic');
    await this.startQuic(scenario);
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

      const checkClosed = setInterval(() => {
        if (this._scenarioAborted) {
          clearInterval(checkClosed);
          // Peer finished and released us — drain whatever is in the buffer
          // right now and exit, don't wait 4s for an alert that isn't coming.
          done();
          return;
        }
        if (isClosedFn() || socket.destroyed) {
          clearInterval(checkClosed);
          // Wait up to 4s after closure to capture late-arriving alerts (common in Node.js TLS)
          setTimeout(done, 4000);
        }
      }, 50);

      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearInterval(checkClosed);
        socket.removeListener('data', onData);
        socket.removeListener('end', onEnd);
        socket.removeListener('close', onEnd);
        resolve(buf.length > 0 ? buf : null);
      };

      const onData = (data) => {
        buf = Buffer.concat([buf, data]);
        // Reset short timer on each chunk
        clearTimeout(timer);
        timer = setTimeout(done, 150);
      };

      const onEnd = () => {
        // TCP FIN received — don't resolve immediately, let checkClosed handle the 4s wait
      };

      socket.on('data', onData);
      socket.on('end', onEnd);
      socket.on('close', onEnd);

      // Overall timeout
      setTimeout(() => {
        if (!settled) done();
      }, timeout);
    });
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = { UnifiedServer };
