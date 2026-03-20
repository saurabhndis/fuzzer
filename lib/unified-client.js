// Unified Fuzzing Client — handles both TLS and HTTP/2 scenarios from one class.
// TLS scenarios (categories A–Y): connect via raw TCP, send raw TLS bytes.
// HTTP/2 scenarios (categories AA–AJ): connect via TLS+ALPN h2, send raw H2 frames.
const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const { Logger } = require('./logger');
const { PcapWriter } = require('./pcap-writer');
const { sendFIN, sendRST, slowDrip, sendFragmented, configureSocket, RawTCPSocket, isRawAvailable } = require('./tcp-tricks');
const { parseRecords, buildAlert } = require('./record');
const { ContentType, HandshakeType, AlertLevel, AlertDescription, AlertDescriptionName, CipherSuiteName, VersionName } = require('./constants');
const { validateClientHello, validateServerFlight, validateClientKeyExchange } = require('./tls-validate');
const { gradeResult, computeOverallGrade, CATEGORY_SEVERITY } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { checkProtocolCompliance } = require('./protocol-compliance');
const { QuicFuzzerClient } = require('./quic-fuzzer-client');

// QUIC category codes start with 'Q' followed by uppercase letter(s) (QA–QL, QS, QSCAN)
// Single-letter 'Q' is a TLS category (ClientHello Field Mutations)
function isQuicScenario(scenario) {
  if (typeof scenario.category !== 'string') return false;
  return scenario.category.length >= 2
    && scenario.category[0] === 'Q' && /^Q[A-Z]/.test(scenario.category);
}

// Raw TCP category codes start with 'R' followed by A-H (RA–RH)
function isTcpScenario(scenario) {
  return typeof scenario.category === 'string' && scenario.category.length === 2
    && scenario.category[0] === 'R' && scenario.category[1] >= 'A' && scenario.category[1] <= 'H';
}

// HTTP/2 category codes are two-letter (AA–AJ); TLS categories are single-letter (A–Y)
function isH2Scenario(scenario) {
  return typeof scenario.category === 'string' && scenario.category.length === 2
    && !isQuicScenario(scenario) && !isTcpScenario(scenario);
}

class UnifiedClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.timeout = opts.timeout || 5000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    let finalPcap = opts.pcapFile;
    if (finalPcap && !finalPcap.includes('.worker-') && !finalPcap.includes('.client.')) {
      finalPcap = finalPcap.replace(/\.pcap$/i, '') + '.client.pcap';
    }
    this.pcap = finalPcap ? new PcapWriter(finalPcap, {
      role: 'client',
      clientPort: 49152 + Math.floor(Math.random() * 16000),
      serverPort: this.port,
    }) : null;
    this.dut = opts.dut || null;
    this.aborted = false;
    this.activeSockets = new Set();
    this.activeChildProcesses = new Set();
    this._healthSocket = null;
    this._healthSocketConnecting = null;
  }

  abort() {
    this.aborted = true;
    for (const socket of this.activeSockets) {
      try { socket.destroy(); } catch (_) {}
    }
    this.activeSockets.clear();
    for (const proc of this.activeChildProcesses) {
      try { proc.kill('SIGKILL'); } catch (_) {}
    }
    this.activeChildProcesses.clear();
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };

    if (scenario.side === 'server') {
      this.logger.error(`Skipping server-side scenario "${scenario.name}" in client mode`);
      return { scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Server-side scenario cannot run in client mode' };
    }

    // Safety timeout: no scenario should ever take more than 90 seconds.
    // Prevents a stuck connection/recv from hanging the worker indefinitely.
    return new Promise(async (resolve) => {
      let resolved = false;
      const timer = setTimeout(() => {
        if (resolved) return;
        resolved = true;
        this.logger.error(`Scenario ${scenario.name} forced timeout after 90s`);
        // Destroy any sockets that might be stuck
        for (const socket of this.activeSockets) {
          try { if (!socket.destroyed) socket.destroy(); } catch (_) {}
        }
        this.activeSockets.clear();
        // Kill any child processes (e.g. OpenSSL spawned by QUIC baseline)
        for (const proc of this.activeChildProcesses) {
          try { proc.kill('SIGKILL'); } catch (_) {}
        }
        this.activeChildProcesses.clear();
        resolve({
          scenario: scenario.name,
          description: scenario.description,
          status: 'TIMEOUT',
          response: 'Forced timeout (90s safety limit)',
        });
      }, 90000);

      const finish = (result) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timer);
        resolve(result);
      };

      try {
        let result;
        if (isTcpScenario(scenario)) {
          result = await this._runRawTCPScenario(scenario);
        } else if (isQuicScenario(scenario)) {
          result = await this._runQuicScenario(scenario);
        } else if (scenario.useNodeTLS) {
          result = await this._runNodeTLSClient(scenario);
        } else if (scenario.useNodeH2) {
          result = await this._runNodeH2Client(scenario);
        } else if (typeof scenario.actions === 'function' || Array.isArray(scenario.actions)) {
          result = await this._runTLSScenario(scenario);
        } else {
          result = isH2Scenario(scenario)
            ? await this._runH2Scenario(scenario)
            : await this._runTLSScenario(scenario);
        }
        finish(result);
      } catch (e) {
        finish({
          scenario: scenario.name,
          description: scenario.description,
          status: 'ERROR',
          response: e.message,
        });
      }
    });
  }

  async runScenarios(scenarios) {
    const results = [];
    let hostWentDown = false;

    for (const scenario of scenarios) {
      if (this.aborted) break;

      if (hostWentDown) {
        this.logger.info(`Re-checking ${this.host}:${this.port} before next scenario...`);
        const recheck = await this._runHealthProbes(this.host);
        this.logger.healthProbe(this.host, this.port, recheck);
        if (!recheck.tcp.alive && !recheck.https.alive) {
          this.logger.hostDown(this.host, this.port, 'still unreachable — stopping batch');
          break;
        }
        this.logger.info('Host is back up — continuing');
        hostWentDown = false;
      }

      const result = await this.runScenario(scenario);
      results.push(result);
      if (result.hostDown) hostWentDown = true;
      await this._sleep(500);
    }

    const report = computeOverallGrade(results);
    this.logger.summary(results, report);
    return { results, report };
  }

  _isConnRefused(err) {
    if (!err) return false;
    if (err.code === 'ECONNREFUSED') return true;
    if (err.message && err.message.includes('ECONNREFUSED')) return true;
    if (typeof AggregateError !== 'undefined' && err instanceof AggregateError) {
      return err.errors.some(e => e.code === 'ECONNREFUSED' || (e.message && e.message.includes('ECONNREFUSED')));
    }
    return false;
  }

  // ── TLS scenario ────────────────────────────────────────────────────────────
  async _runTLSScenario(scenario) {
    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    let socket = null;
    let recvBuffer = Buffer.alloc(0);
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let connectionClosed = false;
    let hasFuzzAction = false; // tracks whether a [FUZZ] action has been sent
    let postFuzzRecvData = null; // data received in recv AFTER a fuzz action

    try {
      socket = await this._connectTLS();
      if (this.pcap) this.pcap.writeTCPHandshake();
      configureSocket(socket);

      socket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
      socket.on('end', () => {
        connectionClosed = true;
        this.logger.tcpEvent('received', 'FIN');
        if (this.pcap) this.pcap.writeFIN('received');
      });
      socket.on('close', () => { connectionClosed = true; });
      socket.on('error', (err) => {
        if (!connectionClosed) { this.logger.error(`Socket error: ${err.message}`); connectionClosed = true; }
      });

      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'send': {
            if (connectionClosed || socket.destroyed) {
              this.logger.error('Cannot send: connection closed'); status = 'DROPPED'; break;
            }
            if ((action.label || '').includes('[FUZZ]') || (action.label || '').includes('[CVE-')) {
              hasFuzzAction = true;
            }
            try {
              socket.write(action.data);
              this.logger.sent(action.data, action.label);
              if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
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
              if (this.pcap) this.pcap.writeTLSData(data, 'received');
              lastResponse = this._describeTLSResponse(data);
              rawResponse = data;
              if (hasFuzzAction) postFuzzRecvData = data;
            } else if (connectionClosed) {
              lastResponse = 'Connection closed'; rawResponse = null; status = 'DROPPED';
              if (hasFuzzAction) postFuzzRecvData = null;
            } else {
              lastResponse = 'Timeout (no response)'; rawResponse = null; status = 'TIMEOUT';
              if (hasFuzzAction) postFuzzRecvData = null;
            }
            break;
          }

          case 'delay': await this._sleep(action.ms); break;

          case 'fin': {
            this.logger.tcpEvent('sent', action.label || 'FIN');
            if (this.pcap) this.pcap.writeFIN('sent');
            try { await sendFIN(socket); } catch (_) {}
            break;
          }

          case 'rst': {
            this.logger.tcpEvent('sent', action.label || 'RST');
            if (this.pcap) this.pcap.writeRST('sent');
            sendRST(socket); connectionClosed = true;
            break;
          }

          case 'slowDrip': {
            this.logger.fuzz(action.label || `Slow drip: ${action.data.length} bytes, ${action.bytesPerChunk}B/chunk`);
            if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            try { await slowDrip(socket, action.data, action.bytesPerChunk, action.delayMs); }
            catch (e) { this.logger.error(`Slow drip failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'fragment': {
            this.logger.fuzz(action.label || `Fragmenting ${action.data.length} bytes into ${action.fragments} segments`);
            if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            try { await sendFragmented(socket, action.data, action.fragments, action.delayMs); }
            catch (e) { this.logger.error(`Fragment send failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'tlsPost': {
            // Close raw TCP socket and establish a real TLS connection for application-layer test
            if (socket && !socket.destroyed) socket.destroy();
            try {
              const result = await this._runTLSPost(action);
              lastResponse = result.response;
              status = result.status;
              this.logger.info(action.label || `HTTP POST ${action.bodySize} bytes`);
              this.logger.info(`Response: ${result.response}`);
            } catch (e) {
              this.logger.error(`TLS POST failed: ${e.message}`);
              status = 'ERROR'; lastResponse = e.message;
            }
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
                // Strict sequence check: exact handshake types in order, no extras
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

            // Content-level validation (matches OpenSSL behavior)
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
                if (this.pcap) this.pcap.writeTLSData(alert, 'sent');
              }
              status = action.alertOnFail ? 'tls-alert-client' : 'DROPPED';
            } else {
              this.logger.info(`Validation passed: ${action.label}`);
            }
            break;
          }
        }

        if (action.type === 'validate' && (status === 'DROPPED' || status === 'tls-alert-client')) break;
        if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
      }

      // TLS 1.3 encrypted alert detection: after a fuzz action, if the post-fuzz
      // recv only got ApplicationData records (no ServerHello/handshake), the server
      // sent an encrypted fatal alert. This applies whether or not the connection
      // has closed yet — encrypted alerts are always rejection signals.
      if (status === 'PASSED' && hasFuzzAction) {
        if (postFuzzRecvData) {
          const { records: postRecords } = parseRecords(postFuzzRecvData);
          const hasHandshake = postRecords.some(r => r.type === 0x16);
          const hasCleartextAlert = postRecords.some(r => r.type === 0x15);
          const onlyAppData = !hasHandshake && postRecords.length > 0 && postRecords.every(r => r.type === 0x17);
          if (hasCleartextAlert || onlyAppData) {
            status = 'tls-alert-server';
            lastResponse = hasCleartextAlert
              ? this._describeTLSResponse(postFuzzRecvData)
              : 'Encrypted alert (TLS 1.3)';
          }
        } else if (connectionClosed) {
          status = 'DROPPED';
          lastResponse = 'Connection closed';
        }
      }

      // Final response-aware status: if response is an alert but status wasn't updated
      if (status === 'PASSED' && lastResponse && /^Alert\(fatal/i.test(lastResponse)) {
        status = 'tls-alert-server';
      }

    } catch (e) {
      if (e.code === 'ECONNREFUSED' || e.message.includes('ECONNREFUSED')) {
        this.logger.error(`Scenario failed: Connection refused (target may be down or unreachable)`);
      } else {
        this.logger.error(`Scenario failed: ` + (e.stack || e));
      }
      status = 'ERROR'; lastResponse = e.message;
    } finally {
      if (socket) {
        this.activeSockets.delete(socket);
        if (!socket.destroyed) socket.destroy();
      }
    }

    let hostDown = false, probe = null;
    if (['DROPPED', 'TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host);
      hostDown = !probe.tcp.alive && !probe.https.alive;
      if (hostDown) this.logger.hostDown(this.host, this.port, scenario.name);
      if (hostDown) this.logger.healthProbe(this.host, this.port, probe);
    }

    // Response-aware status: replace generic DROPPED/PASSED with specific alert status
    if (lastResponse) {
      if (/^Alert\(fatal/i.test(lastResponse) || /Encrypted alert/i.test(lastResponse)) {
        status = 'tls-alert-server';
      }
    }

    const computed = computeExpected(scenario);
    const expected = 'expected' in scenario ? scenario.expected : computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    let verdict = this._computeVerdict(status, expected, lastResponse);

    // Differential Fuzzing Override — semantic behavior matching
    const { normalizeResponse, classifyBehavior } = require('./grader');
    const normResponse = normalizeResponse(lastResponse || status);
    const normBaseline = normalizeResponse(scenario._baselineResponse);
    if (normBaseline && normResponse === normBaseline) {
      verdict = 'AS EXPECTED';
    } else if (scenario._baselineResponse) {
      const targetBehavior = classifyBehavior(lastResponse || status, status);
      const baselineBehavior = classifyBehavior(scenario._baselineResponse, null);
      if (targetBehavior !== 'unknown' && targetBehavior === baselineBehavior) {
        verdict = 'AS EXPECTED';
      }
    }

    const severity = CATEGORY_SEVERITY[scenario.category] || 'low';
    const compliance = checkProtocolCompliance(rawResponse, status);
    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category, severity,
      status, expected, verdict, hostDown, probe,
      response: lastResponse || status,
      compliance,
      _baselineResponse: scenario._baselineResponse,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding, compliance);
    return result;
  }

  // ── Node.js TLS client (real OpenSSL-backed TLS for well-behaved counterpart) ──
  async _runNodeTLSClient(scenario) {
    this.logger.scenario(scenario.name, scenario.description);
    let status = 'PASSED';
    let lastResponse = '';
    let socket = null;

    try {
      socket = await this._connectNodeTLSWithRetry(scenario.nodeTlsOptions || {});

      this.logger.info(`[node-tls] TLS connected (${socket.getProtocol()})`);

      if (scenario.clientHandler) {
        // Scenario defines custom client logic
        const result = await scenario.clientHandler(socket, this.host, this.logger);
        status = result.status || 'PASSED';
        lastResponse = result.response || '';
      } else {
        // Default: send a simple HTTP GET request
        socket.write('GET / HTTP/1.1\r\nHost: ' + this.host + '\r\n\r\n');

        const data = await new Promise((resolve) => {
          let buf = Buffer.alloc(0);
          const dataTimer = setTimeout(() => resolve(buf), 2000);
          socket.on('data', (d) => { buf = Buffer.concat([buf, d]); });
          socket.on('end', () => { clearTimeout(dataTimer); resolve(buf); });
        });

        if (data.length > 0) {
          lastResponse = 'Server response: ' + data.length + ' bytes';
          this.logger.received(data);
        } else {
          lastResponse = 'No server response';
        }
      }
    } catch (e) {
      this.logger.error(`[node-tls] Error: ${e.message}`);
      status = 'DROPPED';
      lastResponse = e.message;
    } finally {
      if (socket) {
        this.activeSockets.delete(socket);
        if (!socket.destroyed) socket.destroy();
      }
    }

    const expected = scenario.expected || 'PASSED';
    const verdict = status === expected ? 'AS EXPECTED' : 'UNEXPECTED';
    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category,
      severity: CATEGORY_SEVERITY[scenario.category] || 'low',
      status, expected, verdict,
      response: lastResponse || status,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict);
    return result;
  }

  // ── Node.js HTTP/2 client (real HTTP/2 session for functional validation) ──
  async _runNodeH2Client(scenario) {
    this.logger.scenario(scenario.name, scenario.description);
    let status = 'PASSED';
    let lastResponse = '';
    let session = null;

    try {
      session = await this._connectNodeH2WithRetry(scenario.nodeTlsOptions || {});
      this.logger.info(`[node-h2] HTTP/2 connected`);

      if (scenario.clientHandler) {
        const result = await scenario.clientHandler(session, this.host, this.logger);
        status = result.status || 'PASSED';
        lastResponse = result.response || '';
      } else {
        // Default: single GET request
        const req = session.request({ ':method': 'GET', ':path': '/' });
        const data = await new Promise((resolve) => {
          let buf = Buffer.alloc(0);
          const dataTimer = setTimeout(() => resolve(buf), 5000);
          req.on('data', (d) => { buf = Buffer.concat([buf, d]); });
          req.on('end', () => { clearTimeout(dataTimer); resolve(buf); });
          req.on('error', () => { clearTimeout(dataTimer); resolve(buf); });
          req.end();
        });
        lastResponse = data.length > 0 ? `Response: ${data.length} bytes` : 'No response';
      }
    } catch (e) {
      this.logger.error(`[node-h2] Error: ${e.message}`);
      status = 'DROPPED';
      lastResponse = e.message;
    } finally {
      if (session) {
        this.activeSockets.delete(session);
        try { session.close(); } catch (_) {}
        try { session.destroy(); } catch (_) {}
      }
    }

    const expected = scenario.expected || 'PASSED';
    const verdict = status === expected ? 'AS EXPECTED' : 'UNEXPECTED';
    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category,
      severity: CATEGORY_SEVERITY[scenario.category] || 'low',
      status, expected, verdict,
      response: lastResponse || status,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict);
    return result;
  }

  async _connectNodeH2WithRetry(options = {}) {
    const maxRetries = 70;
    const retryDelay = 500;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      let session = null;
      try {
        return await new Promise((resolve, reject) => {
          let settled = false;
          session = http2.connect(`https://${this.host}:${this.port}`, {
            rejectUnauthorized: false,
            ...options
          });
          this.activeSockets.add(session);
          session.on('connect', () => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve(session);
          });
          session.on('error', (err) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            reject(err);
          });
          const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            try { session.destroy(); } catch (_) {}
            reject(new Error('H2 connect timeout'));
          }, this.timeout);
        });
      } catch (err) {
        // Clean up failed session from activeSockets
        if (session) {
          this.activeSockets.delete(session);
          try { session.destroy(); } catch (_) {}
        }
        if (this._isConnRefused(err) && attempt < maxRetries && !this.aborted) {
          if (attempt % 10 === 0) {
            this.logger.info(`[node-h2] Connection refused, retrying (${attempt + 1}/${maxRetries})...`);
          }
          await this._sleep(retryDelay);
          continue;
        }
        throw err;
      }
    }
  }

  // ── HTTP/2 scenario ─────────────────────────────────────────────────────────
  async _runH2Scenario(scenario) {
    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    const isProbe = actions.some(a => a.type === 'probe');
    if (isProbe) return this._runProbeScenario(scenario, actions);

    let socket = null;
    let recvBuffer = Buffer.alloc(0);
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let connectionClosed = false;

    try {
      socket = await this._connectH2(scenario.connectionOptions, scenario.isTcpOnly);
      if (this.pcap) this.pcap.writeTCPHandshake();
      configureSocket(socket);

      socket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
      socket.on('end', () => {
        connectionClosed = true;
        this.logger.tcpEvent('received', 'FIN');
        if (this.pcap) this.pcap.writeFIN('received');
      });
      socket.on('close', () => { connectionClosed = true; });
      socket.on('error', (err) => {
        if (!connectionClosed) { this.logger.error(`Socket error: ${err.message}`); connectionClosed = true; }
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
              if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            }
            catch (e) { this.logger.error(`Write failed: ${e.message}`); status = 'DROPPED'; }
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
              if (this.pcap) this.pcap.writeTLSData(data, 'received');
              lastResponse = this._describeH2Response(data); rawResponse = data;
              // Detect HTTP/2 rejection signals: GOAWAY or RST_STREAM frames
              if (this._h2HasRejectionFrame(data)) {
                status = 'DROPPED';
              }
            } else if (connectionClosed) {
              lastResponse = 'Connection closed'; rawResponse = null; status = 'DROPPED';
            } else {
              lastResponse = 'Timeout (no response)'; rawResponse = null; status = 'TIMEOUT';
            }
            break;
          }

          case 'delay': await this._sleep(action.ms); break;
          case 'fin': {
            this.logger.tcpEvent('sent', action.label || 'FIN');
            if (this.pcap) this.pcap.writeFIN('sent');
            try { await sendFIN(socket); } catch (_) {}
            break;
          }
          case 'rst': {
            this.logger.tcpEvent('sent', action.label || 'RST');
            if (this.pcap) this.pcap.writeRST('sent');
            sendRST(socket); connectionClosed = true;
            break;
          }
        }

        if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
      }

      // Post-action H2 rejection detection: if status is still PASSED but
      // the connection was closed by the server without sending any data, that's a rejection
      if (status === 'PASSED' && connectionClosed && !rawResponse) {
        status = 'DROPPED';
        if (!lastResponse) lastResponse = 'Connection closed';
      }

    } catch (e) {
      if (e.code === 'ECONNREFUSED' || e.message.includes('ECONNREFUSED')) {
        this.logger.error(`Scenario failed: Connection refused (target may be down or unreachable)`);
      } else {
        this.logger.error(`Scenario failed: ` + (e.stack || e));
      }
      status = 'ERROR'; lastResponse = e.message;
    } finally {
      if (socket) {
        this.activeSockets.delete(socket);
        if (!socket.destroyed) socket.destroy();
      }
    }

    let hostDown = false, probe = null;
    if (['DROPPED', 'TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host);
      hostDown = !probe.tcp.alive && !probe.https.alive;
      if (hostDown) this.logger.hostDown(this.host, this.port, scenario.name);
      if (hostDown) this.logger.healthProbe(this.host, this.port, probe);
    }

    const computed = computeExpected(scenario);
    const expected = 'expected' in scenario ? scenario.expected : computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    const verdict = this._computeVerdict(status, expected, lastResponse);
    const severity = CATEGORY_SEVERITY[scenario.category] || 'medium';
    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category, severity,
      status, expected, verdict, hostDown, probe,
      response: lastResponse || status,
      compliance: null,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding, null);
    return result;
  }

  async _runProbeScenario(scenario, actions) {
    const probeAction = actions.find(a => a.type === 'probe');
    const label = probeAction ? probeAction.label : 'connectivity probe';
    this.logger.info(`Probe: ${label}`);

    let status = 'CONNECTED';
    let lastResponse = '';
    let socket = null;

    try {
      socket = await this._connectH2(scenario.connectionOptions, scenario.isTcpOnly);
      if (scenario.isTcpOnly) {
        lastResponse = `TCP connected to ${this.host}:${this.port}`;
      } else {
        const alpn = socket.alpnProtocol || 'none';
        const tlsVersion = typeof socket.getProtocol === 'function' ? socket.getProtocol() : 'TLS';
        lastResponse = `Connected (${tlsVersion}, ALPN: ${alpn})`;
      }
      this.logger.info(lastResponse);
    } catch (e) {
      status = 'FAILED_CONNECTION'; lastResponse = e.message;
      this.logger.error(`Probe failed: ${e.message}`);
    } finally {
      if (socket && !socket.destroyed) socket.destroy();
    }

    const verdict = this._computeVerdict(status, scenario.expected, lastResponse);
    const severity = CATEGORY_SEVERITY[scenario.category] || 'info';
    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category, severity,
      status, expected: scenario.expected, verdict, hostDown: false, probe: null,
      response: lastResponse,
      compliance: null,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse, verdict, scenario.expectedReason || '', false, result.finding, null);
    return result;
  }

  // ── Connections ─────────────────────────────────────────────────────────────

  async _connectTLS() {
    const maxRetries = 70;
    const retryDelay = 500;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try { return await this._connectTLSOnce(); }
      catch (err) {
        if (this._isConnRefused(err) && attempt < maxRetries && !this.aborted) {
          if (attempt % 10 === 0) {
            this.logger.info(`Connection refused, retrying (${attempt + 1}/${maxRetries})...`);
          }
          await this._sleep(retryDelay);
          continue;
        }
        throw err;
      }
    }
  }

  _connectTLSOnce() {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: this.host, port: this.port, allowHalfOpen: true }, () => {
        this.logger.info(`Connected to ${this.host}:${this.port}`);
        this.activeSockets.add(socket);
        resolve(socket);
      });
      socket.setTimeout(this.timeout);
      socket.on('timeout', () => { socket.destroy(); reject(new Error('Connection timeout')); });
      socket.on('error', (err) => {
        if (!socket.destroyed) socket.destroy();
        reject(err);
      });
    });
  }

  async _connectH2(connectionOptions, isTcpOnly) {
    const maxRetries = 70;
    const retryDelay = 500;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try { return await this._connectH2Once(connectionOptions, isTcpOnly); }
      catch (err) {
        if (this._isConnRefused(err) && attempt < maxRetries && !this.aborted) {
          if (attempt % 10 === 0) {
            this.logger.info(`Connection refused, retrying (${attempt + 1}/${maxRetries})...`);
          }
          await this._sleep(retryDelay);
          continue;
        }
        throw err;
      }
    }
  }

  _connectH2Once(connectionOptions, isTcpOnly) {
    if (isTcpOnly) {
      return new Promise((resolve, reject) => {
        const socket = net.createConnection({ host: this.host, port: this.port });
        this.activeSockets.add(socket);
        socket.setTimeout(this.timeout);
        socket.on('connect', () => resolve(socket));
        socket.on('timeout', () => { 
          this.activeSockets.delete(socket);
          socket.destroy(); 
          reject(new Error('TCP connection timeout')); 
        });
        socket.on('error', (err) => {
          this.activeSockets.delete(socket);
          reject(err);
        });
      });
    }

    return new Promise((resolve, reject) => {
      const opts = {
        host: this.host, port: this.port,
        ALPNProtocols: ['h2'],
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
      };
      // Merge overrides; undefined values delete the key (e.g. to remove ALPNProtocols)
      if (connectionOptions) {
        for (const [k, v] of Object.entries(connectionOptions)) {
          if (v === undefined) delete opts[k];
          else opts[k] = v;
        }
      }
      const socket = tls.connect(opts);
      this.activeSockets.add(socket);
      socket.on('secureConnect', () => {
        this.logger.info(`TLS connected to ${this.host}:${this.port} (ALPN: ${socket.alpnProtocol || 'none'})`);
        resolve(socket);
      });
      socket.setTimeout(this.timeout);
      socket.on('timeout', () => {
        this.activeSockets.delete(socket);
        socket.destroy();
        reject(new Error('Connection timeout'));
      });
      socket.on('error', (err) => {
        this.activeSockets.delete(socket);
        if (!socket.destroyed) socket.destroy();
        reject(err);
      });
    });
  }

  // ── TLS Application Layer POST ──────────────────────────────────────────────

  _runTLSPost(action) {
    const bodySize = action.bodySize || 131072;
    const path = action.path || '/';
    const contentType = action.contentType || 'application/octet-stream';
    const chunked = action.chunked || false;
    const timeout = action.timeout || Math.max(this.timeout, 30000);

    return new Promise((resolve, reject) => {
      const tlsSocket = tls.connect({
        host: this.host, port: this.port,
        rejectUnauthorized: false,
        servername: this.host,
      });
      this.activeSockets.add(tlsSocket);

      tlsSocket.setTimeout(timeout);
      tlsSocket.on('timeout', () => {
        this.activeSockets.delete(tlsSocket);
        tlsSocket.destroy();
        resolve({ status: 'TIMEOUT', response: `Timeout after ${timeout}ms` });
      });
      tlsSocket.on('error', (err) => {
        this.activeSockets.delete(tlsSocket);
        resolve({ status: 'DROPPED', response: `TLS error: ${err.message}` });
      });

      tlsSocket.on('secureConnect', () => {
        this.logger.info(`TLS handshake complete: ${tlsSocket.getProtocol()} ${(tlsSocket.getCipher() || {}).name || ''}`);

        // Build HTTP/1.1 POST request
        const body = Buffer.alloc(bodySize, 0x41); // Fill with 'A'
        let header;
        if (chunked) {
          header = `POST ${path} HTTP/1.1\r\nHost: ${this.host}\r\nContent-Type: ${contentType}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n`;
        } else {
          header = `POST ${path} HTTP/1.1\r\nHost: ${this.host}\r\nContent-Type: ${contentType}\r\nContent-Length: ${bodySize}\r\nConnection: close\r\n\r\n`;
        }

        let responseData = '';
        tlsSocket.on('data', (data) => { responseData += data.toString(); });
        tlsSocket.on('end', () => {
          this.activeSockets.delete(tlsSocket);
          tlsSocket.destroy();
          const statusLine = responseData.split('\r\n')[0] || '';
          const httpStatus = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
          if (httpStatus) {
            resolve({ status: 'PASSED', response: `${statusLine} (${responseData.length} bytes)` });
          } else if (responseData.length > 0) {
            resolve({ status: 'PASSED', response: `Response: ${responseData.length} bytes` });
          } else {
            resolve({ status: 'DROPPED', response: 'Connection closed without response' });
          }
        });

        // Send header
        tlsSocket.write(header);

        // Send body
        if (chunked) {
          // Send in chunks
          const chunkSize = 16384;
          let offset = 0;
          const sendNextChunk = () => {
            if (offset >= bodySize) {
              tlsSocket.write('0\r\n\r\n'); // Final chunk
              return;
            }
            const end = Math.min(offset + chunkSize, bodySize);
            const chunk = body.slice(offset, end);
            tlsSocket.write(`${chunk.length.toString(16)}\r\n`);
            tlsSocket.write(chunk);
            tlsSocket.write('\r\n');
            offset = end;
            setImmediate(sendNextChunk);
          };
          sendNextChunk();
        } else {
          // Send body in 16KB writes to generate multiple TCP segments
          const chunkSize = 16384;
          let offset = 0;
          const sendNextChunk = () => {
            if (offset >= bodySize) return;
            const end = Math.min(offset + chunkSize, bodySize);
            tlsSocket.write(body.slice(offset, end));
            offset = end;
            if (offset < bodySize) setImmediate(sendNextChunk);
          };
          sendNextChunk();
        }
      });
    });
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  _describeTLSResponse(data) {
    const { records } = parseRecords(data);
    if (records.length === 0) return `Raw data (${data.length} bytes)`;

    // Check for alerts first — most important signal
    for (const r of records) {
      if (r.type === ContentType.ALERT && r.raw.length >= 7) {
        const level = r.raw[5] === AlertLevel.FATAL ? 'fatal' : 'warning';
        const desc = AlertDescriptionName[r.raw[6]] || `Unknown(${r.raw[6]})`;
        return `Alert(${level}, ${desc})`;
      }
    }

    // Check for ServerHello or ClientHello — extract negotiated details
    for (const r of records) {
      if (r.type === ContentType.HANDSHAKE && r.payload.length >= 1) {
        const hsType = r.payload[0];
        if (hsType === HandshakeType.SERVER_HELLO && r.payload.length >= 40) {
          const { getServerHelloVersion } = require('./constants');
          const realVersion = getServerHelloVersion(r.payload);
          const sidLen = r.payload[38];
          const csOffset = 39 + sidLen;
          if (csOffset + 1 < r.payload.length) {
            const cs = (r.payload[csOffset] << 8) | r.payload[csOffset + 1];
            const vName = VersionName[realVersion] || `0x${realVersion.toString(16)}`;
            const csName = CipherSuiteName[cs] || `0x${cs.toString(16)}`;
            return `ServerHello(${vName}, ${csName})`;
          }
          return `ServerHello(${VersionName[realVersion] || '0x' + realVersion.toString(16)})`;
        }
        if (hsType === HandshakeType.CLIENT_HELLO && r.payload.length >= 40) {
          const bodyVersion = (r.payload[4] << 8) | r.payload[5];
          return `ClientHello(${VersionName[bodyVersion] || '0x' + bodyVersion.toString(16)})`;
        }
      }
    }

    // Fallback: describe record types
    const { describeTLS } = require('./logger');
    return records.map(r => describeTLS(r.raw)).join(' + ');
  }

  /**
   * Check if HTTP/2 response data contains rejection frames (GOAWAY or RST_STREAM)
   */
  _h2HasRejectionFrame(data) {
    let offset = 0;
    while (offset + 9 <= data.length) {
      const frameLen = data.readUIntBE(offset, 3);
      const frameType = data[offset + 3];
      // GOAWAY (0x07) or RST_STREAM (0x03) indicate server rejected the request
      if (frameType === 0x07 || frameType === 0x03) return true;
      offset += 9 + frameLen;
      if (offset > data.length) break; // malformed frame, stop parsing
    }
    return false;
  }

  _describeH2Response(data) {
    const frameTypeNames = {
      0: 'DATA', 1: 'HEADERS', 2: 'PRIORITY', 3: 'RST_STREAM',
      4: 'SETTINGS', 5: 'PUSH_PROMISE', 6: 'PING', 7: 'GOAWAY',
      8: 'WINDOW_UPDATE', 9: 'CONTINUATION',
    };
    if (data.length < 9) return `Raw H2 data (${data.length} bytes)`;
    const descriptions = [];
    let offset = 0;
    while (offset + 9 <= data.length) {
      const frameLen = data.readUIntBE(offset, 3);
      const frameType = data[offset + 3];
      const typeName = frameTypeNames[frameType] || `type=0x${frameType.toString(16).padStart(2, '0')}`;
      descriptions.push(`H2 ${typeName}(${frameLen}B)`);
      offset += 9 + frameLen;
      if (descriptions.length >= 5) { descriptions.push('...'); break; }
    }
    return descriptions.join(' + ') || `Raw H2 data (${data.length} bytes)`;
  }

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    if (expected === 'CONNECTED') return status === 'CONNECTED' ? 'AS EXPECTED' : 'UNEXPECTED';
    if (expected === 'FAILED_CONNECTION') return status === 'FAILED_CONNECTION' ? 'AS EXPECTED' : 'UNEXPECTED';

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
        if (isClosedFn() || socket.destroyed) {
          clearInterval(checkClosed);
          setTimeout(done, 100);
        }
      }, 50);

      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearInterval(checkClosed);
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
    });
  }

  /**
   * Ping-based health probe — checks if the target host is reachable via ICMP ping.
   * TCP/HTTPS probes are unreliable after fuzz scenarios; ping checks host liveness.
   */
  async _runHealthProbes(host) {
    const { execFile } = require('child_process');
    const isDarwin = process.platform === 'darwin';
    const pingTimeout = isDarwin ? '2000' : '2'; // 2 seconds (ms on Darwin, sec on Linux)
    const start = Date.now();
    return new Promise((resolve) => {
      execFile('ping', ['-c', '1', '-W', pingTimeout, host], { timeout: 5000 }, (err) => {
        const latency = Date.now() - start;
        if (err) {
          const result = { alive: false, error: 'ping failed' };
          resolve({ tcp: result, https: result });
        } else {
          const result = { alive: true, latency };
          resolve({ tcp: result, https: result });
        }
      });
    });
  }

  // ── QUIC scenario dispatch ──────────────────────────────────────────────────
  async _runQuicScenario(scenario) {
    // Baseline/well-behaved scenarios need a real QUIC connection.
    // Fuzz scenarios send raw crafted UDP packets — they must use QuicFuzzerClient.
    if (scenario.isOpenSslBaseline) {
      let quicheLib = null;
      try {
        quicheLib = require('@currentspace/http3');
      } catch (e) {}

      if (quicheLib) {
        const { QuicheClient } = require('./quic-engines/quiche-client');
        const quicheClient = new QuicheClient({
          host: this.host, port: this.port,
          timeout: this.timeout, delay: this.delay,
          logger: this.logger, quicheLibrary: quicheLib
        });
        return quicheClient.runScenario(scenario);
      }

      const { QuicBaselineClient } = require('./quic-baseline');
      const quicBaselineClient = new QuicBaselineClient({
        host: this.host, port: this.port,
        timeout: this.timeout, logger: this.logger,
        processTracker: this.activeChildProcesses,
      });
      return quicBaselineClient.runScenario(scenario);
    }

    // Fuzz scenarios: stateless UDP with raw crafted packets
    const quicClient = new QuicFuzzerClient({
      host: this.host, port: this.port,
      timeout: this.timeout, delay: this.delay,
      logger: this.logger,
      socketTracker: this.activeSockets,
    });
    return quicClient.runScenario(scenario);
  }

  // ── Raw TCP scenario ─────────────────────────────────────────────────────────
  async _runRawTCPScenario(scenario) {
    if (!isRawAvailable()) {
      this.logger.error(`Skipping raw TCP scenario "${scenario.name}" — raw sockets not available (requires CAP_NET_RAW on Linux)`);
      return {
        scenario: scenario.name, description: scenario.description, category: scenario.category, severity: 'high',
        status: 'SKIPPED', expected: scenario.expected, verdict: 'N/A',
        response: 'Raw sockets not available (requires CAP_NET_RAW on Linux)',
        compliance: null, finding: 'skip', hostDown: false, probe: null,
      };
    }

    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    let rawSocket = null;
    let recvBuffer = Buffer.alloc(0);
    let lastResponse = '';
    let status = 'PASSED';
    let connectionClosed = false;
    let rawResponse = null;

    try {
      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'rawConnect': {
            rawSocket = new RawTCPSocket({
              dstIP: this.host,
              dstPort: this.port,
              window: action.window,
              logger: this.logger,
            });
            this.activeSockets.add(rawSocket);
            if (this.pcap) {
              rawSocket.onPacket = (packet, dir) => this.pcap.writeRawPacket(packet, dir);
            }
            rawSocket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
            rawSocket.on('end', () => { connectionClosed = true; });
            rawSocket.on('close', () => { connectionClosed = true; });
            rawSocket.on('error', (err) => {
              if (!connectionClosed) this.logger.error(`Raw socket error: ${err.message}`);
              connectionClosed = true;
            });
            try {
              await rawSocket.connect(action.window, this.timeout, {
                synOptions: action.synOptions || null,
                ackOptions: action.ackOptions || null,
              });
              this.logger.info(`Raw TCP connected to ${this.host}:${this.port}`);
            } catch (e) {
              this.logger.error(`Raw TCP connect failed: ${e.message}`);
              status = 'ERROR'; lastResponse = e.message;
            }
            break;
          }

          case 'rawSend': {
            const flags = action.flags || '';
            const data = action.data || null;
            const sock = rawSocket || new RawTCPSocket({
              dstIP: this.host,
              dstPort: this.port,
              logger: this.logger,
            });
            if (!rawSocket) {
              // One-shot raw send (no prior connect)
              if (this.pcap) {
                sock.onPacket = (packet, dir) => this.pcap.writeRawPacket(packet, dir);
              }
            }
            try {
              await sock.sendSegment({
                flags,
                data,
                seqOffset: action.seqOffset,
                ackOffset: action.ackOffset,
                seqOverride: action.seqOverride,
                window: action.window,
                urgentPointer: action.urgentPointer,
                tcpOptions: action.tcpOptions || null,
              });
              this.logger.fuzz(action.label || `Raw TCP [${flags}]`);
            } catch (e) {
              this.logger.error(`Raw send failed: ${e.message}`);
              status = 'ERROR';
            }
            if (!rawSocket) {
              // Keep the one-shot socket for potential recv
              rawSocket = sock;
              rawSocket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
              rawSocket.on('end', () => { connectionClosed = true; });
              rawSocket.on('close', () => { connectionClosed = true; });
              rawSocket.on('error', () => { connectionClosed = true; });
            }
            break;
          }

          case 'synFlood': {
            this.logger.fuzz(`SYN flood: ${action.count} packets, spoofed=${!!action.spoofSource}`);
            try {
              await RawTCPSocket.flood(this.host, this.port, action.count, action.spoofSource);
              this.logger.info(`SYN flood complete: ${action.count} packets sent`);
            } catch (e) {
              this.logger.error(`SYN flood failed: ${e.message}`);
              status = 'ERROR'; lastResponse = e.message;
            }
            break;
          }

          case 'sendOverlapping': {
            if (!rawSocket) { status = 'ERROR'; lastResponse = 'No raw connection'; break; }
            this.logger.fuzz(`Overlapping segments: ${action.overlapBytes}B overlap`);
            try {
              await rawSocket.sendOverlapping(action.data, action.overlapBytes);
            } catch (e) {
              this.logger.error(`Overlapping send failed: ${e.message}`);
              status = 'ERROR';
            }
            break;
          }

          case 'sendOutOfOrder': {
            if (!rawSocket) { status = 'ERROR'; lastResponse = 'No raw connection'; break; }
            this.logger.fuzz(`Out-of-order segments: ${action.segments} segs, order=${action.order}`);
            try {
              await rawSocket.sendOutOfOrder(action.data, action.segments, action.order);
            } catch (e) {
              this.logger.error(`Out-of-order send failed: ${e.message}`);
              status = 'ERROR';
            }
            break;
          }

          case 'tcpProbe': {
            const alive = await RawTCPSocket.probe(this.host, this.port, 2000);
            this.logger.info(`TCP probe: ${this.host}:${this.port} is ${alive ? 'alive' : 'dead'}`);
            if (!alive) {
              status = 'DROPPED';
              lastResponse = 'Target became unreachable';
            } else {
              lastResponse = lastResponse || 'Target alive';
            }
            break;
          }

          // Standard actions work via RawTCPSocket's compatible interface
          case 'send': {
            if (!rawSocket || connectionClosed || rawSocket.destroyed) {
              this.logger.error('Cannot send: no raw connection'); status = 'DROPPED'; break;
            }
            try {
              rawSocket.write(action.data);
              this.logger.sent(action.data, action.label);
            } catch (e) { this.logger.error(`Write failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'recv': {
            if (!rawSocket) { status = 'TIMEOUT'; lastResponse = 'No connection'; break; }
            const alreadyReceived = recvBuffer;
            recvBuffer = Buffer.alloc(0);
            const dataFromWait = await this._waitForData(rawSocket, action.timeout || this.timeout, () => connectionClosed);
            recvBuffer = Buffer.alloc(0); // clear data already captured by _waitForData
            const data = Buffer.concat([alreadyReceived, dataFromWait || Buffer.alloc(0)]);
            if (data && data.length > 0) {
              this.logger.received(data);
              lastResponse = this._describeTLSResponse(data);
              rawResponse = data;
            } else if (connectionClosed) {
              lastResponse = 'Connection closed'; status = 'DROPPED';
            } else {
              lastResponse = 'Timeout'; status = 'TIMEOUT';
            }
            break;
          }

          case 'delay': await this._sleep(action.ms); break;

          case 'fin': {
            if (rawSocket) {
              this.logger.tcpEvent('sent', action.label || 'FIN');
              rawSocket.end();
            }
            break;
          }

          case 'rst': {
            if (rawSocket) {
              this.logger.tcpEvent('sent', action.label || 'RST');
              rawSocket.destroy();
              connectionClosed = true;
            }
            break;
          }
        }

        if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
      }
    } catch (e) {
      this.logger.error(`Raw TCP scenario failed: ${e.message}`);
      status = 'ERROR'; lastResponse = e.message;
    } finally {
      if (rawSocket) {
        this.activeSockets.delete(rawSocket);
        if (!rawSocket.destroyed) rawSocket.destroy();
      }
    }

    let hostDown = false, probe = null;
    if (['DROPPED', 'TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host);
      hostDown = !probe.tcp.alive && !probe.https.alive;
      if (hostDown) this.logger.hostDown(this.host, this.port, scenario.name);
    }

    const computed = computeExpected(scenario);
    const expected = 'expected' in scenario ? scenario.expected : computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    let verdict = this._computeVerdict(status, expected, lastResponse);

    // Differential Fuzzing Override — semantic behavior matching
    const { normalizeResponse, classifyBehavior } = require('./grader');
    const normResponse = normalizeResponse(lastResponse || status);
    const normBaseline = normalizeResponse(scenario._baselineResponse);
    if (normBaseline && normResponse === normBaseline) {
      verdict = 'AS EXPECTED';
    } else if (scenario._baselineResponse) {
      const targetBehavior = classifyBehavior(lastResponse || status, status);
      const baselineBehavior = classifyBehavior(scenario._baselineResponse, null);
      if (targetBehavior !== 'unknown' && targetBehavior === baselineBehavior) {
        verdict = 'AS EXPECTED';
      }
    }

    const severity = CATEGORY_SEVERITY[scenario.category] || 'high';
    const compliance = null; // Raw TCP has no TLS compliance check
    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category, severity,
      status, expected, verdict, hostDown, probe,
      response: lastResponse || status,
      compliance,
      _baselineResponse: scenario._baselineResponse,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding, compliance);
    return result;
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  async _connectNodeTLSWithRetry(options = {}) {
    // Retry for up to 35 seconds — server scenarios can take up to 30s
    // (accept timeout) before the next one starts listening
    const maxRetries = 70;
    const retryDelay = 500;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      let sock = null;
      try {
        return await new Promise((resolve, reject) => {
          let settled = false;
          sock = tls.connect({
            host: this.host,
            port: this.port,
            rejectUnauthorized: false,
            ALPNProtocols: ['http/1.1'],
            ...options
          }, () => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve(sock);
          });
          this.activeSockets.add(sock);
          sock.on('error', (err) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            reject(err);
          });
          const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            // Destroy the socket — without this, the FD leaks
            if (sock && !sock.destroyed) sock.destroy();
            reject(new Error('TLS connect timeout'));
          }, this.timeout);
        });
      } catch (err) {
        // Clean up failed socket from activeSockets to prevent accumulation
        if (sock) {
          this.activeSockets.delete(sock);
          if (!sock.destroyed) sock.destroy();
        }
        if (this._isConnRefused(err) && attempt < maxRetries && !this.aborted) {
          if (attempt % 10 === 0) {
            this.logger.info(`[node-tls] Connection refused, retrying (${attempt + 1}/${maxRetries})...`);
          }
          await this._sleep(retryDelay);
          continue;
        }
        throw err;
      }
    }
  }

  close() {
    // Destroy any lingering sockets to prevent FD leaks
    for (const socket of this.activeSockets) {
      try { if (!socket.destroyed) socket.destroy(); } catch (_) {}
    }
    this.activeSockets.clear();
    for (const proc of this.activeChildProcesses) {
      try { proc.kill('SIGKILL'); } catch (_) {}
    }
    this.activeChildProcesses.clear();
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
    if (this._healthSocket && !this._healthSocket.destroyed) {
      this._healthSocket.destroy();
      this._healthSocket = null;
    }
  }
}

module.exports = { UnifiedClient };
