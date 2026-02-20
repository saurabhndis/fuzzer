// Unified Fuzzing Server — handles both TLS and HTTP/2 server-side scenarios.
// TLS scenarios (categories A–Y): raw TCP server, per-scenario accept-and-execute.
// HTTP/2 scenarios (categories AA–AJ, side: 'server'): persistent HTTP/2 server,
//   waits for each client connection and calls scenario.serverHandler().
const net = require('net');
const http2 = require('http2');
const { Logger } = require('./logger');
const { PcapWriter } = require('./pcap-writer');
const { sendFIN, sendRST, configureSocket } = require('./tcp-tricks');
const { parseRecords } = require('./record');
const { gradeResult, computeOverallGrade } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { generateServerCert } = require('./cert-gen');

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

// H2 scenarios have a serverHandler function; TLS scenarios use actions()
function isH2Scenario(scenario) {
  return typeof scenario.serverHandler === 'function';
}

class UnifiedServer {
  constructor(opts = {}) {
    this.port = opts.port || 4433;
    this.hostname = opts.hostname || 'localhost';
    this.timeout = opts.timeout || 10000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.pcapFile = opts.pcapFile || null;
    this.aborted = false;

    // Active server instances
    this.tlsServer = null;   // net.Server (created per TLS scenario)
    this.h2Server = null;    // http2.Server (persistent, shared across H2 scenarios)
    this._h2StopResolve = null;

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
    const h2gen = generateServerCert(this.hostname);
    this.h2CertPEM = derToPem(h2gen.certDER);
    this.h2KeyPEM = h2gen.privateKeyPEM;
    this.h2Fingerprint = h2gen.fingerprint;
  }

  abort() {
    this.aborted = true;
    if (this.tlsServer) this.tlsServer.close();
    if (this.h2Server) this.h2Server.close();
    if (this._h2StopResolve) { this._h2StopResolve(); this._h2StopResolve = null; }
  }

  getCertInfo() {
    return {
      hostname: this.hostname,
      fingerprint: this.certInfo.fingerprint || 'N/A',
      h2Fingerprint: this.h2Fingerprint,
    };
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };
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

  // ── TLS server scenario ─────────────────────────────────────────────────────
  _runTLSScenario(scenario) {
    return new Promise((resolve) => {
      this.logger.scenario(scenario.name, scenario.description);

      const pcap = this.pcapFile ? new PcapWriter(this.pcapFile, {
        srcPort: this.port,
        dstPort: 49152 + Math.floor(Math.random() * 16000),
      }) : null;

      let acceptTimer = null;

      this.tlsServer = net.createServer({ allowHalfOpen: true }, async (socket) => {
        clearTimeout(acceptTimer);
        configureSocket(socket);
        this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);
        if (pcap) pcap.writeTCPHandshake();

        const actions = scenario.actions({ serverCert: this.certDER, hostname: this.hostname });
        let connectionClosed = false;
        let lastResponse = '';
        let rawResponse = null;
        let status = 'PASSED';

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
              const data = await this._waitForData(socket, action.timeout || this.timeout, () => connectionClosed);
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
          }

          if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
        }

        if (!socket.destroyed) socket.destroy();
        if (pcap) pcap.close();

        const computed = computeExpected(scenario);
        const expected = scenario.expected || computed.expected;
        const expectedReason = scenario.expectedReason || computed.reason;
        const verdict = this._computeVerdict(status, expected);
        const result = {
          scenario: scenario.name, category: scenario.category,
          status, expected, verdict,
          response: lastResponse || status,
        };
        gradeResult(result, scenario);
        this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason);

        this.tlsServer.close();
        this.tlsServer = null;
        resolve(result);
      });

      this.tlsServer.listen(this.port, '0.0.0.0', () => {
        this.logger.info(`Fuzzer server listening on 0.0.0.0:${this.port} — waiting for connection...`);
        acceptTimer = setTimeout(() => {
          const computed = computeExpected(scenario);
          this.tlsServer.close();
          this.tlsServer = null;
          resolve({
            scenario: scenario.name, category: scenario.category,
            status: 'TIMEOUT',
            expected: scenario.expected || computed.expected,
            verdict: 'N/A',
            response: 'No client connected (accept timeout)',
          });
        }, 30000);
      });

      this.tlsServer.on('error', (err) => {
        this.logger.error(`Server error: ${err.message}`);
        clearTimeout(acceptTimer);
        resolve({ scenario: scenario.name, status: 'ERROR', response: err.message });
      });
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

    this.h2Server.on('session', (session) => {
      const remoteAddr = session.socket ? session.socket.remoteAddress : 'unknown';
      this.logger.info(`HTTP/2 session from ${remoteAddr}`);
      session.on('error', (err) => { this.logger.error(`Session error: ${err.message}`); });
      session.on('close', () => { this.logger.info(`Session closed from ${remoteAddr}`); });
    });

    // Default handler responds 200 OK (used between scenarios / passive mode)
    this.h2Server.on('stream', (stream, headers) => {
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
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, scenario.description);
    this.logger.info(`Waiting for client to connect on port ${this.port}...`);

    return new Promise((resolve) => {
      const scenarioTimeout = setTimeout(() => {
        this.h2Server.removeListener('stream', onStream);
        this.logger.error(`Scenario "${scenario.name}" timed out — no client connected.`);
        resolve({
          scenario: scenario.name, category: scenario.category,
          severity: 'high', status: 'TIMEOUT',
          expected: scenario.expected, verdict: 'N/A',
          response: 'No client connected within 60s',
          compliance: null, finding: 'timeout', hostDown: false, probe: null,
        });
      }, 60000);

      const onStream = (stream) => {
        clearTimeout(scenarioTimeout);
        this.h2Server.removeListener('stream', onStream);

        const remoteAddr = stream.session && stream.session.socket
          ? stream.session.socket.remoteAddress : 'unknown';
        this.logger.info(`Client connected from ${remoteAddr} — executing scenario handler`);

        const log = (msg) => this.logger.info(msg);
        try {
          scenario.serverHandler(stream, stream.session, log);
          this.logger.result(
            scenario.name, 'PASSED', 'Server handler executed', 'AS EXPECTED',
            scenario.expectedReason || '', false, 'pass', null
          );
          resolve({
            scenario: scenario.name, category: scenario.category,
            severity: 'high', status: 'PASSED',
            expected: scenario.expected, verdict: 'AS EXPECTED',
            response: `Handler executed (client: ${remoteAddr})`,
            compliance: null, finding: 'pass', hostDown: false, probe: null,
          });
        } catch (e) {
          this.logger.error(`Scenario handler error: ${e.message}`);
          resolve({
            scenario: scenario.name, category: scenario.category,
            severity: 'high', status: 'ERROR',
            expected: scenario.expected, verdict: 'N/A',
            response: e.message,
            compliance: null, finding: 'error', hostDown: false, probe: null,
          });
        }
      };

      this.h2Server.once('stream', onStream);
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

  // ── Shared helpers ──────────────────────────────────────────────────────────

  _describeTLSResponse(data) {
    const { records } = parseRecords(data);
    if (records.length === 0) return `Raw data (${data.length} bytes)`;
    const { describeTLS } = require('./logger');
    return records.map(r => describeTLS(r.raw)).join(' + ');
  }

  _computeVerdict(status, expected) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
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
