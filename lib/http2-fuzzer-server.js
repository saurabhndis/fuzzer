// HTTP/2 Fuzzing Server — starts a real HTTP/2 server that clients can fuzz against,
// or acts as a malicious server to fuzz connecting HTTP/2 clients (AJ scenarios).
const http2 = require('http2');
const { Logger } = require('./logger');
const { generateServerCert } = require('./cert-gen');

/**
 * Convert a DER-encoded certificate buffer to PEM format
 */
function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

class Http2FuzzerServer {
  constructor(opts = {}) {
    this.port = opts.port || 4433;
    this.hostname = opts.hostname || 'localhost';
    this.logger = opts.logger || new Logger(opts);
    this.server = null;
    this.aborted = false;
    this._stopResolve = null;

    const certInfo = generateServerCert(this.hostname);
    this.certPEM = derToPem(certInfo.certDER);
    this.privateKeyPEM = certInfo.privateKeyPEM;
    this.fingerprint = certInfo.fingerprint;
  }

  abort() {
    this.aborted = true;
    if (this.server) {
      this.server.close();
    }
    if (this._stopResolve) {
      this._stopResolve();
      this._stopResolve = null;
    }
  }

  getCertInfo() {
    return {
      hostname: this.hostname,
      fingerprint: this.fingerprint,
    };
  }

  /**
   * Start the HTTP/2 server. Emits logger events for each session and stream.
   */
  async start() {
    this.server = http2.createSecureServer({
      key: this.privateKeyPEM,
      cert: this.certPEM,
      allowHTTP1: true,
    });

    this.server.on('error', (err) => {
      this.logger.error(`HTTP/2 server error: ${err.message}`);
    });

    this.server.on('session', (session) => {
      const remoteAddr = session.socket ? session.socket.remoteAddress : 'unknown';
      this.logger.info(`HTTP/2 session from ${remoteAddr}`);

      session.on('error', (err) => {
        this.logger.error(`Session error from ${remoteAddr}: ${err.message}`);
      });

      session.on('close', () => {
        this.logger.info(`Session closed from ${remoteAddr}`);
      });

      session.on('frameError', (type, code, id) => {
        this.logger.fuzz(`Frame error: type=0x${type.toString(16)} code=${code} stream=${id}`);
      });
    });

    this.server.on('stream', (stream, headers) => {
      const method = headers[':method'] || 'UNKNOWN';
      const path = headers[':path'] || '/';
      this.logger.info(`HTTP/2 request: ${method} ${path}`);

      stream.on('error', (err) => {
        this.logger.error(`Stream error: ${err.message}`);
      });

      try {
        stream.respond({ ':status': 200, 'content-type': 'text/plain' });
        stream.end('HTTP/2 fuzzer server OK');
      } catch (_) {}
    });

    this.server.on('unknownProtocol', (socket) => {
      this.logger.fuzz('Unknown protocol attempted (possible fuzzing client)');
      socket.destroy();
    });

    await new Promise((resolve, reject) => {
      this.server.listen(this.port, '0.0.0.0', () => {
        this.logger.info(
          `HTTP/2 server listening on 0.0.0.0:${this.port} | ` +
          `cert SHA256=${this.fingerprint.slice(0, 16)}...`
        );
        resolve();
      });
      this.server.once('error', reject);
    });
  }

  /**
   * Run a single server-side scenario (AJ category).
   * Waits for a client to connect, then calls scenario.serverHandler(stream, session, log).
   * The scenario's handler sends malicious frames/responses to the connecting client.
   */
  async runScenario(scenario) {
    if (!this.server) await this.start();
    if (this.aborted) {
      return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };
    }

    this.logger.scenario(scenario.name, scenario.description);
    this.logger.info(`Waiting for client to connect on port ${this.port}...`);

    return new Promise((resolve) => {
      const scenarioTimeout = 60000; // 60s wait for client connection

      const timeout = setTimeout(() => {
        this.server.removeListener('stream', onStream);
        this.logger.error(`Scenario "${scenario.name}" timed out — no client connected.`);
        resolve({
          scenario: scenario.name,
          category: scenario.category,
          severity: 'high',
          status: 'TIMEOUT',
          expected: scenario.expected,
          verdict: 'N/A',
          response: 'No client connected within 60s',
          compliance: null,
          finding: 'timeout',
          hostDown: false,
          probe: null,
        });
      }, scenarioTimeout);

      const onStream = (stream, headers) => {
        clearTimeout(timeout);
        this.server.removeListener('stream', onStream);

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
            scenario: scenario.name,
            category: scenario.category,
            severity: 'high',
            status: 'PASSED',
            expected: scenario.expected,
            verdict: 'AS EXPECTED',
            response: `Handler executed (client: ${remoteAddr})`,
            compliance: null,
            finding: 'pass',
            hostDown: false,
            probe: null,
          });
        } catch (e) {
          this.logger.error(`Scenario handler error: ${e.message}`);
          resolve({
            scenario: scenario.name,
            category: scenario.category,
            severity: 'high',
            status: 'ERROR',
            expected: scenario.expected,
            verdict: 'N/A',
            response: e.message,
            compliance: null,
            finding: 'error',
            hostDown: false,
            probe: null,
          });
        }
      };

      this.server.once('stream', onStream);
    });
  }

  /**
   * Returns a promise that resolves when abort() is called.
   */
  waitForStop() {
    return new Promise((resolve) => {
      if (this.aborted) return resolve();
      this._stopResolve = resolve;
    });
  }
}

module.exports = { Http2FuzzerServer };
