const { Logger } = require('../logger');
const { gradeResult } = require('../grader');
const { computeExpected } = require('../compute-expected');
const { QUIC_CATEGORY_SEVERITY } = require('../quic-scenarios');

class QuicheClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.timeout = opts.timeout || 5000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.quiche = opts.quicheLibrary;
    this.aborted = false;
  }

  abort() {
    this.aborted = true;
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, `${scenario.description} (quiche)`);

    let status = 'PASSED';
    let lastResponse = '';

    try {
      const session = await this._connect();

      if (scenario.clientHandler) {
        // Custom handler (e.g. multi-stream scenarios)
        if (scenario.useNodeH2) {
          // If the scenario expects an H2 session (like h2-fw-*), pass the raw QUIC session
          // which provides the request() method for H3.
          const result = await scenario.clientHandler(session, this.host, this.logger);
          status = result.status || 'PASSED';
          lastResponse = result.response || '';
        } else {
          // Wrap session in a shim that mimics a TLS socket for compatibility with firewall-scenarios
          const stream = session.openStream();
          const shim = {
            write: (data) => stream.write(data),
            on: (event, cb) => stream.on(event, cb),
            end: (data) => stream.end(data),
            destroy: () => stream.destroy(),
            getProtocol: () => 'QUIC/HTTP3'
          };
          const result = await scenario.clientHandler(shim, this.host, this.logger);
          status = result.status || 'PASSED';
          lastResponse = result.response || '';
        }
      } else {
        // Default: open a bidirectional stream, send a small payload, read response
        const stream = session.openStream();
        const payload = `GET / HTTP/1.1\r\nHost: ${this.host}\r\n\r\n`;
        stream.end(payload);

        const resp = await new Promise((resolve) => {
          let buf = Buffer.alloc(0);
          stream.on('data', (d) => { buf = Buffer.concat([buf, d]); });
          stream.on('end', () => resolve(buf));
          stream.on('error', () => resolve(buf));
          setTimeout(() => resolve(buf), this.timeout);
        });

        lastResponse = resp.length > 0
          ? `QUIC stream response (${resp.length} bytes via quiche)`
          : 'No stream data received';
      }

      try { session.close(); } catch (_) {}
    } catch (e) {
      this.logger.error(`[quiche] ${e.message}`);
      // Connection refused / timeout = server dropped the connection (expected for fuzz targets)
      if (/ECONNREFUSED|timeout|timed out|closed|reset/i.test(e.message)) {
        status = 'DROPPED';
        lastResponse = e.message;
      } else {
        status = 'ERROR';
        lastResponse = e.message;
      }
    }

    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    const verdict = this._computeVerdict(status, expected, lastResponse);
    const severity = QUIC_CATEGORY_SEVERITY[scenario.category] || 'medium';

    const result = {
      scenario: scenario.name, description: scenario.description,
      category: scenario.category, severity,
      status, expected, verdict,
      response: lastResponse || status,
      compliance: null, finding: null, hostDown: false, probe: null,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, false, result.finding, null);
    return result;
  }

  _connect() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('QUIC connection timed out'));
      }, this.timeout);

      try {
        const session = this.quiche.connectQuic(`${this.host}:${this.port}`, {
          rejectUnauthorized: false,
        });

        session.on('connect', () => {
          clearTimeout(timer);
          resolve(session);
        });

        session.on('error', (e) => {
          clearTimeout(timer);
          reject(e);
        });
      } catch (e) {
        clearTimeout(timer);
        reject(e);
      }
    });
  }

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    if (response && /QUIC.*CONNECTION_CLOSE/i.test(response)) return 'AS EXPECTED';
    if (response && /Version Negotiation/i.test(response)) return 'AS EXPECTED';
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    const expectedEffective = expected === 'TIMEOUT' ? 'DROPPED' : expected;
    return effective === expectedEffective ? 'AS EXPECTED' : 'UNEXPECTED';
  }
}

module.exports = { QuicheClient };
