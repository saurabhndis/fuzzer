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
      
      // Ensure session is fully established (handshake complete)
      if (session.ready) {
        await session.ready();
      }

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
          // Use request() for H3 sessions, openStream() for raw QUIC
          const useH3 = typeof session.request === 'function';
          const stream = useH3 
            ? session.request({ ':method': 'POST', ':path': '/', ':scheme': 'https', ':authority': this.host })
            : session.openStream();

          const shim = {
            write: (data) => stream.write(data),
            on: (event, cb) => stream.on(event, cb),
            end: (data) => stream.end(data),
            destroy: () => { if (stream.destroy) stream.destroy(); else stream.close(); },
            getProtocol: () => useH3 ? 'HTTP/3' : 'QUIC/Raw'
          };
          const result = await scenario.clientHandler(shim, this.host, this.logger, session);
          status = result.status || 'PASSED';
          lastResponse = result.response || '';
        }
      } else {
        // Open one or more HTTP/3 streams, send requests, collect responses
        const streamCount = scenario.streamCount || 1;
        const useH3 = typeof session.request === 'function';
        const results = [];

        for (let i = 0; i < streamCount; i++) {
          const resp = await new Promise((resolve) => {
            let buf = Buffer.alloc(0);
            let statusCode = '';

            if (useH3) {
              const req = session.request({
                ':method': 'GET',
                ':path': i === 0 ? '/' : `/stream-${i}`,
                ':scheme': 'https',
                ':authority': this.host,
              });
              req.on('response', (h) => { statusCode = h[':status'] || ''; });
              req.on('data', (d) => { buf = Buffer.concat([buf, d]); });
              req.on('end', () => resolve({ bytes: buf.length, status: statusCode }));
              req.on('error', () => resolve({ bytes: buf.length, status: statusCode }));
              req.end();
            } else {
              const stream = session.openStream();
              const payload = `GET / HTTP/1.1\r\nHost: ${this.host}\r\nX-Stream: ${i}\r\n\r\n`;
              stream.end(payload);
              stream.on('data', (d) => { buf = Buffer.concat([buf, d]); });
              stream.on('end', () => resolve({ bytes: buf.length, status: '' }));
              stream.on('error', () => resolve({ bytes: buf.length, status: '' }));
            }

            setTimeout(() => resolve({ bytes: buf.length, status: statusCode || '' }), this.timeout);
          });

          results.push({ stream: i, ...resp });
        }

        const totalBytes = results.reduce((s, r) => s + r.bytes, 0);
        lastResponse = totalBytes > 0
          ? `HTTP/3 ${streamCount} stream(s), ${totalBytes} bytes total via quiche`
          : 'No stream data received';
      }

      // Allow final data to be processed before closing
      await new Promise(r => setTimeout(r, 200));
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
        // Use HTTP/3 API (lib.connect) for proper ALPN and H3 framing;
        // fall back to raw QUIC (connectQuic) for non-H3 scenarios.
        const connectFn = this.quiche.connect || this.quiche.connectQuic;
        const target = this.quiche.connect
          ? `https://${this.host}:${this.port}`
          : `${this.host}:${this.port}`;

        const session = connectFn(target, {
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
