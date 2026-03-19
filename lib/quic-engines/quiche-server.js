const { Logger } = require('../logger');
const { gradeResult } = require('../grader');
const { computeExpected } = require('../compute-expected');
const { QUIC_CATEGORY_SEVERITY } = require('../quic-scenarios');

class QuicheServer {
  constructor(opts = {}) {
    this.port = opts.port || 4433;
    this.hostname = opts.hostname || 'localhost';
    this.timeout = opts.timeout || 10000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.quiche = opts.quicheLibrary; // Passed in if installed
    this.aborted = false;
    this.server = null;
    this.keyPEM = opts.keyPEM;
    this.certPEM = opts.certPEM;
  }

  async start() {
    if (this.server) return;
    try {
      this.server = this.quiche.createQuicServer({
        key: this.keyPEM,
        cert: this.certPEM,
        alpn: ['quic', 'h3', 'h3-29', 'h3-32'],
      });

      // Event handling will be wired per-scenario
      await this.server.listen(this.port, '0.0.0.0');
      this.logger.info(`QUIC server listening on 0.0.0.0:${this.port} (UDP, quiche)`);
    } catch (e) {
      this.logger.error(`Failed to start QuicheServer: ${e.message}`);
      throw e;
    }
  }

  abort() {
    this.aborted = true;
    if (this.server) {
      try { this.server.close(); } catch (e) {}
    }
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, `${scenario.description} (using quiche Native Engine)`);
    this.logger.info(`Waiting for QUIC client connection on port ${this.port}...`);
    
    let status = 'PASSED';
    let lastResponse = '';

    const promise = new Promise((resolve) => {
      const timer = setTimeout(() => {
        resolve({ status: 'TIMEOUT', response: 'QUIC connection timed out' });
      }, this.timeout);

      // Simple implementation handling 'well-behaved-quic-server'
      this.server.once('session', (session) => {
        clearTimeout(timer);
        const remoteInfo = session.remoteAddress ? `${session.remoteAddress}:${session.remotePort}` : 'unknown';
        this.logger.info(`Handler executed (client: ${remoteInfo})`);
        
        session.on('stream', (stream) => {
          stream.on('data', () => {});
          stream.end(Buffer.from('Handler executed'));
        });

        session.on('close', () => {
           resolve({ status: 'PASSED', response: `Handler executed (client: ${remoteInfo})` });
        });
        
        setTimeout(() => {
           resolve({ status: 'PASSED', response: `Handler executed (client: ${remoteInfo})` });
        }, 1000); // Give it some time then resolve anyway
      });
      
      this.server.on('error', (e) => {
        clearTimeout(timer);
        resolve({ status: 'ERROR', response: e.message });
      });
    });

    const resultFromPromise = await promise;
    status = resultFromPromise.status;
    lastResponse = resultFromPromise.response;

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
    
    // Clean up event listeners for the next scenario
    this.server.removeAllListeners('session');
    this.server.removeAllListeners('error');
    
    return result;
  }

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    const expectedEffective = expected === 'TIMEOUT' ? 'DROPPED' : expected;
    return effective === expectedEffective ? 'AS EXPECTED' : 'UNEXPECTED';
  }
}

module.exports = { QuicheServer };
