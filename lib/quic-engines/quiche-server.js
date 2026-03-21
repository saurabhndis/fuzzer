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
    this.pcapFileBase = opts.pcapFile || null;
    this.pcap = null;
    this.aborted = false;
    this.server = null;
    this.keyPEM = opts.keyPEM;
    this.certPEM = opts.certPEM;
  }

  async start() {
    if (this.server) return;
    try {
      // Use HTTP/3 secure server API for proper ALPN and H3 framing
      const createFn = this.quiche.createSecureServer || this.quiche.createQuicServer;
      this.server = createFn({
        key: this.keyPEM,
        cert: this.certPEM,
      });

      // Event handling will be wired per-scenario
      await this.server.listen(this.port, this.hostname);
      this.logger.info(`HTTP/3 server listening on ${this.hostname}:${this.port} (UDP, quiche)`);
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

    // Initialize per-scenario PCAP if a base filename was provided
    if (this.pcapFileBase) {
      const { PcapWriter } = require('../pcap-writer');
      const path = require('path');
      const ext = path.extname(this.pcapFileBase) || '.pcap';
      const base = this.pcapFileBase.endsWith(ext)
        ? this.pcapFileBase.slice(0, -ext.length)
        : this.pcapFileBase;
      const pcapFilename = `${base}.${scenario.name}.server${ext}`;
      try {
        this.pcap = new PcapWriter(pcapFilename, {
          role: 'server',
          serverPort: this.port,
          clientPort: 49152 + Math.floor(Math.random() * 16000),
        });
      } catch (e) {
        this.logger.error(`Failed to initialize PCAP: ${e.message}`);
        this.pcap = null;
      }
    }

    this.logger.info(`Waiting for QUIC client connection on port ${this.port}...`);
    
    let status = 'PASSED';
    let lastResponse = '';

    const promise = new Promise((resolve) => {
      const timer = setTimeout(() => {
        resolve({ status: 'TIMEOUT', response: 'QUIC connection timed out' });
      }, this.timeout);

      let streamCount = 0;

      // HTTP/3 stream event fires on the server directly (not per-session)
      const streamHandler = (stream, headers) => {
        streamCount++;
        const method = headers[':method'] || 'GET';
        let body = Buffer.alloc(0);

        if (method === 'POST' || method === 'PUT') {
          stream.on('data', (chunk) => { body = Buffer.concat([body, chunk]); });
          stream.on('end', () => {
            try {
              stream.respond({ ':status': 200, 'content-type': 'application/octet-stream' });
              stream.end(body); // echo payload
            } catch (_) {}
          });
        } else {
          try {
            stream.respond({ ':status': 200, 'content-type': 'text/plain' });
            stream.end('OK');
          } catch (_) {}
        }
        stream.on('error', () => {});
      };

      this.server.on('stream', streamHandler);

      this.server.once('session', (session) => {
        clearTimeout(timer);
        const remoteInfo = session.remoteAddress ? `${session.remoteAddress}:${session.remotePort}` : 'unknown';
        this.logger.info(`HTTP/3 session established (client: ${remoteInfo})`);

        // Hook up packet tracking
        if (this.pcap) {
          session.on('packet', (packet, dir) => {
            this.pcap.writeUDPPacket(packet, dir === 'out' ? 'sent' : 'received');
          });
        }

        session.on('close', () => {
          this.server.removeListener('stream', streamHandler);
          resolve({ status: 'PASSED', response: `Handled ${streamCount} stream(s) (client: ${remoteInfo})` });
        });

        // Don't resolve until we've seen at least one stream or a reasonable timeout
        const checkDone = () => {
          if (streamCount > 0) {
            this.server.removeListener('stream', streamHandler);
            resolve({ status: 'PASSED', response: `Handled ${streamCount} stream(s) (client: ${remoteInfo})` });
          } else {
            setTimeout(checkDone, 500);
          }
        };
        setTimeout(checkDone, 1000);
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
    
    if (this.pcap) {
      this.pcap.close();
      this.pcap = null;
    }

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
