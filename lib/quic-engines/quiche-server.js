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
    this.mergePcap = opts.mergePcap || false;
    this.pcap = null;
    this.aborted = false;
    this.server = null;
    this.keyPEM = opts.keyPEM;
    this.certPEM = opts.certPEM;
    
    // Session and Stream buffering for concurrent connections in distributed mode
    this.sessionQueue = [];
    this.activeSessionHandler = null; // Current scenario's session handler
    this.activeSession = null;        // Current scenario's active session
    this.sessionData = new Map();     // Map<Session, { streams: [], resolver: null }>
  }

  async start() {
    if (this.server) return;
    try {
      const createFn = this.quiche.createSecureServer || this.quiche.createQuicServer;
      
      this.logger.info(`[quiche-server] Starting with Key starting with: ${this.keyPEM ? this.keyPEM.substring(0, 30).replace(/\n/g, '\\n') : 'null'}`);
      this.logger.info(`[quiche-server] Starting with Cert starting with: ${this.certPEM ? this.certPEM.substring(0, 30).replace(/\n/g, '\\n') : 'null'}`);

      this.server = createFn({
        key: this.keyPEM,
        cert: this.certPEM,
      });

      // Permanent session listener
      this.server.on('session', (session) => {
        const connHandle = session._connHandle;
        this.logger.info(`[quiche-server] Session established. Handle: ${connHandle}`);
        const data = { streams: [], onStream: null };
        this.sessionData.set(connHandle, data);
        
        session.on('close', () => {
          session._isClosed = true;
          this.sessionData.delete(connHandle);
          if (this.activeSession === session) {
            if (this.activeSessionHandler && this.activeSessionHandler.onClose) {
              this.activeSessionHandler.onClose();
            }
          }
        });

        session.on('error', (e) => {
          if (this.activeSession === session) {
            if (this.activeSessionHandler && this.activeSessionHandler.onError) {
              this.activeSessionHandler.onError(e);
            }
          }
        });

        if (this.activeSessionHandler && !this.activeSession) {
          // Hand off immediately to waiting scenario
          this.activeSession = session;
          this.activeSessionHandler.onSession(session);
        } else {
          this.sessionQueue.push(session);
          // Auto-close sessions that sit in queue too long (30s)
          setTimeout(() => {
            const idx = this.sessionQueue.indexOf(session);
            if (idx !== -1) {
              this.sessionQueue.splice(idx, 1);
              try { session.close(); } catch (_) {}
            }
          }, 30000);
        }
      });

      // Permanent stream dispatcher
      this.server.on('stream', (stream, headers) => {
        const connHandle = stream._connHandle;
        if (connHandle === undefined || connHandle === null) return;

        const data = this.sessionData.get(connHandle);
        if (!data) return;

        if (data.onStream) {
          data.onStream(stream, headers);
        } else {
          data.streams.push({ stream, headers });
        }
      });

      const listenAddr = (this.hostname === 'localhost' || this.hostname === '::1') ? '::' : this.hostname;
      await this.server.listen(this.port, listenAddr);
      this.logger.info(`HTTP/3 server listening on ${listenAddr}:${this.port} (UDP, quiche)`);
    } catch (e) {
      this.logger.error(`Failed to start QuicheServer: ${e.message}`);
      throw e;
    }
  }

  abort() {
    this.aborted = true;
    if (this.server) {
      try { this.server.close(); } catch (e) {}
      this.server = null;
    }
    this.sessionQueue = [];
    this.sessionData.clear();
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, `${scenario.description} (using quiche Native Engine)`);

    // PCAP Init
    if (this.pcapFileBase) {
      const { PcapWriter } = require('../pcap-writer');
      const path = require('path');
      const ext = path.extname(this.pcapFileBase) || '.pcap';
      const base = this.pcapFileBase.endsWith(ext) ? this.pcapFileBase.slice(0, -ext.length) : this.pcapFileBase;
      const pcapFilename = this.mergePcap ? this.pcapFileBase : `${base}.${scenario.name}.server${ext}`;
      try {
        this.pcap = new PcapWriter(pcapFilename, { role: 'server', append: this.mergePcap, serverPort: this.port, clientPort: 49152 + Math.floor(Math.random() * 16000) });
      } catch (e) {
        this.logger.error(`Failed to initialize PCAP: ${e.message}`);
        this.pcap = null;
      }
    }

    this.logger.info(`Waiting for QUIC client connection on port ${this.port}...`);
    
    let status = 'PASSED';
    let lastResponse = '';

    const result = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.activeSessionHandler = null;
        this.activeSession = null;
        resolve({ status: 'TIMEOUT', response: 'QUIC connection timed out' });
      }, this.timeout);

      let streamCount = 0;

      const finish = (s, r) => {
        clearTimeout(timer);
        this.activeSessionHandler = null;
        this.activeSession = null;
        resolve({ status: s, response: r });
      };

      const handleSession = (session) => {
        const remoteInfo = session.remoteAddress ? `${session.remoteAddress}:${session.remotePort}` : 'unknown';
        this.logger.info(`HTTP/3 session established (client: ${remoteInfo})`);

        if (this.pcap) {
          session.on('packet', (packet, dir) => { this.pcap.writeUDPPacket(packet, dir === 'out' ? 'sent' : 'received'); });
        }

        const data = this.sessionData.get(session._connHandle);
        
        const processStream = (stream, headers) => {
          streamCount++;
          const method = headers[':method'] || 'GET';
          const path = headers[':path'] || '/';
          this.logger.info(`[quiche-server] Received stream ${streamCount}: ${method} ${path}`);

          // Support scenario-specific H3 handlers
          if (scenario.h3Handler) {
            return scenario.h3Handler(stream, headers, this.logger);
          }

          let body = Buffer.alloc(0);
          if (method === 'POST' || method === 'PUT') {
            let headersSent = false;
            stream.on('data', (chunk) => { 
              body = Buffer.concat([body, chunk]);
              this.logger.received(chunk, `HTTP/3 Request Body Chunk (${method} ${path})`);
              
              try {
                if (!headersSent) {
                  stream.respond({ ':status': '200', 'content-type': 'application/octet-stream' });
                  headersSent = true;
                }
                stream.write(chunk); // immediate echo
                this.logger.sent(chunk, `HTTP/3 Echo Chunk`);
              } catch (_) {}
            });
            stream.on('end', () => {
              try {
                if (!headersSent) {
                  stream.respond({ ':status': '200', 'content-type': 'application/octet-stream' });
                }
                stream.end();
              } catch (_) {}
            });
          } else {
            try {
              stream.respond({ ':status': '200', 'content-type': 'text/plain' });
              const respBody = Buffer.from('OK');
              stream.end(respBody);
              this.logger.sent(respBody, `HTTP/3 Response Body (OK)`);
            } catch (_) {}
          }
          stream.on('error', () => {});
        };

        // Attach handler for future streams
        if (data) data.onStream = processStream;

        // Process already buffered streams
        if (data && data.streams.length > 0) {
          while (data.streams.length > 0) {
            const { stream, headers } = data.streams.shift();
            processStream(stream, headers);
          }
        }

        this.activeSessionHandler = {
          onClose: () => finish('PASSED', `Handled ${streamCount} stream(s) (client: ${remoteInfo})`),
          onError: (e) => finish('ERROR', e.message)
        };
      };

      if (this.sessionQueue.length > 0) {
        this.activeSession = this.sessionQueue.shift();
        const remoteInfo = this.activeSession.remoteAddress ? `${this.activeSession.remoteAddress}:${this.activeSession.remotePort}` : 'unknown';
        if (this.activeSession._isClosed) {
          this.logger.info(`[quiche-server] Picking up ALREADY CLOSED session from queue (client: ${remoteInfo})`);
          finish('PASSED', `Handled buffered session that closed in queue (client: ${remoteInfo})`);
        } else {
          this.logger.info(`[quiche-server] Picking up active session from queue (client: ${remoteInfo})`);
          handleSession(this.activeSession);
        }
      } else {
        this.activeSessionHandler = { onSession: handleSession };
      }
    });

    status = result.status;
    lastResponse = result.response;

    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const verdict = this._computeVerdict(status, expected, lastResponse);
    
    const finalResult = {
      scenario: scenario.name, description: scenario.description,
      category: scenario.category, severity: QUIC_CATEGORY_SEVERITY[scenario.category] || 'medium',
      status, expected, verdict, response: lastResponse || status,
      compliance: null, finding: null, hostDown: false, probe: null,
    };
    finalResult.finding = gradeResult(finalResult, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, scenario.expectedReason || computed.reason, false, finalResult.finding, null);
    
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
    return finalResult;
  }

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    const expectedEffective = expected === 'TIMEOUT' ? 'DROPPED' : expected;
    return effective === expectedEffective ? 'AS EXPECTED' : 'UNEXPECTED';
  }
}

module.exports = { QuicheServer };
