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
    this.pcapFileBase = opts.pcapFile || null;
    this.mergePcap = opts.mergePcap || false;
    this.pcap = null;
    this.aborted = false;
  }

  abort() {
    this.aborted = true;
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, `${scenario.description} (quiche)`);

    // Initialize per-scenario PCAP if a base filename was provided
    if (this.pcapFileBase) {
      const { PcapWriter } = require('../pcap-writer');
      const path = require('path');
      const ext = path.extname(this.pcapFileBase) || '.pcap';
      const base = this.pcapFileBase.endsWith(ext)
        ? this.pcapFileBase.slice(0, -ext.length)
        : this.pcapFileBase;
      
      const pcapFilename = this.mergePcap 
        ? this.pcapFileBase 
        : `${base}.${scenario.name}.client${ext}`;

      try {
        this.pcap = new PcapWriter(pcapFilename, {
          role: 'client',
          append: this.mergePcap,
          clientPort: 49152 + Math.floor(Math.random() * 16000),
          serverPort: this.port,
        });
      } catch (e) {
        this.logger.error(`Failed to initialize PCAP: ${e.message}`);
        this.pcap = null;
      }
    }

    let status = 'PASSED';
    let lastResponse = '';

    try {
      const session = await this._connect();
      
      if (this.pcap) {
        // TCP handshake is not applicable for QUIC/UDP
      }

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
          let activeStream = null;

          const newStream = () => {
            activeStream = useH3
              ? session.request({ ':method': 'POST', ':path': '/', ':scheme': 'https', ':authority': this.host })
              : session.openStream();
            shimWritten = false;
            shimEnded = false;
            return activeStream;
          };

          const getStream = () => {
            if (activeStream && !shimEnded) return activeStream;
            // Previous stream was ended (e.g. auto-end on 'data' listener) —
            // open a new stream to support multi-request handlers.
            return newStream();
          };

          let shimWritten = false;
          let shimEnded = false;
          // Track wrapped callbacks so removeListener works through the shim
          const listenerMap = new Map();

          // Parse HTTP/1.1 request line to extract method and path for H3 headers
          const parseHttpRequest = (data) => {
            const str = typeof data === 'string' ? data : data.toString();
            const match = str.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/);
            if (match) return { method: match[1], path: match[2] };
            return null;
          };

          const shim = {
            write: (data) => {
              // Only write() opens a new stream if the previous one was ended.
              // This supports multi-request handlers (write→read→write→read).
              if (useH3 && (shimEnded || !activeStream)) {
                // Parse HTTP/1.1 request to set proper H3 pseudo-headers
                const parsed = parseHttpRequest(data);
                const method = parsed ? parsed.method : 'POST';
                const path = parsed ? parsed.path : '/';
                activeStream = session.request({
                  ':method': method, ':path': path,
                  ':scheme': 'https', ':authority': this.host
                });
                shimWritten = false;
                shimEnded = false;
                // For GET/HEAD with no body, end the stream immediately
                if (parsed && (method === 'GET' || method === 'HEAD')) {
                  this.logger.sent(data, `HTTP/3 ${method} ${path}`);
                  shimWritten = true;
                  shimEnded = true;
                  activeStream.end();
                  return true;
                }
              } else if (!activeStream) {
                newStream();
              }
              this.logger.sent(data, `HTTP/3 Data (Stream)`);
              shimWritten = true;
              return activeStream.write(data);
            },
            on: (event, cb) => {
              // Event listeners always attach to the CURRENT stream, never open a new one.
              // This ensures 'data' and 'end' listeners stay on the same stream.
              const s = activeStream || getStream();
              if (event === 'data') {
                // The handler is done writing and waiting for response data.
                // In HTTP/3, the server won't respond until the request stream is
                // half-closed (ended on the write side).  TLS handlers rely on
                // Content-Length / Connection:close, but HTTP/3 needs an explicit end().
                if (shimWritten && !shimEnded) {
                  shimEnded = true;
                  try { s.end(); } catch (_) {}
                }
                let h3Status = '';
                // Capture H3 response status to synthesize HTTP/1.1 headers
                s.on('response', (h) => { h3Status = h[':status'] || '200'; });
                let sentHeaders = false;
                const wrapped = (d) => {
                  this.logger.received(d, `HTTP/3 Data (Stream)`);
                  if (useH3 && !sentHeaders) {
                    // Synthesize HTTP/1.1 response so handlers that parse HTTP headers work
                    const status = h3Status || '200';
                    const header = `HTTP/1.1 ${status} OK\r\nContent-Length: ${d.length}\r\n\r\n`;
                    sentHeaders = true;
                    cb(Buffer.from(header + d.toString()));
                  } else {
                    cb(d);
                  }
                };
                listenerMap.set(cb, { stream: s, event: 'data', wrapped });
                s.on('data', wrapped);
              } else {
                const wrapped = (...args) => cb(...args);
                listenerMap.set(cb, { stream: s, event, wrapped });
                s.on(event, wrapped);
              }
            },
            end: (data) => {
              const s = activeStream || getStream();
              if (data) this.logger.sent(data, `HTTP/3 Data (FIN)`);
              shimEnded = true;
              return s.end(data);
            },
            removeListener: (event, cb) => {
              const entry = listenerMap.get(cb);
              if (entry && entry.stream && entry.stream.removeListener) {
                entry.stream.removeListener(entry.event, entry.wrapped);
                listenerMap.delete(cb);
              } else if (activeStream && activeStream.removeListener) {
                activeStream.removeListener(event, cb);
              }
            },
            destroy: () => {
              if (!activeStream) return;
              if (activeStream.destroy) activeStream.destroy();
              else activeStream.close();
            },
            getProtocol: () => useH3 ? 'HTTP/3' : 'QUIC/Raw'
          };
          const result = await scenario.clientHandler(shim, this.host, this.logger, this.pcap, session);
          
          // Ensure stream is ended if handler used it but didn't end it
          if (activeStream) {
            try { activeStream.end(); } catch (_) {}
          }
          
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
              req.on('data', (d) => { 
                this.logger.received(d, `HTTP/3 Data (Stream ${i})`);
                buf = Buffer.concat([buf, d]); 
              });
              req.on('end', () => resolve({ bytes: buf.length, status: statusCode }));
              req.on('error', () => resolve({ bytes: buf.length, status: statusCode }));
              req.end();
            } else {
              const stream = session.openStream();
              const payload = `GET / HTTP/1.1\r\nHost: ${this.host}\r\nX-Stream: ${i}\r\n\r\n`;
              this.logger.sent(Buffer.from(payload), `QUIC Raw Data (Stream ${i})`);
              stream.end(payload);
              stream.on('data', (d) => { 
                this.logger.received(d, `QUIC Raw Data (Stream ${i})`);
                buf = Buffer.concat([buf, d]); 
              });
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
    } finally {
      if (this.pcap) {
        this.pcap.close();
        this.pcap = null;
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
        const targetHost = this.host;
        const target = this.quiche.connect
          ? `https://${targetHost}:${this.port}`
          : `${targetHost}:${this.port}`;

        const session = connectFn(target, {
          rejectUnauthorized: false,
        });

        if (this.pcap && session.on) {
          session.on('packet', (packet, dir) => {
            this.pcap.writeUDPPacket(packet, dir === 'out' ? 'sent' : 'received');
          });
        }

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
