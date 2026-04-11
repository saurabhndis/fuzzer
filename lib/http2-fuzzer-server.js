// HTTP/2 Fuzzing Server — starts a real HTTP/2 server that clients can fuzz against,
// or acts as a malicious server to fuzz connecting HTTP/2 clients (AJ scenarios).
const http2 = require('http2');
const tls = require('tls');
const { Logger } = require('./logger');
const { generateServerCert } = require('./cert-gen');

/**
 * Convert a DER-encoded certificate buffer to PEM format
 */
function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = (b64.match(/.{1,64}/g) || []).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

class Http2FuzzerServer {
  constructor(opts = {}) {
    this.port = opts.port || 4433;
    this.hostname = opts.hostname || 'localhost';
    this.logger = opts.logger || new Logger(opts);
    this.dut = opts.dut || null;
    this.server = null;
    this.aborted = false;
    this._stopResolve = null;

    const certInfo = generateServerCert(this.hostname);
    this.certPEM = derToPem(certInfo.certDER);
    this.privateKeyPEM = certInfo.privateKeyPEM;
    this.fingerprint = certInfo.fingerprint;
    this._scenarioActive = false;
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
    this.server = http2.createServer({
      allowHTTP1: true,
    });

    this.server.on('error', (err) => {
      this.logger.error(`HTTP/2 server error: ${err.message}`);
    });

    this.server.on('connection', (socket) => {
      this._rawSocket = socket;
    });

    this.server.on('session', (session) => {
      if (this._rawSocket) {
        session._rawSocket = this._rawSocket;
        this._rawSocket = null;
      }
      const remoteAddr = session.socket ? session.socket.remoteAddress : 'unknown';
      this.logger.info(`HTTP/2 session from ${remoteAddr}`);

      session.on('error', (err) => {
        this.logger.error(`Session error from ${remoteAddr}: ${err.message}`);
      });

      session.on('close', () => {
        this.logger.info(`Session closed from ${remoteAddr}`);
        if (this._sessionCloseHandler) this._sessionCloseHandler();
      });

      session.on('frameError', (type, code, id) => {
        this.logger.fuzz(`Frame error: type=0x${type.toString(16)} code=${code} stream=${id}`);
      });
    });
// Default handler: when a scenario is active, dispatch to its handler.
// When a scenario is waiting, queue the stream.
// When idle (passive mode), respond 200.
this._pendingStreams = [];
this._streamHandler = null;

this.server.on('stream', (stream, headers) => {
  // 1. If a scenario is waiting for its first stream, give it directly
  if (this._streamHandler) {
    const handler = this._streamHandler;
    this._streamHandler = null;
    handler(stream);
    return;
  }

  // 2. Queue streams that arrive between scenarios (client connected early)
  if (this._waitingForStream) {
    this._pendingStreams.push(stream);
    return;
  }

  // 3. Passive mode default response
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

    this._pendingStreams = [];

    await new Promise((resolve, reject) => {
      this.server.listen(this.port, '::', () => {
        this.logger.info(
          `HTTP/2 server listening on [::]:${this.port} | ` +
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
      return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };
    }
    if (scenario.useRawTLS) {
      return this._runRawTLSScenario(scenario);
    }
    if (scenario.side === 'client') {
      this.logger.error(`Skipping client-side scenario "${scenario.name}" in server mode`);
      return { scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Client-side scenario cannot run in server mode' };
    }

    this.logger.scenario(scenario.name, scenario.description);
    this.logger.info(`Waiting for client to connect on port ${this.port}...`);

    this._waitingForStream = true;

    return new Promise((resolve) => {
      const finish = (result) => {
        this._scenarioActive = false;
        this._waitingForStream = false;
        this._streamHandler = null;
        this._sessionCloseHandler = null;
        resolve(result);
      };

      const handleStream = (stream) => {
        this._scenarioActive = true;
        clearTimeout(timeout);

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
          this.logger.result(
            scenario.name, 'PASSED', 'Server handler executed', 'AS EXPECTED',
            scenario.expectedReason || '', false, 'pass', null
          );
          finish({
            scenario: scenario.name,
            description: scenario.description,
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
          finish({
            scenario: scenario.name,
            description: scenario.description,
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

      const scenarioTimeout = 60000; // 60s wait for client connection

      const timeout = setTimeout(() => {
        this._streamHandler = null;
        this.logger.error(`Scenario "${scenario.name}" timed out — no client connected.`);
        finish({
          scenario: scenario.name,
          description: scenario.description,
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

      // Check if a stream was queued (client connected between scenarios)
      if (this._pendingStreams && this._pendingStreams.length > 0) {
        const queued = this._pendingStreams.shift();
        this.logger.info('Using queued stream from early client connection');
        handleStream(queued);
        return;
      }

      // Register ourselves as the current stream handler
      this._streamHandler = (stream) => { handleStream(stream); };

      // Detect session-close-without-stream (e.g. probe clients that connect
      // TCP but never send an HTTP/2 request).  Finish early instead of
      // waiting the full 60 s timeout.
      this._sessionCloseHandler = () => {
        if (this._streamHandler) {
          clearTimeout(timeout);
          this._streamHandler = null;
          this._sessionCloseHandler = null;
          this.logger.info('Session closed without sending a stream — finishing early');
          finish({
            scenario: scenario.name, description: scenario.description, category: scenario.category,
            severity: 'high', status: 'PASSED', expected: scenario.expected, verdict: 'AS EXPECTED',
            response: 'Client connected and disconnected (no stream — probe-style)',
            compliance: null, finding: 'pass', hostDown: false, probe: null,
          });
        }
      };
    });
  }

  /**
   * Run a scenario using a raw TLS server (bypassing http2.createSecureServer)
   * so that writeRawFrame() can write directly to the TLS socket.
   */
  async _runRawTLSScenario(scenario) {
    this.logger.scenario(scenario.name, scenario.description);
    this.logger.info(`[rawTLS] Starting raw TLS server for scenario "${scenario.name}"`);

    return new Promise((resolve) => {
      let rawServer = null;
      const port = this.port;
      const finish = (result) => {
        this._scenarioActive = false;
        // Restart the main HTTP/2 server on the same port
        this.server.listen(port, '::', () => {
          this.logger.info(`[rawTLS] Main HTTP/2 server restored on [::]:${port}`);
        });
        resolve(result);
      };

      rawServer = net.createServer({});

      rawServer.on('error', (err) => {
        this.logger.error(`[rawTLS] Server error: ${err.message}`);
      });

      const scenarioTimeout = 60000;
      const timeout = setTimeout(() => {
        this.logger.error(`[rawTLS] Scenario "${scenario.name}" timed out — no client connected.`);
        rawServer.close();
        finish({
          scenario: scenario.name,
          description: scenario.description,
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

      rawServer.on('connection', (tlsSocket) => {
        clearTimeout(timeout);
        this._scenarioActive = true;
        this.logger.info(`[rawTLS] Client connected from ${tlsSocket.remoteAddress || 'unknown'}`);

        let buf = Buffer.alloc(0);
        let prefaceReceived = false;
        let streamId = null;

        const HTTP2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');

        tlsSocket.on('data', (chunk) => {
          buf = Buffer.concat([buf, chunk]);

          // Step 1: Read the 24-byte HTTP/2 connection preface
          if (!prefaceReceived) {
            if (buf.length < 24) return;
            const preface = buf.slice(0, 24);
            if (!preface.equals(HTTP2_PREFACE)) {
              this.logger.error('[rawTLS] Invalid HTTP/2 connection preface');
              tlsSocket.destroy();
              rawServer.close();
              finish({
                scenario: scenario.name,
                description: scenario.description,
                category: scenario.category,
                severity: 'high',
                status: 'ERROR',
                expected: scenario.expected,
                verdict: 'N/A',
                response: 'Invalid HTTP/2 connection preface',
                compliance: null,
                finding: 'error',
                hostDown: false,
                probe: null,
              });
              return;
            }
            prefaceReceived = true;
            buf = buf.slice(24);

            // Send server SETTINGS frame (empty, no params)
            const settingsFrame = Buffer.alloc(9);
            settingsFrame.writeUIntBE(0, 0, 3); // length = 0
            settingsFrame[3] = 0x04; // SETTINGS
            settingsFrame[4] = 0x00; // no flags
            settingsFrame.writeUInt32BE(0, 5); // stream 0
            if (!tlsSocket.destroyed) tlsSocket.write(settingsFrame);
          }

          // Step 2: Parse frames looking for SETTINGS and HEADERS
          while (buf.length >= 9) {
            const frameLen = (buf[0] << 16) | (buf[1] << 8) | buf[2];
            const totalLen = 9 + frameLen;
            if (buf.length < totalLen) break;

            const frameType = buf[3];
            const frameFlags = buf[4];
            const frameStreamId = buf.readUInt32BE(5) & 0x7fffffff;

            if (frameType === 0x04) {
              // SETTINGS frame
              if (!(frameFlags & 0x01)) {
                // Not an ACK — send SETTINGS ACK
                const ack = Buffer.alloc(9);
                ack.writeUIntBE(0, 0, 3);
                ack[3] = 0x04; // SETTINGS
                ack[4] = 0x01; // ACK
                ack.writeUInt32BE(0, 5);
                if (!tlsSocket.destroyed) tlsSocket.write(ack);
              }
            } else if (frameType === 0x08) {
              // WINDOW_UPDATE — skip
            } else if (frameType === 0x01) {
              // HEADERS frame — extract stream ID and invoke handler
              streamId = frameStreamId;
              buf = buf.slice(totalLen);

              const mockSession = { _tlsSocket: tlsSocket, socket: tlsSocket };
              const mockStream = {
                id: streamId,
                respond: (headers) => {
                  const status = headers[':status'] || 200;
                  let headerBlock;
                  if (status === 200) {
                    headerBlock = Buffer.from([0x88]); // HPACK indexed :status 200
                  } else {
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
                    const frame = Buffer.alloc(9);
                    frame[3] = 0x00; // DATA
                    frame[4] = 0x01; // END_STREAM
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
                this.logger.result(
                  scenario.name, 'PASSED', 'Server handler executed (rawTLS)', 'AS EXPECTED',
                  scenario.expectedReason || '', false, 'pass', null
                );
                // Give the handler time to write frames before closing
                setTimeout(() => {
                  rawServer.close();
                  finish({
                    scenario: scenario.name,
                    description: scenario.description,
                    category: scenario.category,
                    severity: 'high',
                    status: 'PASSED',
                    expected: scenario.expected,
                    verdict: 'AS EXPECTED',
                    response: 'Handler executed via rawTLS',
                    compliance: null,
                    finding: 'pass',
                    hostDown: false,
                    probe: null,
                  });
                }, 500);
              } catch (e) {
                this.logger.error(`[rawTLS] Scenario handler error: ${e.message}`);
                rawServer.close();
                finish({
                  scenario: scenario.name,
                  description: scenario.description,
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
              return; // Stop processing further data after handler invoked
            }

            buf = buf.slice(totalLen);
          }
        });

        tlsSocket.on('error', (err) => {
          this.logger.info(`[rawTLS] TLS socket error (may be expected): ${err.message}`);
        });
      });

      // Listen on the same port as the main server
      // We temporarily close the main h2 server, start raw TLS, then restore
      this.server.close(() => {
        rawServer.listen(port, '::', () => {
          this.logger.info(`[rawTLS] Raw TLS server listening on [::]:${port}`);
        });
        rawServer.once('error', (err) => {
          this.logger.error(`[rawTLS] Listen error: ${err.message}`);
          clearTimeout(timeout);
          // Restart the main server
          this.server.listen(port, '::', () => {});
          finish({
            scenario: scenario.name,
            description: scenario.description,
            category: scenario.category,
            severity: 'high',
            status: 'ERROR',
            expected: scenario.expected,
            verdict: 'N/A',
            response: `Raw TLS listen error: ${err.message}`,
            compliance: null,
            finding: 'error',
            hostDown: false,
            probe: null,
          });
        });
      });
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
