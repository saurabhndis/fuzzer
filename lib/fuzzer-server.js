// Fuzzing Server Engine — accepts connections and runs server-side scenarios
const net = require('net');
const { Logger } = require('./logger');
const { PcapWriter } = require('./pcap-writer');
const { sendFIN, sendRST, configureSocket } = require('./tcp-tricks');
const { parseRecords } = require('./record');
const { gradeResult, computeOverallGrade } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { generateServerCert } = require('./cert-gen');

class FuzzerServer {
  constructor(opts = {}) {
    this.port = opts.port || 4433;
    this.hostname = opts.hostname || 'localhost';
    this.timeout = opts.timeout || 10000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.pcapFileBase = opts.pcapFile || null;
    this.mergePcap = opts.mergePcap || false;
    this.pcap = null;
    this.dut = opts.dut || null;
    this.server = null;
    this.aborted = false;
    this.results = [];

    // Generate or use provided certificate
    if (opts.cert) {
      this.certDER = opts.cert;
      this.certInfo = opts.certInfo || {};
    } else {
      const generated = generateServerCert(this.hostname);
      this.certDER = generated.certDER;
      this.certInfo = generated;
    }
  }

  abort() {
    this.aborted = true;
    if (this.server) {
      this.server.close();
    }
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
  }

  close() {
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
  }

  getCertInfo() {
    return {
      hostname: this.hostname,
      fingerprint: this.certInfo.fingerprint || 'N/A',
      certSize: this.certDER.length,
    };
  }

  /**
   * Run a single server-side scenario: listen, accept one connection, execute actions
   */
  runScenario(scenario) {
    if (scenario.side === 'client') {
      this.logger.error(`Skipping client-side scenario "${scenario.name}" in server mode`);
      return Promise.resolve({ scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Client-side scenario cannot run in server mode' });
    }
    return new Promise((resolve) => {
      this.logger.scenario(scenario.name, scenario.description);

    // Initialize per-scenario PCAP if a base filename was provided
    if (this.pcapFileBase) {
      const path = require('path');
      const ext = path.extname(this.pcapFileBase) || '.pcap';
      const base = this.pcapFileBase.toLowerCase().endsWith(ext.toLowerCase()) 
        ? this.pcapFileBase.slice(0, -ext.length) 
        : this.pcapFileBase;
      
      const pcapFilename = this.mergePcap 
        ? this.pcapFileBase 
        : `${base}.${scenario.name}.server${ext}`;

      try {
        this.pcap = new PcapWriter(pcapFilename, {
          role: 'server',
          append: this.mergePcap,
          serverPort: this.port,
          clientPort: 49152 + Math.floor(Math.random() * 16000),
        });
      } catch (e) {
        this.logger.error(`Failed to initialize PCAP: ${e.message}`);
        this.pcap = null;
      }
    }

      const pcap = this.pcap;
      let resolved = false;
      const resolveOnce = (result) => {
        if (resolved) return;
        resolved = true;
        if (this.server) {
          const srv = this.server;
          this.server = null;
          srv.close(() => resolve(result));
          setTimeout(() => resolve(result), 500);
        } else {
          resolve(result);
        }
      };

      let acceptTimer = null;

      this.server = net.createServer({ allowHalfOpen: true }, async (socket) => {
        clearTimeout(acceptTimer);
        configureSocket(socket);
        this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);
        if (pcap) pcap.writeTCPHandshake();

        // Pass server cert and hostname to scenario actions
        const actions = scenario.actions({ serverCert: this.certDER, hostname: this.hostname });
        let connectionClosed = false;
        let recvBuffer = Buffer.alloc(0);
        let lastResponse = '';
        let rawResponse = null;
        let status = 'PASSED';

        socket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
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
                this.logger.error('Cannot send: connection closed');
                status = 'DROPPED';
                break;
              }
              try {
                socket.write(action.data);
                this.logger.sent(action.data, action.label);
                if (pcap) pcap.writeTLSData(action.data, 'sent');
              } catch (e) {
                this.logger.error(`Write failed: ${e.message}`);
                status = 'DROPPED';
              }
              break;
            }

            case 'recv': {
              const recvTimeout = action.timeout || this.timeout;
              const alreadyReceived = recvBuffer;
              recvBuffer = Buffer.alloc(0);
              const dataFromWait = await this._waitForData(socket, recvTimeout, () => connectionClosed);
              const data = Buffer.concat([alreadyReceived, dataFromWait || Buffer.alloc(0)]);
              if (data && data.length > 0) {
                this.logger.received(data);
                if (pcap) pcap.writeTLSData(data, 'received');
                lastResponse = this._describeResponse(data);
                rawResponse = data;
              } else if (connectionClosed) {
                lastResponse = 'Connection closed';
                status = 'DROPPED';
              } else {
                lastResponse = 'Timeout';
                status = 'TIMEOUT';
              }
              break;
            }

            case 'delay': {
              await this._sleep(action.ms);
              break;
            }

            case 'fin': {
              this.logger.tcpEvent('sent', action.label || 'FIN');
              if (pcap) pcap.writeFIN('sent');
              try { await sendFIN(socket); } catch (_) {}
              break;
            }

            case 'rst': {
              this.logger.tcpEvent('sent', action.label || 'RST');
              if (pcap) pcap.writeRST('sent');
              sendRST(socket);
              connectionClosed = true;
              break;
            }
          }

          if (action.type !== 'delay' && action.type !== 'recv') {
            await this._sleep(this.delay);
          }
        }

        if (!socket.destroyed) socket.destroy();

        // Finalize response: if PASSED but response just describes received data, replace with outcome
        if (status === 'PASSED' && lastResponse && /^ClientHello\(/.test(lastResponse)) {
          lastResponse = 'Handshake completed';
        }

        // Response-aware status: alert from client = tls-alert-client
        if (lastResponse && /^Alert\(fatal/i.test(lastResponse)) {
          status = 'tls-alert-client';
        }

        const computed = computeExpected(scenario);
        const expected = scenario.expected || computed.expected;
        const expectedReason = scenario.expectedReason || computed.reason;
        const verdict = this._computeVerdict(status, expected, lastResponse);
        const result = {
          scenario: scenario.name,
          description: scenario.description,
          category: scenario.category,
          status,
          expected,
          verdict,
          response: lastResponse || status,
        };

        // Grade the result
        gradeResult(result, scenario);

        this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason);
        resolveOnce(result);
      });

      // Bind to the specified IP (hostname) for targeted listening
      this.server.listen(this.port, this.hostname, () => {
        this.logger.info(`Fuzzer server listening on ${this.hostname}:${this.port} — waiting for connection...`);
        acceptTimer = setTimeout(() => {
          this.logger.error(`No client connected within 30s — skipping scenario`);
          const computed = computeExpected(scenario);
          resolveOnce({
            scenario: scenario.name,
            description: scenario.description,
            category: scenario.category,
            status: 'TIMEOUT',
            expected: scenario.expected || computed.expected,
            verdict: 'N/A',
            response: 'No client connected (accept timeout)',
          });
        }, 30000);
      });

      this.server.on('error', (err) => {
        this.logger.error(`Server error: ${err.message}`);
        clearTimeout(acceptTimer);
        resolveOnce({ scenario: scenario.name, description: scenario.description, status: 'ERROR', response: err.message });
      });
    });
  }

  /**
   * Run multiple server-side scenarios sequentially (each waits for one connection)
   */
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

  _waitForData(socket, timeout, isClosedFn) {
    return new Promise((resolve) => {
      let buf = Buffer.alloc(0);
      let timer;
      let settled = false;

      const checkClosed = setInterval(() => {
        if (isClosedFn() || socket.destroyed) {
          clearInterval(checkClosed);
          // Wait up to 4s after closure to capture late-arriving alerts
          setTimeout(done, 4000);
        }
      }, 50);

      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearInterval(checkClosed);
        socket.removeListener('data', onData);
        socket.removeListener('end', onEnd);
        socket.removeListener('close', onEnd);
        resolve(buf.length > 0 ? buf : null);
      };

      const onData = (data) => {
        buf = Buffer.concat([buf, data]);
        clearTimeout(timer);
        timer = setTimeout(done, 200);
      };

      const onEnd = () => {
        // TCP FIN received — let checkClosed handle the 4s wait
      };

      socket.on('data', onData);
      socket.on('end', onEnd);
      socket.on('close', onEnd);

      // Overall timeout
      setTimeout(() => {
        if (!settled) done();
      }, timeout);
    });
  }

  _describeResponse(data) {
    const { records } = parseRecords(data);
    if (records.length === 0) return `Raw data (${data.length} bytes)`;
    const { ContentType, HandshakeType, AlertLevel, AlertDescriptionName, CipherSuiteName, VersionName } = require('./constants');

    // Check for alerts first
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
          const vName = VersionName[realVersion] || `0x${realVersion.toString(16)}`;
          return `ServerHello(${vName})`;
        }
        if (hsType === HandshakeType.CLIENT_HELLO && r.payload.length >= 40) {
          const bodyVersion = (r.payload[4] << 8) | r.payload[5];
          const vName = VersionName[bodyVersion] || `0x${bodyVersion.toString(16)}`;
          return `ClientHello(${vName})`;
        }
      }
    }

    // Fallback
    const { describeTLS } = require('./logger');
    return records.map(r => describeTLS(r.raw)).join(' + ');
  }

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';

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

  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }
}

module.exports = { FuzzerServer };
