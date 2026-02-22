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
    this.pcapFile = opts.pcapFile || null;
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
    return new Promise((resolve) => {
      this.logger.scenario(scenario.name, scenario.description);

      const pcap = this.pcapFile ? new PcapWriter(this.pcapFile, {
        srcPort: this.port,
        dstPort: 49152 + Math.floor(Math.random() * 16000),
      }) : null;

      let acceptTimer = null;

      this.server = net.createServer({ allowHalfOpen: true }, async (socket) => {
        clearTimeout(acceptTimer);
        configureSocket(socket);
        this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);
        if (pcap) pcap.writeTCPHandshake();

        // Pass server cert and hostname to scenario actions
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
              const data = await this._waitForData(socket, action.timeout || this.timeout, () => connectionClosed);
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
        if (pcap) pcap.close();

        const computed = computeExpected(scenario);
        const expected = scenario.expected || computed.expected;
        const expectedReason = scenario.expectedReason || computed.reason;
        const verdict = this._computeVerdict(status, expected);
        const result = {
          scenario: scenario.name,
          category: scenario.category,
          status,
          expected,
          verdict,
          response: lastResponse || status,
        };

        // Grade the result
        gradeResult(result, scenario);

        this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason);
        this.server.close();
        resolve(result);
      });

      // Bind to 0.0.0.0 for remote access
      this.server.listen(this.port, '0.0.0.0', () => {
        this.logger.info(`Fuzzer server listening on 0.0.0.0:${this.port} — waiting for connection...`);
        acceptTimer = setTimeout(() => {
          this.logger.error(`No client connected within 30s — skipping scenario`);
          const computed = computeExpected(scenario);
          this.server.close();
          resolve({
            scenario: scenario.name,
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
        resolve({ scenario: scenario.name, status: 'ERROR', response: err.message });
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

  /**
   * TCP connect probe — check if a remote host:port is still accepting connections
   */
  _checkHostAlive(host, port, timeout = 2000) {
    return new Promise((resolve) => {
      const probe = net.createConnection({ host, port }, () => {
        probe.destroy();
        resolve(true);
      });
      probe.setTimeout(timeout);
      probe.on('timeout', () => { probe.destroy(); resolve(false); });
      probe.on('error', () => { probe.destroy(); resolve(false); });
    });
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

  _describeResponse(data) {
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

  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }
}

module.exports = { FuzzerServer };
