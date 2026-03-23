// LDAP Fuzzing Server Engine — runs server-side (LJ) scenarios against connecting clients
// Listens on TCP port, dispatches to scenario serverHandler functions
// Pattern follows lib/quic-fuzzer-server.js

const net = require('net');
const tls = require('tls');
const { Logger } = require('../logger');
const { PcapWriter } = require('../pcap-writer');
const { gradeResult, computeOverallGrade } = require('../grader');
const { parseLDAPMessage } = require('./packet');
const { LDAP_OP, LDAP_OP_NAME, LDAP_RESULT_NAME } = require('./constants');
const { LDAP_CATEGORY_SEVERITY } = require('./scenarios');


class LdapFuzzerServer {
  constructor(opts = {}) {
    this.port = opts.port || 389;
    this.tlsPort = opts.tlsPort || 636;
    this.hostname = opts.hostname || 'localhost';
    this.timeout = opts.timeout || 10000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.pcapFileBase = opts.pcapFile || null;
    this.pcap = null;
    this.aborted = false;
    this._server = null;
    this._tlsServer = null;
    this._stopResolve = null;
    this._tlsContext = null;
  }

  abort() {
    this.aborted = true;
    this.stop();
  }

  /**
   * Start the TCP server on the configured port
   */
  async start() {
    if (this._server) return;

    return new Promise((resolve, reject) => {
      let retries = 0;
      const maxRetries = 30;

      const tryBind = () => {
        this._server = net.createServer({ allowHalfOpen: true });

        this._server.on('error', (err) => {
          if (err.code === 'EADDRINUSE' && retries < maxRetries) {
            retries++;
            this.logger.info(`Port ${this.port} busy, retry ${retries}/${maxRetries}...`);
            this._server.close();
            setTimeout(tryBind, 500);
          } else {
            reject(err);
          }
        });

        this._server.listen(this.port, '0.0.0.0', () => {
          this.logger.info(`LDAP server listening on 0.0.0.0:${this.port} (TCP)`);
          resolve();
        });
      };

      tryBind();
    });
  }

  /**
   * Start LDAPS (TLS) server on port 636
   */
  async startTLS(tlsContext) {
    if (this._tlsServer) return;
    this._tlsContext = tlsContext;

    return new Promise((resolve, reject) => {
      this._tlsServer = tls.createServer({
        key: tlsContext.key,
        cert: tlsContext.cert,
        ...tlsContext,
      });

      this._tlsServer.on('error', (err) => {
        this.logger.error(`LDAPS server error: ${err.message}`);
        reject(err);
      });

      this._tlsServer.listen(this.tlsPort, '0.0.0.0', () => {
        this.logger.info(`LDAPS server listening on 0.0.0.0:${this.tlsPort} (TLS)`);
        resolve();
      });
    });
  }

  /**
   * Stop all servers
   */
  stop() {
    if (this._server) {
      this._server.close();
      this._server = null;
    }
    if (this._tlsServer) {
      this._tlsServer.close();
      this._tlsServer = null;
    }
    if (this.pcap) {
      this.pcap.close();
      this.pcap = null;
    }
  }

  /**
   * Run a single server-side scenario
   */
  async runScenario(scenario) {
    if (this.aborted) {
      return this._buildResult(scenario, 'ABORTED', 'Aborted');
    }
    if (scenario.side !== 'server') {
      this.logger.error(`Skipping client-side scenario "${scenario.name}" in server mode`);
      return this._buildResult(scenario, 'SKIPPED', 'Client-side scenario cannot run in server mode');
    }

    this.logger.scenario(scenario.name, scenario.description);

    // Ensure server is started
    if (!this._server) {
      await this.start();
    }

    // Per-scenario PCAP
    if (this.pcapFileBase) {
      const path = require('path');
      const ext = path.extname(this.pcapFileBase);
      const base = this.pcapFileBase.slice(0, -ext.length || undefined);
      const pcapFile = `${base}.${scenario.name}.server${ext || '.pcap'}`;
      this.pcap = new PcapWriter(pcapFile, {
        role: 'server',
        clientPort: 0,
        serverPort: this.port,
      });
    }

    let result;
    try {
      if (typeof scenario.serverHandler === 'function') {
        result = await this._runHandlerScenario(scenario);
      } else {
        result = this._buildResult(scenario, 'ERROR', 'Server scenario has no serverHandler');
      }
    } catch (e) {
      this.logger.error(`Server scenario error: ${e.stack || e.message}`);
      result = this._buildResult(scenario, 'ERROR', e.message);
    } finally {
      if (this.pcap) {
        this.pcap.close();
        this.pcap = null;
      }
    }

    this.logger.result(scenario.name, result.status, result.response, result.verdict, scenario.expectedReason);
    return result;
  }

  /**
   * Run a scenario that uses serverHandler(socket, log) function
   */
  async _runHandlerScenario(scenario) {
    return new Promise((resolve) => {
      const timeout = scenario.timeout || 60000;
      let resolved = false;

      const done = (status, response) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timer);
        // Remove the one-time connection listener
        this._server.removeListener('connection', onConnection);
        resolve(this._buildResult(scenario, status, response));
      };

      // Timeout if no client connects
      const timer = setTimeout(() => {
        done('TIMEOUT', 'No client connected within timeout');
      }, timeout);

      const log = (msg) => {
        this.logger.info(`[${scenario.name}] ${msg}`);
      };

      const onConnection = (socket) => {
        this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);

        let lastData = null;
        let responseDesc = '';

        socket.on('data', (data) => {
          lastData = data;
          this.logger.received(data);
          if (this.pcap) this.pcap.writeTLSData(data, 'received');
        });

        socket.on('end', () => {
          this.logger.tcpEvent('received', 'FIN');
        });

        socket.on('close', () => {
          // Client disconnected — scenario is done
          if (!resolved) {
            done('PASSED', responseDesc || 'Client disconnected');
          }
        });

        socket.on('error', (err) => {
          this.logger.error(`Client socket error: ${err.message}`);
          if (!resolved) {
            done('PASSED', `Client error: ${err.message}`);
          }
        });

        // Wrap socket.write to log sent data
        const origWrite = socket.write.bind(socket);
        socket.write = (data, ...args) => {
          this.logger.sent(data, scenario.name);
          if (this.pcap) this.pcap.writeTLSData(data, 'sent');
          responseDesc = this._describeLdapData(data);
          return origWrite(data, ...args);
        };

        // Invoke the scenario handler
        try {
          const handlerResult = scenario.serverHandler(socket, log);
          // If handler returns a promise, wait for it
          if (handlerResult && typeof handlerResult.then === 'function') {
            handlerResult
              .then((res) => {
                if (res && typeof res === 'object' && res.status) {
                  done(res.status, res.response || responseDesc);
                }
                // Otherwise, wait for socket close
              })
              .catch((err) => {
                done('ERROR', err.message);
              });
          }
          // For sync handlers, wait for client socket close (handled above)
        } catch (e) {
          done('ERROR', e.message);
        }
      };

      this._server.on('connection', onConnection);
    });
  }

  /**
   * Run multiple server-side scenarios sequentially
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
    this.logger.summary(results, report);
    return { results, report };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  //  Result builder
  // ─────────────────────────────────────────────────────────────────────────────

  _buildResult(scenario, status, response) {
    const expected = scenario.expected || 'PASSED';
    const expectedReason = scenario.expectedReason || '';
    const verdict = this._computeVerdict(status, expected, response);
    const severity = LDAP_CATEGORY_SEVERITY[scenario.category] || 'medium';

    const result = {
      scenario: scenario.name,
      description: scenario.description,
      category: scenario.category,
      severity,
      status,
      expected,
      verdict,
      response,
      compliance: null,
      finding: null,
      hostDown: false,
      probe: null,
    };
    result.finding = gradeResult(result, scenario);
    return result;
  }

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED' || status === 'SKIPPED') return 'N/A';
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    return effective === expected ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  /**
   * Describe LDAP data for logging
   */
  _describeLdapData(data) {
    if (!data || data.length === 0) return 'Empty';
    try {
      const msg = parseLDAPMessage(data);
      if (!msg) return `Raw data (${data.length} bytes)`;
      const opName = LDAP_OP_NAME[msg.protocolOp] || `Op(0x${msg.protocolOp.toString(16)})`;
      if (msg.resultCode !== undefined && msg.resultCode !== null) {
        const resultName = LDAP_RESULT_NAME[msg.resultCode] || `code=${msg.resultCode}`;
        return `${opName}(${resultName})`;
      }
      return opName;
    } catch (e) {
      return `Raw data (${data.length} bytes)`;
    }
  }

  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }
}


module.exports = { LdapFuzzerServer };
