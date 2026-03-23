// LDAP Fuzzing Client Engine — connects to target and runs LDAP scenarios over raw TCP
// Supports plain LDAP (389), LDAPS (636), and StartTLS upgrade
// Pattern follows lib/fuzzer-client.js

const net = require('net');
const tls = require('tls');
const { Logger } = require('../logger');
const { PcapWriter } = require('../pcap-writer');
const { sendFIN, sendRST, configureSocket } = require('../tcp-tricks');
const { gradeResult, computeOverallGrade } = require('../grader');
const { parseLDAPMessage, parseLDAPMessages } = require('./packet');
const { LDAP_OP, LDAP_OP_NAME, LDAP_RESULT_NAME } = require('./constants');
const { LDAP_CATEGORY_SEVERITY } = require('./scenarios');


class LdapFuzzerClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 389;
    this.timeout = opts.timeout || 5000;
    this.delay = opts.delay || 100;
    this.useTLS = opts.useTLS || false;  // Direct LDAPS on port 636
    this.logger = opts.logger || new Logger(opts);
    this.pcap = opts.pcapFile ? new PcapWriter(opts.pcapFile, {
      role: 'client',
      clientPort: 49152 + Math.floor(Math.random() * 16000),
      serverPort: this.port,
    }) : null;
    this.dut = opts.dut || null;
    this.aborted = false;
  }

  abort() {
    this.aborted = true;
  }

  /**
   * Run a single LDAP scenario against the target
   */
  async runScenario(scenario) {
    if (this.aborted) {
      return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };
    }
    if (scenario.side === 'server') {
      this.logger.error(`Skipping server-side scenario "${scenario.name}" in client mode`);
      return { scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Server-side scenario cannot run in client mode' };
    }

    this.logger.scenario(scenario.name, scenario.description);

    const actions = typeof scenario.actions === 'function'
      ? scenario.actions({ hostname: this.host, host: this.host, port: this.port })
      : scenario.actions;

    if (!actions) {
      this.logger.error(`Scenario "${scenario.name}" actions returned undefined!`);
      return { scenario: scenario.name, description: scenario.description, status: 'ERROR', response: 'No actions defined' };
    }

    let socket = null;
    let recvBuffer = Buffer.alloc(0);
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let connectionClosed = false;
    let hasExplicitConnect = actions.some(a => a.type === 'connect');

    try {
      // Auto-connect unless scenario has explicit connect action
      if (!hasExplicitConnect) {
        socket = await this._connect(this.port, this.useTLS);
        if (this.pcap) this.pcap.writeTCPHandshake();
        configureSocket(socket);
        this._attachListeners(socket, (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); },
          () => { connectionClosed = true; this.logger.tcpEvent('received', 'FIN'); },
          () => { connectionClosed = true; },
          (err) => { if (!connectionClosed) { this.logger.error(`Socket error: ${err.message}`); connectionClosed = true; } }
        );
      }

      // Execute actions
      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {

          case 'connect': {
            // Explicit connect — allows mode: 'plain', 'tls', 'starttls-upgrade'
            const port = action.port || this.port;
            const mode = action.mode || 'plain';

            if (mode === 'starttls-upgrade') {
              // Upgrade existing plain socket to TLS
              if (!socket || socket.destroyed) {
                this.logger.error('Cannot StartTLS upgrade: no active socket');
                status = 'ERROR';
                break;
              }
              this.logger.info(`Upgrading to TLS via StartTLS`);
              try {
                socket = await this._upgradeTLS(socket);
                recvBuffer = Buffer.alloc(0);
                connectionClosed = false;
                this._attachListeners(socket, (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); },
                  () => { connectionClosed = true; },
                  () => { connectionClosed = true; },
                  (err) => { if (!connectionClosed) { this.logger.error(`TLS error: ${err.message}`); connectionClosed = true; } }
                );
              } catch (e) {
                this.logger.error(`StartTLS upgrade failed: ${e.message}`);
                status = 'ERROR';
              }
            } else {
              // New connection
              if (socket && !socket.destroyed) socket.destroy();
              const useTLS = mode === 'tls';
              this.logger.info(`Connecting to ${this.host}:${port} (${useTLS ? 'LDAPS' : 'plain'})`);
              try {
                socket = await this._connect(port, useTLS);
                configureSocket(socket);
                recvBuffer = Buffer.alloc(0);
                connectionClosed = false;
                this._attachListeners(socket, (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); },
                  () => { connectionClosed = true; },
                  () => { connectionClosed = true; },
                  (err) => { if (!connectionClosed) { this.logger.error(`Socket error: ${err.message}`); connectionClosed = true; } }
                );
              } catch (e) {
                this.logger.error(`Connect failed: ${e.message}`);
                status = 'ERROR';
              }
            }
            break;
          }

          case 'send': {
            if (connectionClosed || !socket || socket.destroyed) {
              this.logger.error('Cannot send: connection closed');
              status = 'DROPPED';
              break;
            }
            try {
              socket.write(action.data);
              this.logger.sent(action.data, action.label);
              if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
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
            // If data already buffered, use short timeout to check for trailing data
            const waitTimeout = alreadyReceived.length > 0 ? Math.min(recvTimeout, 300) : recvTimeout;
            const dataFromWait = await this._waitForData(socket, waitTimeout, () => connectionClosed);
            const data = Buffer.concat([alreadyReceived, dataFromWait || Buffer.alloc(0)]);

            if (data && data.length > 0) {
              lastResponse = this._describeLdapResponse(data);
              this.logger.received(data, lastResponse);
              if (this.pcap) this.pcap.writeTLSData(data, 'received');
              rawResponse = data;
            } else if (connectionClosed) {
              lastResponse = 'Connection closed';
              rawResponse = null;
              status = 'DROPPED';
            } else {
              lastResponse = 'Timeout (no response)';
              rawResponse = null;
              status = 'TIMEOUT';
            }
            break;
          }

          case 'delay': {
            await this._sleep(action.ms);
            break;
          }

          case 'close': {
            if (socket && !socket.destroyed) {
              this.logger.tcpEvent('sent', action.label || 'Close');
              socket.destroy();
              connectionClosed = true;
            }
            break;
          }

          case 'fin': {
            this.logger.tcpEvent('sent', action.label || 'FIN');
            if (this.pcap) this.pcap.writeFIN('sent');
            try {
              await sendFIN(socket);
            } catch (_) {}
            break;
          }

          case 'rst': {
            this.logger.tcpEvent('sent', action.label || 'RST');
            if (this.pcap) this.pcap.writeRST('sent');
            sendRST(socket);
            connectionClosed = true;
            break;
          }
        }

        // Small delay between actions (except delay/recv actions)
        if (action.type !== 'delay' && action.type !== 'recv') {
          await this._sleep(this.delay);
        }
      }

    } catch (e) {
      this.logger.error(`Scenario failed: ` + (e.stack || e));
      status = 'ERROR';
      lastResponse = e.message;
    } finally {
      if (socket && !socket.destroyed) {
        socket.destroy();
      }
    }

    // Health probes after failure
    let hostDown = false;
    let probe = null;
    if (['DROPPED', 'TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host);
      hostDown = !probe.tcp.alive;
      if (hostDown) {
        this.logger.hostDown(this.host, this.port, scenario.name);
      }
      this.logger.healthProbe(this.host, this.port, probe);
    }

    // LDAP response-aware status refinement
    if (lastResponse) {
      if (/protocolError|unwillingToPerform|operationsError/i.test(lastResponse)) {
        // Server explicitly rejected — this is a proper response
        if (status === 'PASSED') status = 'ldap-error-response';
      }
    }

    const expected = scenario.expected || 'PASSED';
    const expectedReason = scenario.expectedReason || '';
    const verdict = this._computeVerdict(status, expected, lastResponse);

    const severity = LDAP_CATEGORY_SEVERITY[scenario.category] || 'low';
    const result = {
      scenario: scenario.name,
      description: scenario.description,
      category: scenario.category,
      severity,
      status,
      expected,
      verdict,
      hostDown,
      probe,
      response: lastResponse || status,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding);
    return result;
  }

  /**
   * Run multiple scenarios sequentially with host health checks
   */
  async runScenarios(scenarios) {
    const results = [];
    let hostWentDown = false;

    for (const scenario of scenarios) {
      if (this.aborted) break;

      if (hostWentDown) {
        this.logger.info(`Re-checking ${this.host}:${this.port} before next scenario...`);
        const recheck = await this._runHealthProbes(this.host);
        this.logger.healthProbe(this.host, this.port, recheck);
        if (!recheck.tcp.alive) {
          this.logger.hostDown(this.host, this.port, 'still unreachable — stopping batch');
          break;
        }
        this.logger.info(`Host is back up — continuing`);
        hostWentDown = false;
      }

      const result = await this.runScenario(scenario);
      results.push(result);

      if (result.hostDown) {
        hostWentDown = true;
      }

      await this._sleep(500); // pause between scenarios
    }

    const report = computeOverallGrade(results);
    this.logger.summary(results, report);
    return { results, report };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  //  Connection helpers
  // ─────────────────────────────────────────────────────────────────────────────

  async _connect(port, useTLS = false) {
    const maxRetries = 10;
    const retryDelay = 300;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await this._connectOnce(port || this.port, useTLS);
      } catch (err) {
        if ((err.code === 'ECONNREFUSED' || err.message.includes('ECONNREFUSED')) && attempt < maxRetries) {
          await this._sleep(retryDelay);
          continue;
        }
        throw err;
      }
    }
  }

  _connectOnce(port, useTLS = false) {
    return new Promise((resolve, reject) => {
      const connectOpts = {
        host: this.host,
        port: port,
        allowHalfOpen: true,
      };

      let socket;
      if (useTLS) {
        // LDAPS — direct TLS connection
        socket = tls.connect({
          ...connectOpts,
          rejectUnauthorized: false, // Accept self-signed certs in fuzzing
        }, () => {
          this.logger.info(`LDAPS connected to ${this.host}:${port}`);
          resolve(socket);
        });
      } else {
        // Plain LDAP
        socket = net.createConnection(connectOpts, () => {
          this.logger.info(`Connected to ${this.host}:${port}`);
          resolve(socket);
        });
      }

      socket.setTimeout(this.timeout);
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('Connection timeout'));
      });
      socket.on('error', (err) => {
        reject(err);
      });
    });
  }

  /**
   * Upgrade an existing plain TCP socket to TLS (for StartTLS)
   */
  _upgradeTLS(plainSocket) {
    return new Promise((resolve, reject) => {
      const tlsSocket = tls.connect({
        socket: plainSocket,
        rejectUnauthorized: false,
      }, () => {
        this.logger.info('TLS upgrade successful (StartTLS)');
        resolve(tlsSocket);
      });
      tlsSocket.on('error', (err) => {
        reject(err);
      });
      // Timeout for TLS handshake
      const timer = setTimeout(() => {
        reject(new Error('TLS upgrade timeout'));
      }, this.timeout);
      tlsSocket.once('secureConnect', () => clearTimeout(timer));
    });
  }

  /**
   * Attach event listeners to socket
   */
  _attachListeners(socket, onData, onEnd, onClose, onError) {
    socket.removeAllListeners('data');
    socket.removeAllListeners('end');
    socket.removeAllListeners('close');
    socket.removeAllListeners('error');
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('close', onClose);
    socket.on('error', onError);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  //  Data reception
  // ─────────────────────────────────────────────────────────────────────────────

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
        socket.removeListener('end', onEnd);
        socket.removeListener('close', onEnd);
        resolve(buf.length > 0 ? buf : null);
      };

      const onData = (data) => {
        buf = Buffer.concat([buf, data]);
        clearTimeout(timer);
        timer = setTimeout(done, 150);
      };

      const onEnd = () => {
        clearTimeout(timer);
        timer = setTimeout(done, 100);
      };

      socket.on('data', onData);
      socket.on('end', onEnd);
      socket.on('close', onEnd);

      timer = setTimeout(() => {
        done();
      }, timeout);
    });
  }

  _waitForClose(socket, timeout) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), timeout);
      socket.once('close', () => { clearTimeout(timer); resolve(true); });
      socket.once('end', () => { clearTimeout(timer); resolve(true); });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  //  LDAP response description
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Parse LDAP response data and return human-readable description
   * e.g. "BindResponse(success)", "SearchResultDone(noSuchObject)"
   */
  _describeLdapResponse(data) {
    if (!data || data.length === 0) return 'Empty response';

    try {
      const parsed = parseLDAPMessages(data);
      const messages = parsed.messages || parsed;
      if (!messages || messages.length === 0) {
        return `Raw data (${data.length} bytes)`;
      }

      const parts = [];
      for (const msg of messages) {
        const opName = LDAP_OP_NAME[msg.protocolOp] || `Unknown(0x${msg.protocolOp.toString(16)})`;
        if (msg.resultCode !== undefined && msg.resultCode !== null) {
          const resultName = LDAP_RESULT_NAME[msg.resultCode] || `code=${msg.resultCode}`;
          let desc = `${opName}(${resultName})`;
          if (msg.diagnosticMessage) {
            desc += ` "${msg.diagnosticMessage}"`;
          }
          parts.push(desc);
        } else {
          // SearchResultEntry, etc. — no result code
          if (msg.matchedDN) {
            parts.push(`${opName}(dn="${msg.matchedDN}")`);
          } else {
            parts.push(opName);
          }
        }
      }
      return parts.join(' + ');
    } catch (e) {
      return `Parse error (${data.length} bytes): ${e.message}`;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  //  Verdict computation
  // ─────────────────────────────────────────────────────────────────────────────

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';

    // LDAP error response is still a valid server behavior
    if (status === 'ldap-error-response') return 'AS EXPECTED';

    // If server sent a coherent LDAP response, that's a proper reaction
    if (response) {
      if (/Response\(|ResultDone\(/i.test(response)) return 'AS EXPECTED';
    }

    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    return effective === expected ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  // ─────────────────────────────────────────────────────────────────────────────
  //  Health probes
  // ─────────────────────────────────────────────────────────────────────────────

  async _runHealthProbes(host) {
    const { execFile } = require('child_process');
    const start = Date.now();
    return new Promise((resolve) => {
      execFile('ping', ['-c', '1', '-W', '2', host], { timeout: 5000 }, (err) => {
        const latency = Date.now() - start;
        if (err) {
          const result = { alive: false, error: 'ping failed' };
          resolve({ tcp: result, https: result });
        } else {
          const result = { alive: true, latency };
          resolve({ tcp: result, https: result });
        }
      });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  //  Utilities
  // ─────────────────────────────────────────────────────────────────────────────

  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  close() {
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
  }
}


module.exports = { LdapFuzzerClient };
