// QUIC Fuzzing Server — listens on UDP for QUIC client connections and runs
// server-side scenarios to fuzz client implementations.
// Supports two scenario patterns:
//   1. serverHandler(rinfo, sendFn, log) — direct control (like HTTP/2 AJ)
//   2. actions() — sequential send/recv actions via UDP (like existing QD/QE/QF server scenarios)
const dgram = require('dgram');
const { Logger } = require('./logger');
const { gradeResult } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { QUIC_CATEGORY_SEVERITY } = require('./quic-scenarios');

class QuicFuzzerServer {
  constructor(opts = {}) {
    this.port = opts.port || 443;
    this.hostname = opts.hostname || 'localhost';
    this.timeout = opts.timeout || 10000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.aborted = false;
    this.socket = null;
    this._stopResolve = null;
  }

  async start() {
    if (this.socket) return;

    this.socket = dgram.createSocket('udp4');

    this.socket.on('error', (err) => {
      this.logger.error(`QUIC server socket error: ${err.message}`);
    });

    await new Promise((resolve, reject) => {
      this.socket.bind(this.port, '0.0.0.0', () => {
        this.logger.info(`QUIC server listening on 0.0.0.0:${this.port} (UDP)`);
        resolve();
      });
      this.socket.once('error', reject);
    });
  }

  abort() {
    this.aborted = true;
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    if (this._stopResolve) {
      this._stopResolve();
      this._stopResolve = null;
    }
  }

  close() {
    this.abort();
  }

  waitForStop() {
    return new Promise((resolve) => {
      if (this.aborted) return resolve();
      this._stopResolve = resolve;
    });
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };
    if (scenario.side === 'client') {
      this.logger.error(`Skipping client-side scenario "${scenario.name}" in server mode`);
      return { scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Client-side scenario cannot run in server mode' };
    }
    if (!this.socket) await this.start();

    this.logger.scenario(scenario.name, scenario.description);
    this.logger.info(`Waiting for QUIC client packet on port ${this.port}...`);

    if (typeof scenario.serverHandler === 'function') {
      return this._runHandlerScenario(scenario);
    }
    return this._runActionsScenario(scenario);
  }

  // serverHandler(rinfo, sendFn, log) pattern — direct control
  _runHandlerScenario(scenario) {
    return new Promise((resolve) => {
      const scenarioTimeout = setTimeout(() => {
        if (!this.socket) return resolve(this._buildResult(scenario, 'TIMEOUT', 'Socket closed'));
        this.socket.removeListener('message', onMessage);
        this.logger.error(`Scenario "${scenario.name}" timed out — no client packet received.`);
        resolve(this._buildResult(scenario, 'TIMEOUT', 'No client packet within 60s'));
      }, 60000);

      const onMessage = (msg, rinfo) => {
        clearTimeout(scenarioTimeout);
        this.socket.removeListener('message', onMessage);

        this.logger.info(`QUIC client packet from ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
        this.logger.received(msg, `UDP from ${rinfo.address}:${rinfo.port}`);

        const sendFn = (data, label) => {
          return new Promise((res, rej) => {
            if (!this.socket) return rej(new Error('Socket closed'));
            this.socket.send(data, rinfo.port, rinfo.address, (err) => {
              if (err) {
                this.logger.error(`UDP send failed: ${err.message}`);
                rej(err);
              } else {
                this.logger.sent(data, label || `UDP to ${rinfo.address}:${rinfo.port}`);
                res();
              }
            });
          });
        };

        const log = (msg) => this.logger.info(msg);

        try {
          const handlerResult = scenario.serverHandler(rinfo, sendFn, log, msg);
          // Support async handlers
          const finish = () => {
            this.logger.result(
              scenario.name, 'PASSED', 'Server handler executed', 'AS EXPECTED',
              scenario.expectedReason || '', false, 'pass', null
            );
            resolve(this._buildResult(scenario, 'PASSED', `Handler executed (client: ${rinfo.address}:${rinfo.port})`));
          };
          if (handlerResult && typeof handlerResult.then === 'function') {
            handlerResult.then(finish).catch((e) => {
              this.logger.error(`Scenario handler error: ${e.message}`);
              resolve(this._buildResult(scenario, 'ERROR', e.message));
            });
          } else {
            finish();
          }
        } catch (e) {
          this.logger.error(`Scenario handler error: ${e.message}`);
          resolve(this._buildResult(scenario, 'ERROR', e.message));
        }
      };

      this.socket.on('message', onMessage);
    });
  }

  // actions() pattern — sequential send/recv via UDP
  _runActionsScenario(scenario) {
    return new Promise((resolve) => {
      const scenarioTimeout = setTimeout(() => {
        if (!this.socket) return resolve(this._buildResult(scenario, 'TIMEOUT', 'Socket closed'));
        this.socket.removeListener('message', onFirstMessage);
        this.logger.error(`Scenario "${scenario.name}" timed out — no client packet received.`);
        resolve(this._buildResult(scenario, 'TIMEOUT', 'No client packet within 30s'));
      }, 30000);

      const onFirstMessage = async (msg, rinfo) => {
        clearTimeout(scenarioTimeout);
        this.socket.removeListener('message', onFirstMessage);

        this.logger.info(`QUIC client packet from ${rinfo.address}:${rinfo.port} (${msg.length} bytes)`);
        this.logger.received(msg, `UDP from ${rinfo.address}:${rinfo.port}`);

        const actions = scenario.actions({ serverCert: null, hostname: this.hostname });
        let lastResponse = '';
        let status = 'PASSED';

        for (const action of actions) {
          if (this.aborted) { status = 'ABORTED'; break; }

          switch (action.type) {
            case 'send': {
              try {
                await this._sendUDP(action.data, rinfo.port, rinfo.address);
                this.logger.sent(action.data, action.label);
              } catch (e) {
                this.logger.error(`UDP send failed: ${e.message}`);
                status = 'ERROR';
              }
              break;
            }

            case 'recv': {
              const data = await this._waitForUDP(action.timeout || this.timeout);
              if (data) {
                lastResponse = `QUIC response (${data.msg.length} bytes)`;
                this.logger.received(data.msg, `UDP from ${data.rinfo.address}:${data.rinfo.port}`);
              } else {
                lastResponse = 'No UDP response (timeout)';
                status = 'TIMEOUT';
              }
              break;
            }

            case 'delay': {
              await this._sleep(action.ms);
              break;
            }
          }

          if (action.type !== 'delay' && action.type !== 'recv') {
            await this._sleep(this.delay);
          }
        }

        resolve(this._buildResult(scenario, status, lastResponse || status));
      };

      this.socket.on('message', onFirstMessage);
    });
  }

  _sendUDP(data, port, address) {
    return new Promise((resolve, reject) => {
      if (!this.socket) return reject(new Error('Socket closed'));
      this.socket.send(data, port, address, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  _waitForUDP(timeout) {
    return new Promise((resolve) => {
      if (!this.socket) return resolve(null);
      const timer = setTimeout(() => {
        if (this.socket) this.socket.removeListener('message', onMsg);
        resolve(null);
      }, timeout);

      const onMsg = (msg, rinfo) => {
        clearTimeout(timer);
        if (this.socket) this.socket.removeListener('message', onMsg);
        resolve({ msg, rinfo });
      };

      this.socket.on('message', onMsg);
    });
  }

  _buildResult(scenario, status, response) {
    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    const verdict = this._computeVerdict(status, expected);
    const severity = QUIC_CATEGORY_SEVERITY[scenario.category] || 'medium';

    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category, severity,
      status, expected, verdict,
      response: response || status,
      compliance: null, finding: null, hostDown: false, probe: null,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, response || 'No response', verdict, expectedReason, false, result.finding, null);
    return result;
  }

  _computeVerdict(status, expected) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    const expectedEffective = expected === 'TIMEOUT' ? 'DROPPED' : expected;
    return effective === expectedEffective ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = { QuicFuzzerServer };
