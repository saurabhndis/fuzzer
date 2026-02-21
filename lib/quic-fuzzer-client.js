// QUIC Fuzzing Client — connects to a target QUIC server via UDP and runs scenarios
const dgram = require('dgram');
const net = require('net');
const https = require('https');
const { Logger } = require('./logger');
const { gradeResult, computeOverallGrade } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { QUIC_CATEGORY_SEVERITY } = require('./quic-scenarios');

class QuicFuzzerClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.timeout = opts.timeout || 5000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.aborted = false;
    this.socket = null;
  }

  abort() {
    this.aborted = true;
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let receivedAny = false;

    try {
      this.socket = dgram.createSocket('udp4');
      
      const recvBuffer = [];
      this.socket.on('message', (msg, rinfo) => {
        receivedAny = true;
        recvBuffer.push(msg);
        this.logger.received(msg, `UDP from ${rinfo.address}:${rinfo.port}`);
      });

      this.socket.on('error', (err) => {
        this.logger.error(`Socket error: ${err.message}`);
      });

      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'send': {
            try {
              await this._sendUDP(action.data);
              this.logger.sent(action.data, action.label);
            } catch (e) {
              this.logger.error(`UDP send failed: ${e.message}`);
              status = 'ERROR';
            }
            break;
          }

          case 'recv': {
            const recvTimeout = action.timeout || this.timeout;
            const data = await this._waitForUDP(recvBuffer, recvTimeout);
            if (data) {
              lastResponse = `QUIC response (${data.length} bytes)`;
              rawResponse = data;
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

    } catch (e) {
      this.logger.error(`Scenario failed: ${e.message}`);
      status = 'ERROR';
      lastResponse = e.message;
    } finally {
      if (this.socket) {
        this.socket.close();
        this.socket = null;
      }
    }

    // UDP doesn't have "DROPPED" (connection closed) in the same way, 
    // but if we got nothing and it's not a success, we'll call it TIMEOUT/DROPPED
    if (status === 'PASSED' && !receivedAny) {
        // Many fuzz scenarios expect the server to drop the packet silently
        status = 'TIMEOUT'; 
    }

    // Health probe after failures (QUIC uses UDP, but we check TCP/HTTPS as baseline)
    let hostDown = false;
    let probe = null;
    if (['TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host, this.port);
      hostDown = !probe.tcp.alive;
      if (hostDown) this.logger.hostDown(this.host, this.port, scenario.name);
      this.logger.healthProbe(this.host, this.port, probe);
    }

    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    const verdict = this._computeVerdict(status, expected);
    const severity = QUIC_CATEGORY_SEVERITY[scenario.category] || 'medium';
    
    const result = {
      scenario: scenario.name, category: scenario.category, severity,
      status, expected, verdict, hostDown, probe,
      response: lastResponse || status,
      compliance: null,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding, null);
    return result;
  }

  async runScenarios(scenarios) {
    const results = [];
    let hostWentDown = false;

    for (const scenario of scenarios) {
      if (this.aborted) break;

      if (hostWentDown) {
        this.logger.info(`Re-checking ${this.host}:${this.port} before next scenario...`);
        const recheck = await this._runHealthProbes(this.host, this.port);
        this.logger.healthProbe(this.host, this.port, recheck);
        if (recheck.tcp.alive) {
          this.logger.info('Host is back up — continuing');
          hostWentDown = false;
        }
      }

      const result = await this.runScenario(scenario);
      results.push(result);
      if (result.hostDown) hostWentDown = true;
      await this._sleep(500);
    }

    const report = computeOverallGrade(results);
    this.logger.summary(results, report);
    return { results, report };
  }

  _sendUDP(data) {
    return new Promise((resolve, reject) => {
      this.socket.send(data, this.port, this.host, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  _waitForUDP(recvBuffer, timeout) {
    return new Promise((resolve) => {
      if (recvBuffer.length > 0) return resolve(recvBuffer.shift());
      
      const timer = setTimeout(() => {
        this.socket.removeListener('message', onMsg);
        resolve(null);
      }, timeout);

      const onMsg = (msg) => {
        clearTimeout(timer);
        this.socket.removeListener('message', onMsg);
        resolve(msg);
      };

      this.socket.on('message', onMsg);
    });
  }

  _computeVerdict(status, expected) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    // For UDP, we often treat TIMEOUT as DROPPED (server ignored)
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    const expectedEffective = expected === 'TIMEOUT' ? 'DROPPED' : expected;
    return effective === expectedEffective ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  // Health probes use TCP/HTTPS as baseline
  _checkTCPAlive(host, port, timeout = 2000) {
    const net = require('net');
    const start = Date.now();
    return new Promise((resolve) => {
      const probe = net.createConnection({ host, port }, () => {
        probe.destroy();
        resolve({ alive: true, latency: Date.now() - start });
      });
      probe.setTimeout(timeout);
      probe.on('timeout', () => { probe.destroy(); resolve({ alive: false, error: 'timeout' }); });
      probe.on('error', (err) => { probe.destroy(); resolve({ alive: false, error: err.code || err.message }); });
    });
  }

  _checkHTTPSAlive(host, port, timeout = 3000) {
    const https = require('https');
    const start = Date.now();
    return new Promise((resolve) => {
      const req = https.request({
        hostname: host, port, path: '/', method: 'HEAD', timeout,
        rejectUnauthorized: false,
      }, (res) => {
        const latency = Date.now() - start;
        const tlsSocket = res.socket;
        res.resume();
        resolve({
          alive: true, latency,
          statusCode: res.statusCode,
          tlsVersion: tlsSocket.getProtocol ? tlsSocket.getProtocol() : 'unknown',
          cipher: tlsSocket.getCipher ? (tlsSocket.getCipher() || {}).name : 'unknown',
        });
      });
      req.setTimeout(timeout, () => { req.destroy(); resolve({ alive: false, error: 'timeout' }); });
      req.on('error', (err) => resolve({ alive: false, error: err.code || err.message }));
      req.end();
    });
  }

  async _runHealthProbes(host, port) {
    const [tcp, httpsProbe] = await Promise.all([
      this._checkTCPAlive(host, port),
      this._checkHTTPSAlive(host, port),
    ]);
    return { tcp, https: httpsProbe };
  }

  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }
}

module.exports = { QuicFuzzerClient };
