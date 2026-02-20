// HTTP/2 Fuzzing Client — connects to a target HTTP/2 server via TLS+ALPN and runs scenarios
// Mirrors the FuzzerClient interface but uses tls.connect() instead of a raw TCP socket.
const tls = require('tls');
const net = require('net');
const https = require('https');
const { Logger } = require('./logger');
const { sendFIN, sendRST, configureSocket } = require('./tcp-tricks');
const { gradeResult, computeOverallGrade } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { HTTP2_CATEGORY_SEVERITY } = require('./http2-scenarios');

class Http2FuzzerClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.timeout = opts.timeout || 5000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.aborted = false;
  }

  abort() {
    this.aborted = true;
  }

  /**
   * Run a single HTTP/2 scenario against the target.
   * For probe scenarios (action.type === 'probe'), just test connectivity.
   * For normal scenarios, the connection uses TLS+ALPN h2 and sends raw HTTP/2 frames.
   */
  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };

    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    const isProbe = actions.some(a => a.type === 'probe');

    // ── Probe scenarios: just test connectivity ─────────────────────────────
    if (isProbe) {
      return this._runProbeScenario(scenario, actions);
    }

    // ── Normal scenarios: send raw H2 frames ────────────────────────────────
    let socket = null;
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let connectionClosed = false;

    try {
      socket = await this._connectWithOptions(scenario.connectionOptions, scenario.isTcpOnly);
      configureSocket(socket);

      socket.on('data', () => {}); // keep receiving
      socket.on('end', () => {
        connectionClosed = true;
        this.logger.tcpEvent('received', 'FIN');
      });
      socket.on('close', () => { connectionClosed = true; });
      socket.on('error', (err) => {
        if (!connectionClosed) {
          this.logger.error(`Socket error: ${err.message}`);
          connectionClosed = true;
        }
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
            } catch (e) {
              this.logger.error(`Write failed: ${e.message}`);
              status = 'DROPPED';
            }
            break;
          }

          case 'recv': {
            const recvTimeout = action.timeout || this.timeout;
            const data = await this._waitForData(socket, recvTimeout, () => connectionClosed);
            if (data && data.length > 0) {
              this.logger.received(data);
              lastResponse = this._describeH2Response(data);
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

          case 'fin': {
            this.logger.tcpEvent('sent', action.label || 'FIN');
            try { await sendFIN(socket); } catch (_) {}
            break;
          }

          case 'rst': {
            this.logger.tcpEvent('sent', action.label || 'RST');
            sendRST(socket);
            connectionClosed = true;
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
      if (socket && !socket.destroyed) socket.destroy();
    }

    // Health probe after failures
    let hostDown = false;
    let probe = null;
    if (['DROPPED', 'TIMEOUT', 'ERROR'].includes(status)) {
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
    const severity = HTTP2_CATEGORY_SEVERITY[scenario.category] || 'medium';
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

  /**
   * Run a probe scenario — just test whether the connection can be established.
   * Returns CONNECTED or FAILED_CONNECTION as status.
   */
  async _runProbeScenario(scenario, actions) {
    const probeAction = actions.find(a => a.type === 'probe');
    const label = probeAction ? probeAction.label : 'connectivity probe';
    this.logger.info(`Probe: ${label}`);

    let status = 'CONNECTED';
    let lastResponse = '';
    let socket = null;

    try {
      socket = await this._connectWithOptions(scenario.connectionOptions, scenario.isTcpOnly);
      if (scenario.isTcpOnly) {
        lastResponse = `TCP connected to ${this.host}:${this.port}`;
      } else {
        const alpn = socket.alpnProtocol || 'none';
        const tlsVersion = typeof socket.getProtocol === 'function' ? socket.getProtocol() : 'TLS';
        lastResponse = `Connected (${tlsVersion}, ALPN: ${alpn})`;
      }
      this.logger.info(lastResponse);
    } catch (e) {
      status = 'FAILED_CONNECTION';
      lastResponse = e.message;
      this.logger.error(`Probe failed: ${e.message}`);
    } finally {
      if (socket && !socket.destroyed) socket.destroy();
    }

    const expected = scenario.expected;
    const expectedReason = scenario.expectedReason || '';
    const verdict = this._computeVerdict(status, expected);
    const severity = HTTP2_CATEGORY_SEVERITY[scenario.category] || 'info';
    const result = {
      scenario: scenario.name, category: scenario.category, severity,
      status, expected, verdict, hostDown: false, probe: null,
      response: lastResponse,
      compliance: null,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse, verdict, expectedReason, false, result.finding, null);
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
        if (!recheck.tcp.alive) {
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

  /**
   * Connect with optional overrides for TLS options or TCP-only mode.
   * @param {object} connectionOptions - TLS options to merge (e.g. ALPNProtocols, minVersion)
   * @param {boolean} isTcpOnly - if true, use raw TCP instead of TLS
   */
  async _connectWithOptions(connectionOptions, isTcpOnly) {
    const maxRetries = 3;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await this._connectOnceWithOptions(connectionOptions, isTcpOnly);
      } catch (err) {
        if (err.code === 'ECONNREFUSED' && attempt < maxRetries) {
          await this._sleep(300);
          continue;
        }
        throw err;
      }
    }
  }

  _connectOnceWithOptions(connectionOptions, isTcpOnly) {
    if (isTcpOnly) {
      return new Promise((resolve, reject) => {
        const socket = net.createConnection({ host: this.host, port: this.port });
        socket.setTimeout(this.timeout);
        socket.on('connect', () => resolve(socket));
        socket.on('timeout', () => { socket.destroy(); reject(new Error('TCP connection timeout')); });
        socket.on('error', reject);
      });
    }

    return new Promise((resolve, reject) => {
      const defaultOptions = {
        host: this.host,
        port: this.port,
        ALPNProtocols: ['h2'],
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
      };
      // Merge: connectionOptions values override defaults; undefined values are omitted
      const opts = { ...defaultOptions };
      if (connectionOptions) {
        for (const [k, v] of Object.entries(connectionOptions)) {
          if (v === undefined) {
            delete opts[k]; // explicitly missing (e.g. no ALPN)
          } else {
            opts[k] = v;
          }
        }
      }

      const socket = tls.connect(opts);
      socket.on('secureConnect', () => {
        this.logger.info(`TLS connected to ${this.host}:${this.port} (ALPN: ${socket.alpnProtocol || 'none'})`);
        resolve(socket);
      });
      socket.setTimeout(this.timeout);
      socket.on('timeout', () => { socket.destroy(); reject(new Error('Connection timeout')); });
      socket.on('error', reject);
    });
  }

  // Legacy method used internally for normal scenarios
  async _connect() {
    return this._connectWithOptions(null, false);
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

  /**
   * Describe raw HTTP/2 response bytes by parsing frame headers
   */
  _describeH2Response(data) {
    const frameTypeNames = {
      0: 'DATA', 1: 'HEADERS', 2: 'PRIORITY', 3: 'RST_STREAM',
      4: 'SETTINGS', 5: 'PUSH_PROMISE', 6: 'PING', 7: 'GOAWAY',
      8: 'WINDOW_UPDATE', 9: 'CONTINUATION',
    };

    if (data.length < 9) return `Raw H2 data (${data.length} bytes)`;

    const descriptions = [];
    let offset = 0;
    while (offset + 9 <= data.length) {
      const frameLen = data.readUIntBE(offset, 3);
      const frameType = data[offset + 3];
      const typeName = frameTypeNames[frameType] || `type=0x${frameType.toString(16).padStart(2, '0')}`;
      descriptions.push(`H2 ${typeName}(${frameLen}B)`);
      offset += 9 + frameLen;
      if (descriptions.length >= 5) { descriptions.push('...'); break; }
    }
    return descriptions.join(' + ') || `Raw H2 data (${data.length} bytes)`;
  }

  _computeVerdict(status, expected) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    // Probe statuses
    if (expected === 'CONNECTED') return status === 'CONNECTED' ? 'AS EXPECTED' : 'UNEXPECTED';
    if (expected === 'FAILED_CONNECTION') return status === 'FAILED_CONNECTION' ? 'AS EXPECTED' : 'UNEXPECTED';
    // Normal statuses
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    return effective === expected ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  _checkTCPAlive(host, port, timeout = 2000) {
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

  close() {}
}

module.exports = { Http2FuzzerClient };
