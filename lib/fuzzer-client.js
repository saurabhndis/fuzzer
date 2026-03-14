// Fuzzing Client Engine — connects to target and runs scenarios over raw TCP
const net = require('net');
const https = require('https');
const tls = require('tls');
const { Logger } = require('./logger');
const { PcapWriter } = require('./pcap-writer');
const { sendFIN, sendRST, slowDrip, sendFragmented, configureSocket } = require('./tcp-tricks');
const { parseRecords } = require('./record');
const { gradeResult, computeOverallGrade, CATEGORY_SEVERITY } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { checkProtocolCompliance } = require('./protocol-compliance');

class FuzzerClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.timeout = opts.timeout || 5000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.pcap = opts.pcapFile ? new PcapWriter(opts.pcapFile, {
      role: 'client',
      clientPort: 49152 + Math.floor(Math.random() * 16000),
      serverPort: this.port,
    }) : null;
    this.dut = opts.dut || null;
    this.aborted = false;
    this._healthAgent = new https.Agent({
      keepAlive: true,
      keepAliveMsecs: 500,
      maxSockets: 1,
      timeout: 3000,
      rejectUnauthorized: false,
    });
  }

  abort() {
    this.aborted = true;
  }

  /**
   * Run a single scenario against the target
   */
  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };
    if (scenario.side === 'server') {
      this.logger.error(`Skipping server-side scenario "${scenario.name}" in client mode`);
      return { scenario: scenario.name, status: 'SKIPPED', response: 'Server-side scenario cannot run in client mode' };
    }

    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    let socket = null;
    let recvBuffer = Buffer.alloc(0);
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let connectionClosed = false;
    let hasFuzzAction = false;
    let postFuzzRecvData = null;

    try {
      // Connect
      socket = await this._connect();
      if (this.pcap) this.pcap.writeTCPHandshake();

      configureSocket(socket);

      // Collect received data
      socket.on('data', (data) => {
        recvBuffer = Buffer.concat([recvBuffer, data]);
      });

      socket.on('end', () => {
        connectionClosed = true;
        this.logger.tcpEvent('received', 'FIN');
        if (this.pcap) this.pcap.writeFIN('received');
      });

      socket.on('close', () => {
        connectionClosed = true;
      });

      socket.on('error', (err) => {
        if (!connectionClosed) {
          this.logger.error(`Socket error: ${err.message}`);
          connectionClosed = true;
        }
      });

      // Execute actions
      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'send': {
            if (connectionClosed || socket.destroyed) {
              this.logger.error('Cannot send: connection closed');
              status = 'DROPPED';
              break;
            }
            if ((action.label || '').includes('[FUZZ]') || (action.label || '').includes('[CVE-')) {
              hasFuzzAction = true;
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
            const dataFromWait = await this._waitForData(socket, recvTimeout, () => connectionClosed);
            const data = Buffer.concat([alreadyReceived, dataFromWait || Buffer.alloc(0)]);
            if (data && data.length > 0) {
              this.logger.received(data);
              if (this.pcap) this.pcap.writeTLSData(data, 'received');
              lastResponse = this._describeResponse(data);
              rawResponse = data;
              if (hasFuzzAction) postFuzzRecvData = data;

              // Cleartext alert detection (TLS 1.2 and below)
              const { records } = parseRecords(data);
              const hasCleartextAlert = records.some(r => r.type === 21);
              if (hasCleartextAlert && connectionClosed) {
                status = 'DROPPED';
              }
            } else if (connectionClosed) {
              lastResponse = 'Connection closed';
              rawResponse = null;
              status = 'DROPPED';
              if (hasFuzzAction) postFuzzRecvData = null;
            } else {
              lastResponse = 'Timeout (no response)';
              rawResponse = null;
              status = 'TIMEOUT';
              if (hasFuzzAction) postFuzzRecvData = null;
            }
            break;
          }

          case 'delay': {
            await this._sleep(action.ms);
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

          case 'slowDrip': {
            this.logger.fuzz(action.label || `Slow drip: ${action.data.length} bytes, ${action.bytesPerChunk}B/chunk`);
            if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            try {
              await slowDrip(socket, action.data, action.bytesPerChunk, action.delayMs);
            } catch (e) {
              this.logger.error(`Slow drip failed: ${e.message}`);
              status = 'DROPPED';
            }
            break;
          }

          case 'fragment': {
            this.logger.fuzz(action.label || `Fragmenting ${action.data.length} bytes into ${action.fragments} segments`);
            if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            try {
              await sendFragmented(socket, action.data, action.fragments, action.delayMs);
            } catch (e) {
              this.logger.error(`Fragment send failed: ${e.message}`);
              status = 'DROPPED';
            }
            break;
          }
        }

        // Small delay between actions
        if (action.type !== 'delay' && action.type !== 'recv') {
          await this._sleep(this.delay);
        }
      }

      // TLS 1.3 encrypted alert detection: after a fuzz action, if the server
      // closed the connection and the post-fuzz recv only got ApplicationData
      // records (no ServerHello), the server sent an encrypted fatal alert.
      if (status === 'PASSED' && hasFuzzAction && connectionClosed) {
        if (postFuzzRecvData) {
          const { records: postRecords } = parseRecords(postFuzzRecvData);
          const hasHandshake = postRecords.some(r => r.type === 0x16);
          const hasCleartextAlert = postRecords.some(r => r.type === 0x15);
          if (hasCleartextAlert || (!hasHandshake && postRecords.every(r => r.type === 0x17))) {
            status = 'DROPPED';
            lastResponse = hasCleartextAlert
              ? this._describeResponse(postFuzzRecvData)
              : lastResponse + ' [connection closed]';
          }
        } else {
          status = 'DROPPED';
          lastResponse = 'Connection closed';
        }
      }

    } catch (e) {
      this.logger.error(`Scenario failed: ${e.message}`);
      status = 'ERROR';
      lastResponse = e.message;
    } finally {
      if (socket && !socket.destroyed) {
        socket.destroy();
      }
    }

    // Health probes after failure — TCP + HTTPS
    let hostDown = false;
    let probe = null;
    if (['DROPPED', 'TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host, this.port);
      hostDown = !probe.tcp.alive && !probe.https.alive;
      if (hostDown) {
        this.logger.hostDown(this.host, this.port, scenario.name);
      }
      this.logger.healthProbe(this.host, this.port, probe);
    }

    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    let verdict = this._computeVerdict(status, expected);
    
    // Differential Fuzzing Override:
    // If we have a baseline response and we match it (normalized), the behavior is "as expected"
    const { normalizeResponse } = require('./grader');
    const normResponse = normalizeResponse(lastResponse || status);
    const normBaseline = normalizeResponse(scenario._baselineResponse);
    if (normBaseline && normResponse === normBaseline) {
      verdict = 'AS EXPECTED';
    }

    const severity = CATEGORY_SEVERITY[scenario.category] || 'low';
    const compliance = checkProtocolCompliance(rawResponse, status);
    const result = {
      scenario: scenario.name, category: scenario.category, severity,
      status, expected, verdict, hostDown, probe,
      response: lastResponse || status,
      compliance,
      _baselineResponse: scenario._baselineResponse,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding, compliance);
    return result;
  }

  /**
   * TCP connect probe — check if target host:port is still accepting connections
   */
  _checkTCPAlive(host, port, timeout = 2000) {
    const start = Date.now();
    return new Promise((resolve) => {
      const probe = net.createConnection({ host, port, autoSelectFamily: true }, () => {
        const latency = Date.now() - start;
        probe.destroy();
        resolve({ alive: true, latency });
      });
      probe.setTimeout(timeout);
      probe.on('timeout', () => { probe.destroy(); resolve({ alive: false, error: 'timeout' }); });
      probe.on('error', (err) => { probe.destroy(); resolve({ alive: false, error: err.code || err.message }); });
    });
  }

  /**
   * HTTPS probe — do a real TLS handshake + HTTP HEAD to verify service health
   */
  _checkHTTPSAlive(host, port, timeout = 3000) {
    const start = Date.now();
    return new Promise((resolve) => {
      const req = https.request({
        hostname: host,
        port,
        path: '/',
        method: 'HEAD',
        timeout,
        agent: this._healthAgent,
        autoSelectFamily: true,
      }, (res) => {
        const latency = Date.now() - start;
        const tlsSocket = res.socket;
        const tlsVersion = tlsSocket.getProtocol ? tlsSocket.getProtocol() : null;
        const cipher = tlsSocket.getCipher ? tlsSocket.getCipher() : null;
        res.resume(); // drain
        resolve({
          alive: true,
          latency,
          statusCode: res.statusCode,
          tlsVersion: tlsVersion || 'unknown',
          cipher: cipher ? cipher.name : 'unknown',
        });
      });
      req.setTimeout(timeout, () => {
        req.destroy();
        resolve({ alive: false, error: 'timeout' });
      });
      req.on('error', (err) => {
        resolve({ alive: false, error: err.code || err.message });
      });
      req.end();
    });
  }

  /**
   * Run both TCP and HTTPS health probes
   */
  async _runHealthProbes(host, port) {
    const [tcp, httpsProbe] = await Promise.all([
      this._checkTCPAlive(host, port),
      this._checkHTTPSAlive(host, port),
    ]);
    return { tcp, https: httpsProbe };
  }

  /**
   * Run multiple scenarios sequentially with host health checks
   */
  async runScenarios(scenarios) {
    const results = [];
    let hostWentDown = false;

    for (const scenario of scenarios) {
      if (this.aborted) break;

      // If the previous scenario caused the host to go down, re-probe before continuing
      if (hostWentDown) {
        this.logger.info(`Re-checking ${this.host}:${this.port} before next scenario...`);
        const recheck = await this._runHealthProbes(this.host, this.port);
        this.logger.healthProbe(this.host, this.port, recheck);
        if (!recheck.tcp.alive && !recheck.https.alive) {
          this.logger.hostDown(this.host, this.port, 'still unreachable — stopping batch');
          break;
        }
        this.logger.info(`Host is back up — continuing`);
        hostWentDown = false;
      }

      const result = await this.runScenario(scenario);
      results.push(result);

      // runScenario already probes and sets hostDown — use that
      if (result.hostDown) {
        hostWentDown = true;
      }

      await this._sleep(500); // pause between scenarios
    }
    const report = computeOverallGrade(results);
    this.logger.summary(results, report);
    return { results, report };
  }

  async _connect() {
    const maxRetries = 10;
    const retryDelay = 300;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await this._connectOnce();
      } catch (err) {
        if (err.code === 'ECONNREFUSED' && attempt < maxRetries) {
          await this._sleep(retryDelay);
          continue;
        }
        throw err;
      }
    }
  }

  _connectOnce() {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({
        host: this.host,
        port: this.port,
        allowHalfOpen: true,
      }, () => {
        this.logger.info(`Connected to ${this.host}:${this.port}`);
        resolve(socket);
      });
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
        // Reset short timer on each chunk — wait a bit for potential more
        clearTimeout(timer);
        timer = setTimeout(done, 150);
      };

      const onEnd = () => {
        // If we get an end/close, wait a tiny bit for any buffered data events
        // to fire before finalizing.
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

  _describeResponse(data) {
    const { records } = parseRecords(data);
    if (records.length === 0) return `Raw data (${data.length} bytes)`;
    const descriptions = records.map(r => {
      const { describeTLS } = require('./logger');
      return describeTLS(r.raw);
    });
    return descriptions.join(' + ');
  }

  _computeVerdict(status, expected) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    return effective === expected ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  close() {
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
    if (this._healthAgent) { this._healthAgent.destroy(); this._healthAgent = null; }
  }
}

module.exports = { FuzzerClient };
