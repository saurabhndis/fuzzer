// Unified Fuzzing Client — handles both TLS and HTTP/2 scenarios from one class.
// TLS scenarios (categories A–Y): connect via raw TCP, send raw TLS bytes.
// HTTP/2 scenarios (categories AA–AJ): connect via TLS+ALPN h2, send raw H2 frames.
const net = require('net');
const https = require('https');
const tls = require('tls');
const { Logger } = require('./logger');
const { PcapWriter } = require('./pcap-writer');
const { sendFIN, sendRST, slowDrip, sendFragmented, configureSocket, RawTCPSocket, isRawAvailable } = require('./tcp-tricks');
const { parseRecords } = require('./record');
const { gradeResult, computeOverallGrade, CATEGORY_SEVERITY } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { checkProtocolCompliance } = require('./protocol-compliance');
const { QuicFuzzerClient } = require('./quic-fuzzer-client');

// QUIC category codes start with 'Q' (QA–QF)
function isQuicScenario(scenario) {
  return typeof scenario.category === 'string' && scenario.category.startsWith('Q');
}

// Raw TCP category codes start with 'R' followed by A-G (RA–RG)
function isTcpScenario(scenario) {
  return typeof scenario.category === 'string' && scenario.category.length === 2
    && scenario.category[0] === 'R' && scenario.category[1] >= 'A' && scenario.category[1] <= 'G';
}

// HTTP/2 category codes are two-letter (AA–AJ); TLS categories are single-letter (A–Y)
function isH2Scenario(scenario) {
  return typeof scenario.category === 'string' && scenario.category.length === 2
    && !isQuicScenario(scenario) && !isTcpScenario(scenario);
}

class UnifiedClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.timeout = opts.timeout || 5000;
    this.delay = opts.delay || 100;
    this.logger = opts.logger || new Logger(opts);
    this.pcap = opts.pcapFile ? new PcapWriter(opts.pcapFile, {
      srcPort: 49152 + Math.floor(Math.random() * 16000),
      dstPort: this.port,
    }) : null;
    this.dut = opts.dut || null;
    this.aborted = false;
  }

  abort() { this.aborted = true; }

  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, status: 'ABORTED', response: 'Aborted' };

    if (scenario.side === 'server') {
      this.logger.error(`Skipping server-side scenario "${scenario.name}" in client mode`);
      return { scenario: scenario.name, status: 'SKIPPED', response: 'Server-side scenario cannot run in client mode' };
    }

    if (isTcpScenario(scenario)) {
      return this._runRawTCPScenario(scenario);
    }

    if (isQuicScenario(scenario)) {
      const quicClient = new QuicFuzzerClient({
        host: this.host,
        port: this.port,
        timeout: this.timeout,
        delay: this.delay,
        logger: this.logger
      });
      return quicClient.runScenario(scenario);
    }

    return isH2Scenario(scenario)
      ? this._runH2Scenario(scenario)
      : this._runTLSScenario(scenario);
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
          this.logger.hostDown(this.host, this.port, 'still unreachable — stopping batch');
          break;
        }
        this.logger.info('Host is back up — continuing');
        hostWentDown = false;
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

  // ── TLS scenario ────────────────────────────────────────────────────────────
  async _runTLSScenario(scenario) {
    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    let socket = null;
    let recvBuffer = Buffer.alloc(0);
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let connectionClosed = false;

    try {
      socket = await this._connectTLS();
      if (this.pcap) this.pcap.writeTCPHandshake();
      configureSocket(socket);

      socket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
      socket.on('end', () => {
        connectionClosed = true;
        this.logger.tcpEvent('received', 'FIN');
        if (this.pcap) this.pcap.writeFIN('received');
      });
      socket.on('close', () => { connectionClosed = true; });
      socket.on('error', (err) => {
        if (!connectionClosed) { this.logger.error(`Socket error: ${err.message}`); connectionClosed = true; }
      });

      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'send': {
            if (connectionClosed || socket.destroyed) {
              this.logger.error('Cannot send: connection closed'); status = 'DROPPED'; break;
            }
            try {
              socket.write(action.data);
              this.logger.sent(action.data, action.label);
              if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            } catch (e) { this.logger.error(`Write failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'recv': {
            recvBuffer = Buffer.alloc(0);
            const data = await this._waitForData(socket, action.timeout || this.timeout, () => connectionClosed);
            if (data && data.length > 0) {
              this.logger.received(data);
              if (this.pcap) this.pcap.writeTLSData(data, 'received');
              lastResponse = this._describeTLSResponse(data);
              rawResponse = data;
            } else if (connectionClosed) {
              lastResponse = 'Connection closed'; rawResponse = null; status = 'DROPPED';
            } else {
              lastResponse = 'Timeout (no response)'; rawResponse = null; status = 'TIMEOUT';
            }
            break;
          }

          case 'delay': await this._sleep(action.ms); break;

          case 'fin': {
            this.logger.tcpEvent('sent', action.label || 'FIN');
            if (this.pcap) this.pcap.writeFIN('sent');
            try { await sendFIN(socket); } catch (_) {}
            break;
          }

          case 'rst': {
            this.logger.tcpEvent('sent', action.label || 'RST');
            if (this.pcap) this.pcap.writeRST('sent');
            sendRST(socket); connectionClosed = true;
            break;
          }

          case 'slowDrip': {
            this.logger.fuzz(action.label || `Slow drip: ${action.data.length} bytes, ${action.bytesPerChunk}B/chunk`);
            if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            try { await slowDrip(socket, action.data, action.bytesPerChunk, action.delayMs); }
            catch (e) { this.logger.error(`Slow drip failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'fragment': {
            this.logger.fuzz(action.label || `Fragmenting ${action.data.length} bytes into ${action.fragments} segments`);
            if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            try { await sendFragmented(socket, action.data, action.fragments, action.delayMs); }
            catch (e) { this.logger.error(`Fragment send failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'tlsPost': {
            // Close raw TCP socket and establish a real TLS connection for application-layer test
            if (socket && !socket.destroyed) socket.destroy();
            try {
              const result = await this._runTLSPost(action);
              lastResponse = result.response;
              status = result.status;
              this.logger.info(action.label || `HTTP POST ${action.bodySize} bytes`);
              this.logger.info(`Response: ${result.response}`);
            } catch (e) {
              this.logger.error(`TLS POST failed: ${e.message}`);
              status = 'ERROR'; lastResponse = e.message;
            }
            break;
          }
        }

        if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
      }

    } catch (e) {
      this.logger.error(`Scenario failed: ${e.message}`);
      status = 'ERROR'; lastResponse = e.message;
    } finally {
      if (socket && !socket.destroyed) socket.destroy();
    }

    let hostDown = false, probe = null;
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
    const severity = CATEGORY_SEVERITY[scenario.category] || 'low';
    const compliance = checkProtocolCompliance(rawResponse, status);
    const result = {
      scenario: scenario.name, category: scenario.category, severity,
      status, expected, verdict, hostDown, probe,
      response: lastResponse || status,
      compliance,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding, compliance);
    return result;
  }

  // ── HTTP/2 scenario ─────────────────────────────────────────────────────────
  async _runH2Scenario(scenario) {
    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    const isProbe = actions.some(a => a.type === 'probe');
    if (isProbe) return this._runProbeScenario(scenario, actions);

    let socket = null;
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let connectionClosed = false;

    try {
      socket = await this._connectH2(scenario.connectionOptions, scenario.isTcpOnly);
      if (this.pcap) this.pcap.writeTCPHandshake();
      configureSocket(socket);

      socket.on('data', () => {});
      socket.on('end', () => {
        connectionClosed = true;
        this.logger.tcpEvent('received', 'FIN');
        if (this.pcap) this.pcap.writeFIN('received');
      });
      socket.on('close', () => { connectionClosed = true; });
      socket.on('error', (err) => {
        if (!connectionClosed) { this.logger.error(`Socket error: ${err.message}`); connectionClosed = true; }
      });

      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'send': {
            if (connectionClosed || socket.destroyed) {
              this.logger.error('Cannot send: connection closed'); status = 'DROPPED'; break;
            }
            try {
              socket.write(action.data);
              this.logger.sent(action.data, action.label);
              if (this.pcap) this.pcap.writeTLSData(action.data, 'sent');
            }
            catch (e) { this.logger.error(`Write failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'recv': {
            const data = await this._waitForData(socket, action.timeout || this.timeout, () => connectionClosed);
            if (data && data.length > 0) {
              this.logger.received(data);
              if (this.pcap) this.pcap.writeTLSData(data, 'received');
              lastResponse = this._describeH2Response(data); rawResponse = data;
            } else if (connectionClosed) {
              lastResponse = 'Connection closed'; rawResponse = null; status = 'DROPPED';
            } else {
              lastResponse = 'Timeout (no response)'; rawResponse = null; status = 'TIMEOUT';
            }
            break;
          }

          case 'delay': await this._sleep(action.ms); break;
          case 'fin': {
            this.logger.tcpEvent('sent', action.label || 'FIN');
            if (this.pcap) this.pcap.writeFIN('sent');
            try { await sendFIN(socket); } catch (_) {}
            break;
          }
          case 'rst': {
            this.logger.tcpEvent('sent', action.label || 'RST');
            if (this.pcap) this.pcap.writeRST('sent');
            sendRST(socket); connectionClosed = true;
            break;
          }
        }

        if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
      }

    } catch (e) {
      this.logger.error(`Scenario failed: ${e.message}`);
      status = 'ERROR'; lastResponse = e.message;
    } finally {
      if (socket && !socket.destroyed) socket.destroy();
    }

    let hostDown = false, probe = null;
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
    const severity = CATEGORY_SEVERITY[scenario.category] || 'medium';
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

  async _runProbeScenario(scenario, actions) {
    const probeAction = actions.find(a => a.type === 'probe');
    const label = probeAction ? probeAction.label : 'connectivity probe';
    this.logger.info(`Probe: ${label}`);

    let status = 'CONNECTED';
    let lastResponse = '';
    let socket = null;

    try {
      socket = await this._connectH2(scenario.connectionOptions, scenario.isTcpOnly);
      if (scenario.isTcpOnly) {
        lastResponse = `TCP connected to ${this.host}:${this.port}`;
      } else {
        const alpn = socket.alpnProtocol || 'none';
        const tlsVersion = typeof socket.getProtocol === 'function' ? socket.getProtocol() : 'TLS';
        lastResponse = `Connected (${tlsVersion}, ALPN: ${alpn})`;
      }
      this.logger.info(lastResponse);
    } catch (e) {
      status = 'FAILED_CONNECTION'; lastResponse = e.message;
      this.logger.error(`Probe failed: ${e.message}`);
    } finally {
      if (socket && !socket.destroyed) socket.destroy();
    }

    const verdict = this._computeVerdict(status, scenario.expected);
    const severity = CATEGORY_SEVERITY[scenario.category] || 'info';
    const result = {
      scenario: scenario.name, category: scenario.category, severity,
      status, expected: scenario.expected, verdict, hostDown: false, probe: null,
      response: lastResponse,
      compliance: null,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse, verdict, scenario.expectedReason || '', false, result.finding, null);
    return result;
  }

  // ── Connections ─────────────────────────────────────────────────────────────

  async _connectTLS() {
    const maxRetries = 10;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try { return await this._connectTLSOnce(); }
      catch (err) {
        if (err.code === 'ECONNREFUSED' && attempt < maxRetries) { await this._sleep(300); continue; }
        throw err;
      }
    }
  }

  _connectTLSOnce() {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: this.host, port: this.port, allowHalfOpen: true }, () => {
        this.logger.info(`Connected to ${this.host}:${this.port}`);
        resolve(socket);
      });
      socket.setTimeout(this.timeout);
      socket.on('timeout', () => { socket.destroy(); reject(new Error('Connection timeout')); });
      socket.on('error', reject);
    });
  }

  async _connectH2(connectionOptions, isTcpOnly) {
    const maxRetries = 3;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try { return await this._connectH2Once(connectionOptions, isTcpOnly); }
      catch (err) {
        if (err.code === 'ECONNREFUSED' && attempt < maxRetries) { await this._sleep(300); continue; }
        throw err;
      }
    }
  }

  _connectH2Once(connectionOptions, isTcpOnly) {
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
      const opts = {
        host: this.host, port: this.port,
        ALPNProtocols: ['h2'],
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
      };
      // Merge overrides; undefined values delete the key (e.g. to remove ALPNProtocols)
      if (connectionOptions) {
        for (const [k, v] of Object.entries(connectionOptions)) {
          if (v === undefined) delete opts[k];
          else opts[k] = v;
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

  // ── TLS Application Layer POST ──────────────────────────────────────────────

  _runTLSPost(action) {
    const bodySize = action.bodySize || 131072;
    const path = action.path || '/';
    const contentType = action.contentType || 'application/octet-stream';
    const chunked = action.chunked || false;
    const timeout = action.timeout || Math.max(this.timeout, 30000);

    return new Promise((resolve, reject) => {
      const tlsSocket = tls.connect({
        host: this.host, port: this.port,
        rejectUnauthorized: false,
        servername: this.host,
      });

      tlsSocket.setTimeout(timeout);
      tlsSocket.on('timeout', () => {
        tlsSocket.destroy();
        resolve({ status: 'TIMEOUT', response: `Timeout after ${timeout}ms` });
      });
      tlsSocket.on('error', (err) => {
        resolve({ status: 'DROPPED', response: `TLS error: ${err.message}` });
      });

      tlsSocket.on('secureConnect', () => {
        this.logger.info(`TLS handshake complete: ${tlsSocket.getProtocol()} ${(tlsSocket.getCipher() || {}).name || ''}`);

        // Build HTTP/1.1 POST request
        const body = Buffer.alloc(bodySize, 0x41); // Fill with 'A'
        let header;
        if (chunked) {
          header = `POST ${path} HTTP/1.1\r\nHost: ${this.host}\r\nContent-Type: ${contentType}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n`;
        } else {
          header = `POST ${path} HTTP/1.1\r\nHost: ${this.host}\r\nContent-Type: ${contentType}\r\nContent-Length: ${bodySize}\r\nConnection: close\r\n\r\n`;
        }

        let responseData = '';
        tlsSocket.on('data', (data) => { responseData += data.toString(); });
        tlsSocket.on('end', () => {
          tlsSocket.destroy();
          const statusLine = responseData.split('\r\n')[0] || '';
          const httpStatus = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
          if (httpStatus) {
            resolve({ status: 'PASSED', response: `${statusLine} (${responseData.length} bytes)` });
          } else if (responseData.length > 0) {
            resolve({ status: 'PASSED', response: `Response: ${responseData.length} bytes` });
          } else {
            resolve({ status: 'DROPPED', response: 'Connection closed without response' });
          }
        });

        // Send header
        tlsSocket.write(header);

        // Send body
        if (chunked) {
          // Send in chunks
          const chunkSize = 16384;
          let offset = 0;
          const sendNextChunk = () => {
            if (offset >= bodySize) {
              tlsSocket.write('0\r\n\r\n'); // Final chunk
              return;
            }
            const end = Math.min(offset + chunkSize, bodySize);
            const chunk = body.slice(offset, end);
            tlsSocket.write(`${chunk.length.toString(16)}\r\n`);
            tlsSocket.write(chunk);
            tlsSocket.write('\r\n');
            offset = end;
            setImmediate(sendNextChunk);
          };
          sendNextChunk();
        } else {
          // Send body in 16KB writes to generate multiple TCP segments
          const chunkSize = 16384;
          let offset = 0;
          const sendNextChunk = () => {
            if (offset >= bodySize) return;
            const end = Math.min(offset + chunkSize, bodySize);
            tlsSocket.write(body.slice(offset, end));
            offset = end;
            if (offset < bodySize) setImmediate(sendNextChunk);
          };
          sendNextChunk();
        }
      });
    });
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  _describeTLSResponse(data) {
    const { records } = parseRecords(data);
    if (records.length === 0) return `Raw data (${data.length} bytes)`;
    const { describeTLS } = require('./logger');
    return records.map(r => describeTLS(r.raw)).join(' + ');
  }

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
    if (expected === 'CONNECTED') return status === 'CONNECTED' ? 'AS EXPECTED' : 'UNEXPECTED';
    if (expected === 'FAILED_CONNECTION') return status === 'FAILED_CONNECTION' ? 'AS EXPECTED' : 'UNEXPECTED';
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    return effective === expected ? 'AS EXPECTED' : 'UNEXPECTED';
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

  _checkTCPAlive(host, port, timeout = 2000) {
    const start = Date.now();
    return new Promise((resolve) => {
      const probe = net.createConnection({ host, port }, () => { probe.destroy(); resolve({ alive: true, latency: Date.now() - start }); });
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

  // ── Raw TCP scenario ─────────────────────────────────────────────────────────
  async _runRawTCPScenario(scenario) {
    if (!isRawAvailable()) {
      this.logger.error(`Skipping raw TCP scenario "${scenario.name}" — raw sockets not available (requires CAP_NET_RAW on Linux)`);
      return {
        scenario: scenario.name, category: scenario.category, severity: 'high',
        status: 'SKIPPED', expected: scenario.expected, verdict: 'N/A',
        response: 'Raw sockets not available (requires CAP_NET_RAW on Linux)',
        compliance: null, finding: 'skip', hostDown: false, probe: null,
      };
    }

    this.logger.scenario(scenario.name, scenario.description);

    const actions = scenario.actions({ hostname: this.host });
    let rawSocket = null;
    let lastResponse = '';
    let status = 'PASSED';
    let connectionClosed = false;
    let rawResponse = null;

    try {
      for (const action of actions) {
        if (this.aborted) { status = 'ABORTED'; break; }

        switch (action.type) {
          case 'rawConnect': {
            rawSocket = new RawTCPSocket({
              dstIP: this.host,
              dstPort: this.port,
              window: action.window,
              logger: this.logger,
            });
            if (this.pcap) {
              rawSocket.onPacket = (packet, dir) => this.pcap.writeRawPacket(packet, dir);
            }
            rawSocket.on('data', () => {});
            rawSocket.on('end', () => { connectionClosed = true; });
            rawSocket.on('close', () => { connectionClosed = true; });
            rawSocket.on('error', (err) => {
              if (!connectionClosed) this.logger.error(`Raw socket error: ${err.message}`);
              connectionClosed = true;
            });
            try {
              await rawSocket.connect(action.window, this.timeout);
              this.logger.info(`Raw TCP connected to ${this.host}:${this.port}`);
            } catch (e) {
              this.logger.error(`Raw TCP connect failed: ${e.message}`);
              status = 'ERROR'; lastResponse = e.message;
            }
            break;
          }

          case 'rawSend': {
            const flags = action.flags || '';
            const data = action.data || null;
            const sock = rawSocket || new RawTCPSocket({
              dstIP: this.host,
              dstPort: this.port,
              logger: this.logger,
            });
            if (!rawSocket) {
              // One-shot raw send (no prior connect)
              if (this.pcap) {
                sock.onPacket = (packet, dir) => this.pcap.writeRawPacket(packet, dir);
              }
            }
            try {
              await sock.sendSegment({
                flags,
                data,
                seqOffset: action.seqOffset,
                ackOffset: action.ackOffset,
                seqOverride: action.seqOverride,
                window: action.window,
                urgentPointer: action.urgentPointer,
              });
              this.logger.fuzz(action.label || `Raw TCP [${flags}]`);
            } catch (e) {
              this.logger.error(`Raw send failed: ${e.message}`);
              status = 'ERROR';
            }
            if (!rawSocket) {
              // Keep the one-shot socket for potential recv
              rawSocket = sock;
              rawSocket.on('data', () => {});
              rawSocket.on('end', () => { connectionClosed = true; });
              rawSocket.on('close', () => { connectionClosed = true; });
              rawSocket.on('error', () => { connectionClosed = true; });
            }
            break;
          }

          case 'synFlood': {
            this.logger.fuzz(`SYN flood: ${action.count} packets, spoofed=${!!action.spoofSource}`);
            try {
              await RawTCPSocket.flood(this.host, this.port, action.count, action.spoofSource);
              this.logger.info(`SYN flood complete: ${action.count} packets sent`);
            } catch (e) {
              this.logger.error(`SYN flood failed: ${e.message}`);
              status = 'ERROR'; lastResponse = e.message;
            }
            break;
          }

          case 'sendOverlapping': {
            if (!rawSocket) { status = 'ERROR'; lastResponse = 'No raw connection'; break; }
            this.logger.fuzz(`Overlapping segments: ${action.overlapBytes}B overlap`);
            try {
              await rawSocket.sendOverlapping(action.data, action.overlapBytes);
            } catch (e) {
              this.logger.error(`Overlapping send failed: ${e.message}`);
              status = 'ERROR';
            }
            break;
          }

          case 'sendOutOfOrder': {
            if (!rawSocket) { status = 'ERROR'; lastResponse = 'No raw connection'; break; }
            this.logger.fuzz(`Out-of-order segments: ${action.segments} segs, order=${action.order}`);
            try {
              await rawSocket.sendOutOfOrder(action.data, action.segments, action.order);
            } catch (e) {
              this.logger.error(`Out-of-order send failed: ${e.message}`);
              status = 'ERROR';
            }
            break;
          }

          case 'tcpProbe': {
            const alive = await RawTCPSocket.probe(this.host, this.port, 2000);
            this.logger.info(`TCP probe: ${this.host}:${this.port} is ${alive ? 'alive' : 'dead'}`);
            if (!alive) {
              status = 'DROPPED';
              lastResponse = 'Target became unreachable';
            } else {
              lastResponse = lastResponse || 'Target alive';
            }
            break;
          }

          // Standard actions work via RawTCPSocket's compatible interface
          case 'send': {
            if (!rawSocket || connectionClosed || rawSocket.destroyed) {
              this.logger.error('Cannot send: no raw connection'); status = 'DROPPED'; break;
            }
            try {
              rawSocket.write(action.data);
              this.logger.sent(action.data, action.label);
            } catch (e) { this.logger.error(`Write failed: ${e.message}`); status = 'DROPPED'; }
            break;
          }

          case 'recv': {
            if (!rawSocket) { status = 'TIMEOUT'; lastResponse = 'No connection'; break; }
            const data = await this._waitForData(rawSocket, action.timeout || this.timeout, () => connectionClosed);
            if (data && data.length > 0) {
              this.logger.received(data);
              lastResponse = this._describeTLSResponse(data);
              rawResponse = data;
            } else if (connectionClosed) {
              lastResponse = 'Connection closed'; status = 'DROPPED';
            } else {
              lastResponse = 'Timeout'; status = 'TIMEOUT';
            }
            break;
          }

          case 'delay': await this._sleep(action.ms); break;

          case 'fin': {
            if (rawSocket) {
              this.logger.tcpEvent('sent', action.label || 'FIN');
              rawSocket.end();
            }
            break;
          }

          case 'rst': {
            if (rawSocket) {
              this.logger.tcpEvent('sent', action.label || 'RST');
              rawSocket.destroy();
              connectionClosed = true;
            }
            break;
          }
        }

        if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
      }
    } catch (e) {
      this.logger.error(`Raw TCP scenario failed: ${e.message}`);
      status = 'ERROR'; lastResponse = e.message;
    } finally {
      if (rawSocket && !rawSocket.destroyed) rawSocket.destroy();
    }

    let hostDown = false, probe = null;
    if (['DROPPED', 'TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host, this.port);
      hostDown = !probe.tcp.alive;
      if (hostDown) this.logger.hostDown(this.host, this.port, scenario.name);
    }

    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    const verdict = this._computeVerdict(status, expected);
    const severity = CATEGORY_SEVERITY[scenario.category] || 'high';
    const compliance = null; // Raw TCP has no TLS compliance check
    const result = {
      scenario: scenario.name, category: scenario.category, severity,
      status, expected, verdict, hostDown, probe,
      response: lastResponse || status,
      compliance,
    };
    result.finding = gradeResult(result, scenario);
    this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, hostDown, result.finding, compliance);
    return result;
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  close() {
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
  }
}

module.exports = { UnifiedClient };
