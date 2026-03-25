// Fuzzing Client Engine — connects to target and runs scenarios over raw TCP
const net = require('net');
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
    this.pcapFileBase = opts.pcapFile || null;
    this.mergePcap = opts.mergePcap || false;
    this.pcap = null;
    this.dut = opts.dut || null;
    this.aborted = false;
  }

  abort() {
    this.aborted = true;
  }

  /**
   * Run a single scenario against the target
   */
  async runScenario(scenario) {
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };
    if (scenario.side === 'server') {
      this.logger.error(`Skipping server-side scenario "${scenario.name}" in client mode`);
      return { scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Server-side scenario cannot run in client mode' };
    }

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
        : `${base}.${scenario.name}.client${ext}`;

      try {
        this.pcap = new PcapWriter(pcapFilename, {
          role: 'client',
          append: this.mergePcap,
          clientPort: 49152 + Math.floor(Math.random() * 16000),
          serverPort: this.port,
        });
      } catch (e) {
        this.logger.error(`Failed to initialize PCAP: ${e.message}`);
        this.pcap = null;
      }
    }

    // Delegate to UnifiedClient for scenarios using Node.js TLS/H2 APIs
    if (scenario.useNodeTLS || scenario.useNodeH2 || scenario.useCustomClient) {
      const { UnifiedClient } = require('./unified-client');
      const uc = new UnifiedClient({ host: this.host, port: this.port, timeout: this.timeout, delay: this.delay, logger: this.logger, pcapFile: this.pcapFileBase, mergePcap: this.mergePcap });
      return uc.runScenario(scenario);
    }

    const actions = typeof scenario.actions === 'function' ? scenario.actions({ hostname: this.host }) : scenario.actions;
    if (!actions) {
      this.logger.error(`Scenario "${scenario.name}" actions returned undefined!`);
    }
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

      // Rejection detection:
      // 1. Post-fuzz encrypted alert or only application data (TLS 1.3 rejection)
      if (status === 'PASSED' && hasFuzzAction && postFuzzRecvData) {
        const { records: postRecords } = parseRecords(postFuzzRecvData);
        const hasHandshake = postRecords.some(r => r.type === 0x16);
        const hasCleartextAlert = postRecords.some(r => r.type === 0x15);
        const onlyAppData = !hasHandshake && postRecords.length > 0 && postRecords.every(r => r.type === 0x17);
        if (hasCleartextAlert || onlyAppData) {
          status = 'DROPPED';
          lastResponse = hasCleartextAlert
            ? this._describeResponse(postFuzzRecvData)
            : 'Encrypted alert (TLS 1.3)';
        }
      }

      // 2. Premature termination: if status is still PASSED but the connection was 
      // closed by the server without sending any response data, that's a rejection.
      if (status === 'PASSED' && connectionClosed && !rawResponse && !postFuzzRecvData) {
        status = 'DROPPED';
        if (!lastResponse) lastResponse = 'Connection closed';
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

    // Health probes after failure — TCP + HTTPS
    let hostDown = false;
    let probe = null;
    if (['DROPPED', 'TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host);
      hostDown = !probe.tcp.alive && !probe.https.alive;
      if (hostDown) {
        this.logger.hostDown(this.host, this.port, scenario.name);
      }
      this.logger.healthProbe(this.host, this.port, probe);
    }

    // Response-aware status: alert from server = tls-alert-server
    if (lastResponse) {
      if (/^Alert\(fatal/i.test(lastResponse) || /Encrypted alert/i.test(lastResponse)) {
        status = 'tls-alert-server';
      }
    }

    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    let verdict = this._computeVerdict(status, expected, lastResponse);

    // Differential Fuzzing Override:
    // If baseline and target show the same behavior class (both accept or both reject), match
    const { normalizeResponse, classifyBehavior } = require('./grader');
    const normResponse = normalizeResponse(lastResponse || status);
    const normBaseline = normalizeResponse(scenario._baselineResponse);
    if (normBaseline && normResponse === normBaseline) {
      verdict = 'AS EXPECTED';
    } else if (scenario._baselineResponse) {
      const targetBehavior = classifyBehavior(lastResponse || status, status);
      const baselineBehavior = classifyBehavior(scenario._baselineResponse, null);
      if (targetBehavior !== 'unknown' && targetBehavior === baselineBehavior) {
        verdict = 'AS EXPECTED';
      }
    }

    const severity = CATEGORY_SEVERITY[scenario.category] || 'low';
    const compliance = checkProtocolCompliance(rawResponse, status);
    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category, severity,
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
   * Ping-based health probe — checks if the target host is reachable via ICMP ping.
   * TCP/HTTPS probes are unreliable after fuzz scenarios; ping checks host liveness.
   */
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
        const recheck = await this._runHealthProbes(this.host);
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
        if ((err.code === 'ECONNREFUSED' || err.message.includes('ECONNREFUSED')) && attempt < maxRetries) {
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

  close() {
    if (this.pcap) { this.pcap.close(); this.pcap = null; }
  }
}

module.exports = { FuzzerClient };
