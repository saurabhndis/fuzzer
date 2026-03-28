// QUIC Fuzzing Client — connects to a target QUIC server via UDP and runs scenarios
const dgram = require('dgram');
const { Logger } = require('./logger');
const { gradeResult, computeOverallGrade } = require('./grader');
const { computeExpected } = require('./compute-expected');
const { QUIC_CATEGORY_SEVERITY } = require('./quic-scenarios');
const { parseQuicRetry, buildQuicInitialWithCrypto } = require('./quic-packet');

class QuicFuzzerClient {
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
    if (this.aborted) return { scenario: scenario.name, description: scenario.description, status: 'ABORTED', response: 'Aborted' };
    if (scenario.side === 'server') {
      this.logger.error(`Skipping server-side scenario "${scenario.name}" in client mode`);
      return { scenario: scenario.name, description: scenario.description, status: 'SKIPPED', response: 'Server-side scenario cannot run in client mode' };
    }

    this.logger.scenario(scenario.name, scenario.description);

    // Initialize per-scenario PCAP if a base filename was provided
    if (this.pcapFileBase) {
      const { PcapWriter } = require('./pcap-writer');
      const path = require('path');
      const ext = path.extname(this.pcapFileBase) || '.pcap';
      const base = this.pcapFileBase.endsWith(ext)
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

    const actions = scenario.actions({ hostname: this.host });
    
    let lastResponse = '';
    let rawResponse = null;
    let status = 'PASSED';
    let receivedAny = false;
    let lastSentCryptoPayload = null; // Track the original CRYPTO payload for Retry handling

    try {
      const isIPv6 = this.host.includes(':') || this.host === 'localhost' || this.host === '::1';
      const type = isIPv6 ? 'udp6' : 'udp4';
      this.socket = dgram.createSocket(type);
      
      const recvBuffer = [];
      this.socket.on('message', (msg, rinfo) => {
        receivedAny = true;
        recvBuffer.push(msg);
        this.logger.received(msg, `UDP from ${rinfo.address}:${rinfo.port}`);
        if (this.pcap) this.pcap.writeUDPPacket(msg, 'received');
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
              if (action._cryptoPayload) lastSentCryptoPayload = action._cryptoPayload;
            } catch (e) {
              this.logger.error(`UDP send failed: ${e.message}`);
              status = 'ERROR';
            }
            break;
          }

          case 'recv': {
            const recvTimeout = action.timeout || this.timeout;
            let data = await this._waitForUDP(recvBuffer, recvTimeout);

            // Transparent QUIC Retry handling (RFC 9000 §8.1):
            // If the server sends a Retry, extract the token, rebuild the Initial
            // with the token and new DCID, resend, and wait for the real response.
            if (data && lastSentCryptoPayload) {
              const retry = parseQuicRetry(data);
              if (retry && retry.token.length > 0) {
                this.logger.info(`[quic] Received Retry — resending Initial with token (${retry.token.length}B)`);
                try {
                  const retryPacket = buildQuicInitialWithCrypto(lastSentCryptoPayload, {
                    dcid: retry.scid,
                    token: retry.token,
                    packetNumber: 0,
                  });
                  await this._sendUDP(retryPacket);
                  this.logger.sent(retryPacket, '[QUIC] Initial (with Retry token)');
                  // Wait for the actual server response
                  data = await this._waitForUDP(recvBuffer, recvTimeout);
                } catch (e) {
                  this.logger.error(`Retry resend failed: ${e.message}`);
                }
              }
            }

            if (data) {
              lastResponse = this._describeQuicResponse(data);
              rawResponse = data;
              // Stateless Reset and CONNECTION_CLOSE are rejections (RFC 9000 §10.3, §10.2)
              if (/Stateless Reset|CONNECTION_CLOSE/i.test(lastResponse)) {
                status = 'DROPPED';
              }
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
      if (this.pcap) {
        this.pcap.close();
        this.pcap = null;
      }
    }

    // UDP doesn't have "DROPPED" (connection closed) in the same way, 
    // but if we got nothing and it's not a success, we'll call it TIMEOUT/DROPPED
    if (status === 'PASSED' && !receivedAny) {
        // Many fuzz scenarios expect the server to drop the packet silently
        status = 'TIMEOUT'; 
    }

    // Health probe after failures — QUIC runs over UDP, so we send a
    // minimal QUIC Initial packet and check for any UDP response.
    let hostDown = false;
    let probe = null;
    if (['TIMEOUT', 'ERROR'].includes(status)) {
      await this._sleep(200);
      probe = await this._runHealthProbes(this.host);
      hostDown = !probe.udp.alive;
      if (hostDown) this.logger.hostDown(this.host, this.port, scenario.name);
      this.logger.healthProbe(this.host, this.port, probe);
    }

    const computed = computeExpected(scenario);
    const expected = scenario.expected || computed.expected;
    const expectedReason = scenario.expectedReason || computed.reason;
    const verdict = this._computeVerdict(status, expected, lastResponse);
    const severity = QUIC_CATEGORY_SEVERITY[scenario.category] || 'medium';
    
    const result = {
      scenario: scenario.name, description: scenario.description, category: scenario.category, severity,
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
        const recheck = await this._runHealthProbes(this.host);
        this.logger.healthProbe(this.host, this.port, recheck);
        if (!recheck.udp.alive) {
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

  _sendUDP(data) {
    if (this.pcap) this.pcap.writeUDPPacket(data, 'sent');
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

  _describeQuicResponse(data) {
    if (!data || data.length < 5) return `QUIC response (${data ? data.length : 0} bytes)`;

    const firstByte = data[0];
    const isLong = (firstByte & 0x80) !== 0;

    if (isLong) {
      const version = data.readUInt32BE(1);
      if (version === 0x00000000) {
        // Version Negotiation
        const dcidLen = data[5];
        const scidLen = data[6 + dcidLen];
        const versionsStart = 7 + dcidLen + scidLen;
        const versions = [];
        for (let i = versionsStart; i + 3 < data.length; i += 4) {
          versions.push('0x' + data.readUInt32BE(i).toString(16));
        }
        return `QUIC Version Negotiation [${versions.join(', ')}]`;
      }
      const pktType = (firstByte & 0x30) >> 4;
      const typeNames = ['Initial', '0-RTT', 'Handshake', 'Retry'];
      const typeName = typeNames[pktType] || 'Unknown';

      // A tiny Initial/Handshake (< 100 bytes) can't contain a real ServerHello
      // (minimum ~91 bytes for header + CRYPTO frame + AEAD tag). These are
      // CONNECTION_CLOSE or error responses — effectively rejections.
      if ((pktType === 0 || pktType === 2) && data.length < 100) {
        return `QUIC ${typeName} CONNECTION_CLOSE (${data.length} bytes, v=0x${version.toString(16)})`;
      }
      return `QUIC ${typeName} (${data.length} bytes, v=0x${version.toString(16)})`;
    }

    // Short header — without an established connection this is a Stateless Reset (RFC 9000 §10.3)
    // Stateless Resets are ≥21 bytes with fixed bit set; we can't verify the token but
    // any short-header response to an unestablished connection is effectively a reset.
    if (data.length >= 21 && data.length <= 43) {
      return `QUIC Stateless Reset (${data.length} bytes)`;
    }
    return `QUIC Short Header (${data.length} bytes)`;
  }

  _computeVerdict(status, expected, response) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return 'N/A';

    // TLS/QUIC alert statuses are always expected
    if (status === 'tls-alert-server' || status === 'tls-alert-client') return 'AS EXPECTED';

    // Response-aware verdict: coherent protocol responses indicate proper behavior
    if (response) {
      if (/QUIC.*CONNECTION_CLOSE/i.test(response)) return 'AS EXPECTED';
      if (/Version Negotiation/i.test(response)) return 'AS EXPECTED';
      if (/^ServerHello\(/i.test(response)) return 'AS EXPECTED';
    }

    // For UDP, we often treat TIMEOUT as DROPPED (server ignored)
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    const expectedEffective = expected === 'TIMEOUT' ? 'DROPPED' : expected;
    return effective === expectedEffective ? 'AS EXPECTED' : 'UNEXPECTED';
  }

  /**
   * Lazily create a persistent UDP socket for health probes, reused across
   * all checks to avoid socket creation/teardown overhead.
   */

  /**
   * Ping-based health probe — checks if the target host is reachable via ICMP ping.
   * UDP probes are unreliable after fuzz scenarios; ping checks host liveness.
   */
  async _runHealthProbes(host) {
    const { execFile } = require('child_process');
    const start = Date.now();
    return new Promise((resolve) => {
      execFile('ping', ['-c', '1', '-W', '2', host], { timeout: 5000 }, (err) => {
        const latency = Date.now() - start;
        if (err) {
          const result = { alive: false, error: 'ping failed' };
          resolve({ tcp: result, https: result, udp: result });
        } else {
          const result = { alive: true, latency };
          resolve({ tcp: result, https: result, udp: result });
        }
      });
    });
  }

  _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  close() {
  }
}

module.exports = { QuicFuzzerClient };
