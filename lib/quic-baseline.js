const { spawn } = require('child_process');
const { Logger } = require('./logger');

class QuicBaselineClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.logger = opts.logger || new Logger(opts);
    this.timeout = opts.timeout || 15000;
    this.processTracker = opts.processTracker || null;
    this.pcapFileBase = opts.pcapFile || null;
    this.pcap = null;
  }

  async runScenario(scenario) {
    this.logger.scenario(scenario.name, scenario.description);

    // Initialize per-scenario PCAP if a base filename was provided
    if (this.pcapFileBase) {
      const { PcapWriter } = require('./pcap-writer');
      const path = require('path');
      const ext = path.extname(this.pcapFileBase) || '.pcap';
      const base = this.pcapFileBase.endsWith(ext)
        ? this.pcapFileBase.slice(0, -ext.length)
        : this.pcapFileBase;
      const pcapFilename = `${base}.${scenario.name}.client${ext}`;
      try {
        this.pcap = new PcapWriter(pcapFilename, {
          role: 'client',
          clientPort: 49152 + Math.floor(Math.random() * 16000),
          serverPort: this.port,
          protocol: 'udp',
        });
      } catch (e) {
        this.logger.error(`Failed to initialize PCAP: ${e.message}`);
        this.pcap = null;
      }
    }

    return new Promise((resolve) => {
      let resolved = false;
      const finish = (result) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timer);
        if (this.pcap) {
          this.pcap.close();
          this.pcap = null;
        }
        // Clean up all pending timers/intervals
        for (const t of pendingTimers) clearTimeout(t);
        if (pendingInterval) clearInterval(pendingInterval);
        pendingTimers.length = 0;
        pendingInterval = null;
        // Unregister from parent tracker
        if (this.processTracker) this.processTracker.delete(client);
        // Ensure process is dead
        try { client.kill(); } catch (_) {}
        resolve(result);
      };

      const pendingTimers = [];
      let pendingInterval = null;

      const isMultipleStreams = scenario.name === 'well-behaved-quic-client-100-streams';

      const args = [
        's_client',
        '-quic',
        '-alpn', 'h3',
        '-connect', `${this.host}:${this.port}`,
        '-ign_eof'
      ];

      if (scenario.sni) {
        args.push('-servername', scenario.sni);
      }

      this.logger.info(`Spawning OpenSSL: openssl ${args.join(' ')}`);

      const client = spawn('openssl', args);

      // Register with parent's process tracker so 90s timeout can kill us
      if (this.processTracker) this.processTracker.add(client);

      let output = '';
      let errorOutput = '';
      let connected = false;

      // Handle stdin pipe errors (e.g. if the target server abruptly drops connection during fuzzing)
      client.stdin.on('error', (err) => {
        if (err.code !== 'EPIPE') {
          this.logger.error(`stdin error: ${err.message}`);
        }
      });

      client.stdout.on('data', (data) => {
        const str = data.toString();
        output += str;

        if (str.includes('CONNECTED') && !connected) {
          connected = true;
          this.logger.info('QUIC Handshake Completed (CONNECTED)');

          if (isMultipleStreams) {
            this.logger.info('Sending 100 HTTP/3 streams...');
            for (let i = 0; i < 100; i++) {
              client.stdin.write(`GET / HTTP/1.1\r\nHost: ${this.host}\r\nConnection: keep-alive\r\n\r\n`);
            }
            pendingTimers.push(setTimeout(() => { try { client.stdin.write('Q\n'); } catch (_) {} }, 3000));

          } else if (scenario.name === 'quic-post-handshake-garbage') {
            this.logger.info('Flooding stream with 1MB of garbage data...');
            const crypto = require('crypto');
            client.stdin.write(crypto.randomBytes(1024 * 1024));
            pendingTimers.push(setTimeout(() => { try { client.stdin.write('Q\n'); } catch (_) {} }, 2000));

          } else if (scenario.name === 'quic-post-handshake-slowloris') {
            this.logger.info('Starting Slowloris drip-feed...');
            let count = 0;
            pendingInterval = setInterval(() => {
              try { client.stdin.write(Buffer.from([0x00])); } catch (_) {}
              count++;
              if (count > 15) {
                clearInterval(pendingInterval);
                pendingInterval = null;
                try { client.stdin.write('Q\n'); } catch (_) {}
              }
            }, 1000);

          } else if (scenario.name === 'quic-post-handshake-http-smuggling') {
            this.logger.info('Sending malformed HTTP/1.1 over QUIC...');
            client.stdin.write(`POST / HTTP/1.1\r\nHost: ${this.host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 50\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: ${this.host}\r\n\r\n`);
            pendingTimers.push(setTimeout(() => { try { client.stdin.write('Q\n'); } catch (_) {} }, 1000));

          } else {
            pendingTimers.push(setTimeout(() => {
              try { client.stdin.write('Q\n'); } catch (_) {} // Quit openssl
            }, 1000));
          }
        }
      });

      client.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      const timer = setTimeout(() => {
        this.logger.error('OpenSSL s_client timed out');
        finish({
          scenario: scenario.name,
          description: scenario.description,
          status: 'TIMEOUT',
          response: 'OpenSSL s_client timed out',
          verdict: 'UNEXPECTED',
          category: scenario.category
        });
      }, this.timeout);

      client.on('close', (code) => {
        const isSuccess = output.includes('CONNECTED') && output.includes('SSL-Session');

        if (isSuccess) {
          finish({
            scenario: scenario.name,
            description: scenario.description,
            status: 'PASSED',
            response: isMultipleStreams ? 'OpenSSL established QUIC connection and sent 100 payloads' : 'OpenSSL successfully established QUIC connection',
            verdict: 'AS EXPECTED',
            category: scenario.category
          });
        } else {
          this.logger.error(`OpenSSL failed to connect. Exit code: ${code}`);
          this.logger.error(`OpenSSL error output: ${errorOutput}`);
          finish({
            scenario: scenario.name,
            description: scenario.description,
            status: 'ERROR',
            response: `OpenSSL QUIC Handshake Failed`,
            verdict: 'UNEXPECTED',
            category: scenario.category
          });
        }
      });

      client.on('error', (err) => {
        this.logger.error(`Failed to start OpenSSL: ${err.message}`);
        finish({
          scenario: scenario.name,
          description: scenario.description,
          status: 'ERROR',
          response: `Failed to spawn OpenSSL: ${err.message}`,
          verdict: 'UNEXPECTED',
          category: scenario.category
        });
      });
    });
  }
}

module.exports = { QuicBaselineClient };
