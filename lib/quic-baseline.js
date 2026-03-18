const { spawn } = require('child_process');
const { Logger } = require('./logger');

class QuicBaselineClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 443;
    this.logger = opts.logger || new Logger(opts);
    this.timeout = opts.timeout || 15000;
  }

  async runScenario(scenario) {
    this.logger.scenario(scenario.name, scenario.description);

    return new Promise((resolve) => {
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
            setTimeout(() => { client.stdin.write('Q\n'); }, 3000);

          } else if (scenario.name === 'quic-post-handshake-garbage') {
            this.logger.info('Flooding stream with 1MB of garbage data...');
            const crypto = require('crypto');
            client.stdin.write(crypto.randomBytes(1024 * 1024));
            setTimeout(() => { client.stdin.write('Q\n'); }, 2000);

          } else if (scenario.name === 'quic-post-handshake-slowloris') {
            this.logger.info('Starting Slowloris drip-feed...');
            let count = 0;
            const iv = setInterval(() => {
              client.stdin.write(Buffer.from([0x00]));
              count++;
              if (count > 15) {
                clearInterval(iv);
                client.stdin.write('Q\n');
              }
            }, 1000);

          } else if (scenario.name === 'quic-post-handshake-http-smuggling') {
            this.logger.info('Sending malformed HTTP/1.1 over QUIC...');
            client.stdin.write(`POST / HTTP/1.1\r\nHost: ${this.host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 50\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: ${this.host}\r\n\r\n`);
            setTimeout(() => { client.stdin.write('Q\n'); }, 1000);

          } else {
             setTimeout(() => {
                client.stdin.write('Q\n'); // Quit openssl
            }, 1000);
          }
        }
      });

      client.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      const timer = setTimeout(() => {
        this.logger.error('OpenSSL s_client timed out');
        client.kill();
        resolve({
          scenario: scenario.name,
          description: scenario.description,
          status: 'TIMEOUT',
          response: 'OpenSSL s_client timed out',
          verdict: 'UNEXPECTED',
          category: scenario.category
        });
      }, this.timeout);

      client.on('close', (code) => {
        clearTimeout(timer);
        
        const isSuccess = output.includes('CONNECTED') && output.includes('SSL-Session');
        
        if (isSuccess) {
          resolve({
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
          resolve({
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
        clearTimeout(timer);
        this.logger.error(`Failed to start OpenSSL: ${err.message}`);
        resolve({
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
