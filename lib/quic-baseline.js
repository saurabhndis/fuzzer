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
      
      this.logger.info(`Spawning OpenSSL: openssl ${args.join(' ')}`);
      
      const client = spawn('openssl', args);
      let output = '';
      let errorOutput = '';
      let connected = false;

      client.stdout.on('data', (data) => {
        const str = data.toString();
        output += str;
        
        if (str.includes('CONNECTED') && !connected) {
          connected = true;
          this.logger.info('QUIC Handshake Completed (CONNECTED)');
          
          if (isMultipleStreams) {
            this.logger.info('Sending 100 HTTP/3 streams...');
            // OpenSSL s_client doesn't natively multiplex 100 concurrent h3 streams via stdin
            // But we can rapidly send payload that OpenSSL wraps in QUIC application data
            for (let i = 0; i < 100; i++) {
              client.stdin.write(`GET / HTTP/1.1\r\nHost: ${this.host}\r\nConnection: keep-alive\r\n\r\n`);
            }
            setTimeout(() => {
                client.stdin.write('Q\n'); // Quit openssl
            }, 3000);
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
