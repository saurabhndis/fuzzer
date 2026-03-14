const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const { spawn } = require('child_process');

class WellBehavedClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 4433;
    this.logger = opts.logger || null;
    this._connection = null; // Node APIs
    this._quicProcess = null; // QUIC CLI
    this._stopped = false;
  }

  connectRawTLS() {
    // For raw TLS fuzzing on server side, we can just connect normally via TLS API.
    // The server fuzzer expects a genuine ClientHello, which Node's API will send.
    return this.connectTLS();
  }

  connectTLS() {
    return new Promise((resolve) => {
      const socket = tls.connect({
        host: this.host,
        port: this.port,
        rejectUnauthorized: false,
        servername: this.host,
      });

      this._connection = socket;

      socket.on('secureConnect', () => {
        if (this.logger) this.logger.info('[local-client] Node TLS connected');
        try {
          socket.write('GET / HTTP/1.1\r\nHost: ' + this.host + '\r\n\r\n');
        } catch (_) {}
      });

      socket.on('data', () => {});

      socket.on('error', (err) => {
        if (this.logger) this.logger.info(`[local-client] TLS error (expected): ${err.message}`);
        resolve();
      });

      socket.on('close', () => resolve());

      socket.setTimeout(10000, () => {
        socket.destroy();
        resolve();
      });
    });
  }

  connectH2() {
    return new Promise((resolve) => {
      let session;
      try {
        session = http2.connect(`https://${this.host}:${this.port}`, {
          rejectUnauthorized: false,
        });
      } catch (e) {
        if (this.logger) this.logger.info(`[local-client] H2 connect error: ${e.message}`);
        resolve();
        return;
      }

      this._connection = session;

      session.on('connect', () => {
        if (this.logger) this.logger.info('[local-client] Node HTTP/2 connected');
        const req = session.request({ ':method': 'GET', ':path': '/' });
        req.on('response', () => {});
        req.on('data', () => {});
        req.on('end', () => resolve());
        req.on('error', () => resolve());
        req.end();
      });

      session.on('error', (err) => {
        if (this.logger) this.logger.info(`[local-client] H2 error (expected): ${err.message}`);
        resolve();
      });

      session.setTimeout(10000, () => {
        session.destroy();
        resolve();
      });
    });
  }

  connectQuic() {
    return new Promise((resolve) => {
      const args = ['s_client', '-connect', `${this.host}:${this.port}`, '-ign_eof', '-quic'];
      
      this._quicProcess = spawn('openssl', args);
      
      if (this.logger) {
        this._quicProcess.stdout.on('data', d => {
            const msg = d.toString().trim();
            if (msg) this.logger.info(`[openssl-quic-client] ${msg}`);
        });
        this._quicProcess.stderr.on('data', d => {
            const msg = d.toString().trim();
            if (msg) this.logger.info(`[openssl-quic-client err] ${msg}`);
        });
      }

      this._quicProcess.on('error', (err) => {
        if (this.logger) this.logger.info(`[local-client] OpenSSL QUIC error: ${err.message}`);
        resolve();
      });

      this._quicProcess.on('close', () => {
        resolve();
      });

      try {
        this._quicProcess.stdin.write(`GET / HTTP/1.1\r\nHost: ${this.host}\r\n\r\n`);
      } catch (e) {}

      setTimeout(() => {
        if (!this._stopped) resolve();
      }, 5000);
    });
  }

  stop() {
    this._stopped = true;
    if (this._connection) {
      try { this._connection.destroy(); } catch (_) {}
      try { this._connection.close(); } catch (_) {}
      this._connection = null;
    }
    if (this._quicProcess) {
      try { this._quicProcess.kill('SIGKILL'); } catch (_) {}
      this._quicProcess = null;
    }
  }
}

module.exports = { WellBehavedClient };
