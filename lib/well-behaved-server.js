const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { generateServerCert } = require('./cert-gen');

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

const certPath = path.join(os.tmpdir(), 'fuzzer-openssl-cert.pem');
const keyPath = path.join(os.tmpdir(), 'fuzzer-openssl-key.pem');

let _opensslGroups = null;
function getOpenSSLGroups() {
  if (_opensslGroups !== null) return _opensslGroups;
  try {
    const out = execSync('openssl list -kem-algorithms 2>/dev/null', { encoding: 'utf8', timeout: 5000 });
    const groups = [];
    groups.push('X25519', 'P-256', 'P-384', 'P-521');
    if (out.includes('X25519MLKEM768')) groups.push('X25519MLKEM768');
    if (out.includes('SecP256r1MLKEM768')) groups.push('SecP256r1MLKEM768');
    if (out.includes('SecP384r1MLKEM1024')) groups.push('SecP384r1MLKEM1024');
    if (out.includes('MLKEM768')) groups.push('MLKEM768');
    if (out.includes('MLKEM1024')) groups.push('MLKEM1024');
    if (out.includes('MLKEM512')) groups.push('MLKEM512');
    _opensslGroups = groups.join(':');
  } catch {
    _opensslGroups = '';
  }
  return _opensslGroups;
}

class WellBehavedServer {
  constructor(opts = {}) {
    this.port = opts.port || 0;
    this.hostname = opts.hostname || 'localhost';
    this.logger = opts.logger || null;
    this._server = null; // for Node APIs
    this._quicProcess = null; // for QUIC CLI
    this._actualPort = null;

    const gen = generateServerCert(this.hostname);
    this.privateKeyPEM = gen.privateKeyPEM;
    this.certPEM = derToPem(gen.certDER);
  }

  get actualPort() { return this._actualPort; }

  async startTLS() {
    this._server = tls.createServer({
      key: this.privateKeyPEM,
      cert: this.certPEM,
      rejectUnauthorized: false,
    });

    this._server.on('secureConnection', (socket) => {
      if (this.logger) this.logger.info('[local-server] TLS client connected');
      let responded = false;
      socket.on('data', () => {
        if (responded) return;
        responded = true;
        try {
          socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
        } catch (_) {}
      });
      socket.on('error', () => {});
    });

    this._server.on('tlsClientError', (err, socket) => {
      if (socket && !socket.destroyed) socket.destroy();
    });

    this._server.on('error', () => {});

    return new Promise((resolve, reject) => {
      this._server.listen(this.port, '0.0.0.0', () => {
        this._actualPort = this._server.address().port;
        if (this.logger) this.logger.info(`[local-server] Node TLS server listening on port ${this._actualPort}`);
        resolve();
      });
      this._server.once('error', reject);
    });
  }

  async startH2() {
    this._server = http2.createSecureServer({
      key: this.privateKeyPEM,
      cert: this.certPEM,
      allowHTTP1: true,
    });

    this._server.on('stream', (stream) => {
      try {
        stream.respond({ ':status': 200, 'content-type': 'text/plain' });
        stream.end('OK');
      } catch (_) {}
    });

    this._server.on('session', (session) => {
      session.on('error', () => {});
    });

    this._server.on('error', () => {});

    return new Promise((resolve, reject) => {
      this._server.listen(this.port, '0.0.0.0', () => {
        this._actualPort = this._server.address().port;
        if (this.logger) this.logger.info(`[local-server] Node HTTP/2 server listening on port ${this._actualPort}`);
        resolve();
      });
      this._server.once('error', reject);
    });
  }

  async startTCP() {
    this._server = net.createServer();

    this._server.on('connection', (socket) => {
      if (this.logger) this.logger.info('[local-server] TCP client connected');
      socket.on('data', () => {
        try {
          socket.write('OK\r\n');
        } catch (_) {}
      });
      socket.on('error', () => {});
    });

    this._server.on('error', () => {});

    return new Promise((resolve, reject) => {
      this._server.listen(this.port, '0.0.0.0', () => {
        this._actualPort = this._server.address().port;
        if (this.logger) this.logger.info(`[local-server] Node TCP server listening on port ${this._actualPort}`);
        resolve();
      });
      this._server.once('error', reject);
    });
  }

  _ensureCerts() {
    try {
      if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
        execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout ${keyPath} -out ${certPath} -days 1 -subj '/CN=${this.hostname}'`, { stdio: 'ignore' });
      }
    } catch (e) {
      if (this.logger) this.logger.info(`[local-server] Cert gen failed: ${e.message}`);
    }
  }

  async startQuic() {
    return new Promise((resolve, reject) => {
      let listenPort = this.port;
      if (listenPort === 0) listenPort = 40000 + Math.floor(Math.random() * 20000);
      this._actualPort = listenPort;

      this._ensureCerts();

      const args = [
        's_server',
        '-cert', certPath,
        '-key', keyPath,
        '-accept', listenPort.toString(),
        '-www',
        '-quic',
        '-ign_eof'
      ];

      const groups = getOpenSSLGroups();
      if (groups) args.push('-groups', groups);

      this._quicProcess = spawn('openssl', args);

      if (this.logger) {
        this._quicProcess.stdout.on('data', d => {
            const msg = d.toString().trim();
            if (msg) this.logger.info(`[openssl-quic-server] ${msg}`);
        });
        this._quicProcess.stderr.on('data', d => {
            const msg = d.toString().trim();
            if (msg) this.logger.info(`[openssl-quic-server err] ${msg}`);
        });
      }

      let started = false;
      this._quicProcess.stdout.on('data', (data) => {
        if (!started && data.toString().includes('ACCEPT')) {
          started = true;
          if (this.logger) this.logger.info(`[local-server] OpenSSL QUIC server listening on port ${this._actualPort}`);
          resolve();
        }
      });

      this._quicProcess.on('error', (err) => {
        if (!started) {
          started = true;
          reject(err);
        }
      });

      setTimeout(() => {
        if (!started) {
          started = true;
          resolve();
        }
      }, 500);
    });
  }

  stop() {
    if (this._server) {
      try { this._server.close(); } catch (_) {}
      this._server = null;
    }
    if (this._quicProcess) {
      try { this._quicProcess.kill('SIGKILL'); } catch (_) {}
      this._quicProcess = null;
    }
  }
}

module.exports = { WellBehavedServer };
