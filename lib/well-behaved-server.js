// Well-behaved protocol server — used as a local target during client fuzz tests.
// Provides a compliant TLS, HTTP/2, or QUIC server that responds properly,
// allowing the fuzzing client to run scenarios without an external target.
const tls = require('tls');
const http2 = require('http2');
const dgram = require('dgram');
const crypto = require('crypto');
const { generateServerCert } = require('./cert-gen');
const { buildQuicInitialWithCrypto } = require('./quic-packet');

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

function buildSyntheticServerHello() {
  const random = crypto.randomBytes(32);
  const sessionId = crypto.randomBytes(32);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),        // TLS 1.2 legacy version
    random,                            // 32 bytes server random
    Buffer.from([sessionId.length]),   // session ID length
    sessionId,                         // session ID
    Buffer.from([0x13, 0x01]),         // TLS_AES_128_GCM_SHA256
    Buffer.from([0x00]),               // compression: null
  ]);
  const header = Buffer.alloc(4);
  header[0] = 0x02; // ServerHello
  header.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([header, body]);
}

class WellBehavedServer {
  constructor(opts = {}) {
    this.port = opts.port || 0;
    this.hostname = opts.hostname || 'localhost';
    this.logger = opts.logger || null;
    this._server = null;
    this._actualPort = null;

    const gen = generateServerCert(this.hostname);
    this.certDER = gen.certDER;
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
      socket.on('data', () => {
        try {
          socket.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
        } catch (_) {}
      });
      socket.on('error', () => {});
    });

    this._server.on('tlsClientError', (err, socket) => {
      // Expected — fuzzer sends malformed TLS data
      if (socket && !socket.destroyed) socket.destroy();
    });

    this._server.on('error', () => {});

    await new Promise((resolve, reject) => {
      this._server.listen(this.port, '0.0.0.0', () => {
        this._actualPort = this._server.address().port;
        if (this.logger) this.logger.info(`[local-server] TLS server listening on port ${this._actualPort}`);
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

    await new Promise((resolve, reject) => {
      this._server.listen(this.port, '0.0.0.0', () => {
        this._actualPort = this._server.address().port;
        if (this.logger) this.logger.info(`[local-server] HTTP/2 server listening on port ${this._actualPort}`);
        resolve();
      });
      this._server.once('error', reject);
    });
  }

  async startQuic() {
    this._server = dgram.createSocket('udp4');

    this._server.on('message', (msg, rinfo) => {
      if (this.logger) this.logger.info(`[local-server] QUIC packet from ${rinfo.address}:${rinfo.port} (${msg.length}B)`);

      // Extract client's DCID to mirror back
      let clientDcid = crypto.randomBytes(8);
      if (msg.length > 6) {
        const dcidLen = msg[5];
        if (dcidLen > 0 && msg.length > 6 + dcidLen) {
          clientDcid = msg.slice(6, 6 + dcidLen);
        }
      }

      const serverHello = buildSyntheticServerHello();
      const response = buildQuicInitialWithCrypto(serverHello, {
        dcid: clientDcid,
        scid: crypto.randomBytes(8),
        packetNumber: 0,
      });

      this._server.send(response, rinfo.port, rinfo.address, () => {});
    });

    this._server.on('error', () => {});

    await new Promise((resolve, reject) => {
      this._server.bind(this.port, '0.0.0.0', () => {
        this._actualPort = this._server.address().port;
        if (this.logger) this.logger.info(`[local-server] QUIC server listening on UDP port ${this._actualPort}`);
        resolve();
      });
      this._server.once('error', reject);
    });
  }

  stop() {
    if (this._server) {
      try { this._server.close(); } catch (_) {}
      this._server = null;
    }
  }
}

module.exports = { WellBehavedServer };
