// Well-behaved protocol client — used during server fuzz tests in local mode.
// Sends proper protocol messages (ClientHello, HTTP/2 requests, QUIC Initial)
// to the fuzzing server, allowing it to execute server-side scenarios
// without needing an external client.
const tls = require('tls');
const http2 = require('http2');
const dgram = require('dgram');
const crypto = require('crypto');
const { buildQuicInitialWithCrypto } = require('./quic-packet');

function buildSyntheticClientHello() {
  const random = crypto.randomBytes(32);
  const sessionId = crypto.randomBytes(32);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),              // TLS 1.2 legacy version
    random,                                  // 32 bytes client random
    Buffer.from([sessionId.length]),         // session ID length
    sessionId,                               // session ID
    Buffer.from([0x00, 0x02, 0x13, 0x01]),  // cipher suites: length=2, TLS_AES_128_GCM_SHA256
    Buffer.from([0x01, 0x00]),              // compression: 1 method, null
  ]);
  const header = Buffer.alloc(4);
  header[0] = 0x01; // ClientHello
  header.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([header, body]);
}

class WellBehavedClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 4433;
    this.logger = opts.logger || null;
    this._connection = null;
    this._stopped = false;
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
        if (this.logger) this.logger.info('[local-client] TLS connected');
        try {
          socket.write('GET / HTTP/1.1\r\nHost: ' + this.host + '\r\n\r\n');
        } catch (_) {}
      });

      socket.on('data', () => {});

      socket.on('error', (err) => {
        // Expected when server sends fuzzed/malformed TLS data
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
        if (this.logger) this.logger.info('[local-client] HTTP/2 connected');
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
      const socket = dgram.createSocket('udp4');
      this._connection = socket;

      const clientHello = buildSyntheticClientHello();
      const packet = buildQuicInitialWithCrypto(clientHello, {
        dcid: crypto.randomBytes(8),
        scid: crypto.randomBytes(8),
        packetNumber: 0,
      });

      socket.send(packet, this.port, this.host, (err) => {
        if (err && this.logger) this.logger.info(`[local-client] QUIC send error: ${err.message}`);
        if (this.logger) this.logger.info('[local-client] QUIC Initial sent');
      });

      socket.on('message', (msg) => {
        if (this.logger) this.logger.info(`[local-client] QUIC response: ${msg.length} bytes`);
      });

      socket.on('error', () => {});

      // Wait for scenario to complete
      setTimeout(() => resolve(), 5000);
    });
  }

  stop() {
    this._stopped = true;
    if (this._connection) {
      try { this._connection.destroy(); } catch (_) {}
      try { this._connection.close(); } catch (_) {}
      this._connection = null;
    }
  }
}

module.exports = { WellBehavedClient };
