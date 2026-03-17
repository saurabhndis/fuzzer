const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const dgram = require('dgram');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { buildQuicInitialWithCrypto, encodeVarInt } = require('./quic-packet');
const hs = require('./handshake');
const { Version, CipherSuite, ExtensionType, HandshakeType, NamedGroup } = require('./constants');

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
    // Send a compliant QUIC Initial with a proper TLS 1.3 ClientHello via UDP.
    // This replaces the broken `openssl s_client -quic` approach.
    return new Promise((resolve) => {
      const socket = dgram.createSocket('udp4');
      this._quicSocket = socket;

      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);

      // Build a real TLS 1.3 ClientHello
      const extraExtensions = [];
      const suppressExtensions = [];

      extraExtensions.push({ type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x04]) });
      suppressExtensions.push(ExtensionType.EC_POINT_FORMATS);
      suppressExtensions.push(ExtensionType.RENEGOTIATION_INFO);

      extraExtensions.push({
        type: ExtensionType.SUPPORTED_GROUPS,
        data: (() => { const b = Buffer.alloc(4); b.writeUInt16BE(2, 0); b.writeUInt16BE(NamedGroup.X25519, 2); return b; })(),
      });
      extraExtensions.push({
        type: ExtensionType.KEY_SHARE,
        data: hs.buildPQCKeyShareExtension([{ group: NamedGroup.X25519, keySize: 32 }]),
      });
      extraExtensions.push({
        type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        data: hs.buildALPNExtension(['h3']),
      });
      // QUIC transport parameters
      const tpBuf = Buffer.concat([
        (() => { const id = encodeVarInt(0x0f); const val = scid; return Buffer.concat([id, encodeVarInt(val.length), val]); })(),
        (() => { const id = encodeVarInt(0x04); const val = encodeVarInt(1048576); return Buffer.concat([id, encodeVarInt(val.length), val]); })(),
        (() => { const id = encodeVarInt(0x08); const val = encodeVarInt(100); return Buffer.concat([id, encodeVarInt(val.length), val]); })(),
      ]);
      extraExtensions.push({ type: 0x39, data: tpBuf });

      const chBody = hs.buildClientHelloBody({
        hostname: this.host,
        version: Version.TLS_1_2,
        cipherSuites: [CipherSuite.TLS_AES_128_GCM_SHA256],
        variant: 'small',
        extraExtensions,
        suppressExtensions,
      });

      const chMsg = hs.buildHandshakeMessage(HandshakeType.CLIENT_HELLO, chBody);

      const packet = buildQuicInitialWithCrypto(chMsg, { dcid, scid });

      socket.on('message', () => {
        if (this.logger) this.logger.info('[local-client] QUIC response received');
      });

      socket.on('error', (err) => {
        if (this.logger) this.logger.info(`[local-client] QUIC UDP error: ${err.message}`);
      });

      socket.send(packet, this.port, this.host, (err) => {
        if (err && this.logger) this.logger.info(`[local-client] QUIC send error: ${err.message}`);
      });

      setTimeout(() => {
        try { socket.close(); } catch (_) {}
        this._quicSocket = null;
        resolve();
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
    if (this._quicSocket) {
      try { this._quicSocket.close(); } catch (_) {}
      this._quicSocket = null;
    }
  }
}

module.exports = { WellBehavedClient };
