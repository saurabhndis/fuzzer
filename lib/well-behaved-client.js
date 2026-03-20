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
    this.activeSockets = new Set();
  }

  connectRawTLS() {
    // For raw TLS fuzzing on server side, we can just connect normally via TLS API.
    // The server fuzzer expects a genuine ClientHello, which Node's API will send.
    return this.connectTLS();
  }

  connectTLS() {
    const maxRetries = 70;
    const retryDelay = 500;

    const attempt = (retryCount) => {
      return new Promise((resolve) => {
        let retrying = false;

        const tlsOpts = {
          host: this.host,
          port: this.port,
          rejectUnauthorized: false,
        };
        // Only set servername for hostnames, not IP addresses
        if (this.host && !net.isIP(this.host)) {
          tlsOpts.servername = this.host;
        }
        const socket = tls.connect(tlsOpts);

        this._connection = socket;
        this.activeSockets.add(socket);

        const cleanup = () => { this.activeSockets.delete(socket); };
        socket.on('close', cleanup);

        socket.on('secureConnect', () => {
          if (this.logger) this.logger.info('[local-client] Node TLS connected');
          try {
            socket.write('GET / HTTP/1.1\r\nHost: ' + this.host + '\r\n\r\n');
          } catch (_) {}
        });

        socket.on('data', () => {});

        socket.on('error', (err) => {
          // Retry on connection refused (server not ready yet)
          if ((err.code === 'ECONNREFUSED' || err.message.includes('ECONNREFUSED')) && retryCount < maxRetries && !this._stopped) {
            retrying = true;
            this.activeSockets.delete(socket);
            try { socket.destroy(); } catch (_) {}
            if (this.logger) this.logger.info(`[local-client] Connection refused, retrying (${retryCount + 1}/${maxRetries})...`);
            setTimeout(() => attempt(retryCount + 1).then(resolve), retryDelay);
            return;
          }
          // Retry on transient system errors (FD exhaustion, resource pressure)
          if ((err.code === 'EMFILE' || err.code === 'ENFILE' || err.code === 'ENOMEM' || err.code === 'EAGAIN') && retryCount < maxRetries && !this._stopped) {
            retrying = true;
            this.activeSockets.delete(socket);
            try { socket.destroy(); } catch (_) {}
            if (this.logger) this.logger.error(`[local-client] System error ${err.code}, retrying after delay (${retryCount + 1}/${maxRetries})...`);
            setTimeout(() => attempt(retryCount + 1).then(resolve), retryDelay * 2);
            return;
          }
          if (this.logger) this.logger.info(`[local-client] TLS error (expected): ${err.message}`);
          resolve();
        });

        socket.on('close', () => { if (!retrying) resolve(); });

        socket.setTimeout(10000, () => {
          socket.destroy();
          resolve();
        });
      });
    };

    return attempt(0);
  }

  connectH2() {
    const maxRetries = 70;
    const retryDelay = 500;

    const attempt = (retryCount) => {
      return new Promise((resolve) => {
        let retrying = false;
        let session;
        try {
          session = http2.connect(`https://${this.host}:${this.port}`, {
            rejectUnauthorized: false,
          });
        } catch (e) {
          if ((e.code === 'ECONNREFUSED' || e.message.includes('ECONNREFUSED')) && retryCount < maxRetries && !this._stopped) {
            if (this.logger) this.logger.info(`[local-client] H2 connection refused, retrying (${retryCount + 1}/${maxRetries})...`);
            setTimeout(() => attempt(retryCount + 1).then(resolve), retryDelay);
            return;
          }
          if (this.logger) this.logger.info(`[local-client] H2 connect error: ${e.message}`);
          resolve();
          return;
        }

        this._connection = session;
        this.activeSockets.add(session);

        session.on('connect', () => {
          if (this.logger) this.logger.info('[local-client] Node HTTP/2 connected');
          const req = session.request({ ':method': 'GET', ':path': '/' });
          req.on('response', () => {});
          req.on('data', () => {});
          req.on('end', () => { if (!retrying) resolve(); });
          req.on('error', () => { if (!retrying) resolve(); });
          req.end();
        });

        session.on('error', (err) => {
          if ((err.code === 'ECONNREFUSED' || err.message.includes('ECONNREFUSED')) && retryCount < maxRetries && !this._stopped) {
            retrying = true;
            if (this.logger) this.logger.info(`[local-client] H2 connection refused, retrying (${retryCount + 1}/${maxRetries})...`);
            setTimeout(() => attempt(retryCount + 1).then(resolve), retryDelay);
            return;
          }
          if (this.logger) this.logger.info(`[local-client] H2 error (expected): ${err.message}`);
          resolve();
        });

        session.setTimeout(10000, () => {
          if (!retrying) { session.destroy(); resolve(); }
        });
      });
    };

    return attempt(0);
  }

  connectQuic(opts = {}) {
    const streamCount = opts.streams || 1;
    let quicheLib;
    try {
      quicheLib = require('@currentspace/http3');
    } catch (_) {
      // Fall back to raw UDP Initial-only handshake if quiche is not installed
      return this._connectQuicRaw();
    }

    const maxRetries = 70;
    const retryDelay = 500;

    const attempt = (retryCount) => {
      return new Promise((resolve) => {
        let retrying = false;
        let session;

        const timer = setTimeout(() => {
          if (session) try { session.close(); } catch (_) {}
          resolve();
        }, 10000);

        try {
          session = quicheLib.connect(`https://${this.host}:${this.port}`, {
            rejectUnauthorized: false,
          });
        } catch (e) {
          clearTimeout(timer);
          if ((e.code === 'ECONNREFUSED' || (e.message && e.message.includes('ECONNREFUSED'))) && retryCount < maxRetries && !this._stopped) {
            if (this.logger) this.logger.info(`[local-client] QUIC connection refused, retrying (${retryCount + 1}/${maxRetries})...`);
            setTimeout(() => attempt(retryCount + 1).then(resolve), retryDelay);
            return;
          }
          if (this.logger) this.logger.info(`[local-client] QUIC connect error: ${e.message}`);
          resolve();
          return;
        }

        this._quicSession = session;
        this.activeSockets.add(session);

        session.on('connect', () => {
          clearTimeout(timer);
          if (this.logger) this.logger.info(`[local-client] HTTP/3 connected via quiche, opening ${streamCount} stream(s)`);

          let completed = 0;
          for (let i = 0; i < streamCount; i++) {
            const req = session.request({
              ':method': 'GET',
              ':path': i === 0 ? '/' : `/stream-${i}`,
              ':scheme': 'https',
              ':authority': this.host,
            });

            let buf = Buffer.alloc(0);
            req.on('response', () => {});
            req.on('data', (d) => { buf = Buffer.concat([buf, d]); });
            const finish = () => {
              completed++;
              if (this.logger) this.logger.info(`[local-client] HTTP/3 stream ${i} response: ${buf.length} bytes`);
              if (completed >= streamCount) {
                try { session.close(); } catch (_) {}
                if (!retrying) resolve();
              }
            };
            req.on('end', finish);
            req.on('error', finish);
            req.end();
          }

          // Safety timeout for stream completion
          setTimeout(() => {
            try { session.close(); } catch (_) {}
            if (!retrying) resolve();
          }, 8000);
        });

        session.on('error', (err) => {
          clearTimeout(timer);
          if ((err.code === 'ECONNREFUSED' || (err.message && err.message.includes('ECONNREFUSED'))) && retryCount < maxRetries && !this._stopped) {
            retrying = true;
            if (this.logger) this.logger.info(`[local-client] QUIC connection refused, retrying (${retryCount + 1}/${maxRetries})...`);
            setTimeout(() => attempt(retryCount + 1).then(resolve), retryDelay);
            return;
          }
          if (this.logger) this.logger.info(`[local-client] QUIC error (expected): ${err.message}`);
          resolve();
        });
      });
    };

    return attempt(0);
  }

  _connectQuicRaw() {
    // Fallback: Send a compliant QUIC Initial with a proper TLS 1.3 ClientHello via raw UDP.
    return new Promise((resolve) => {
      const socket = dgram.createSocket('udp4');
      this._quicSocket = socket;

      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);

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
    for (const socket of this.activeSockets) {
      try { socket.destroy(); } catch (_) {}
    }
    this.activeSockets.clear();

    if (this._quicSession) {
      try { this._quicSession.close(); } catch (_) {}
      this._quicSession = null;
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
