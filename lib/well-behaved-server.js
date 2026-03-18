const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const dgram = require('dgram');
const crypto = require('crypto');
const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { generateServerCert } = require('./cert-gen');
const { deriveInitialKeys, protectPacket, encodeVarInt } = require('./quic-packet');
const hs = require('./handshake');
const { Version, CipherSuite, ExtensionType, HandshakeType, NamedGroup } = require('./constants');

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
      let reqBuf = Buffer.alloc(0);
      let processing = false;

      const processRequest = () => {
        if (processing) return;
        // Find end of HTTP headers
        const headerEnd = reqBuf.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;

        const headerStr = reqBuf.slice(0, headerEnd).toString();
        const lines = headerStr.split('\r\n');
        const method = (lines[0] || '').split(' ')[0];

        // Check for Content-Length to read body
        const clMatch = headerStr.match(/content-length:\s*(\d+)/i);
        const contentLength = clMatch ? parseInt(clMatch[1]) : 0;
        const bodyStart = headerEnd + 4;
        const totalNeeded = bodyStart + contentLength;

        if (reqBuf.length < totalNeeded) return; // wait for more data

        processing = true;
        const body = reqBuf.slice(bodyStart, totalNeeded);
        reqBuf = reqBuf.slice(totalNeeded); // keep remainder for pipelining

        let responseBody;
        if (method === 'POST' || method === 'PUT') {
          responseBody = body; // echo the payload
        } else if (method === 'HEAD') {
          responseBody = Buffer.alloc(0);
        } else {
          responseBody = Buffer.from('OK');
        }

        try {
          const header = `HTTP/1.1 200 OK\r\nContent-Length: ${responseBody.length}\r\nConnection: keep-alive\r\n\r\n`;
          socket.write(header);
          if (responseBody.length > 0) socket.write(responseBody);
        } catch (_) {}

        processing = false;
        // Process next pipelined request if any
        if (reqBuf.length > 0) setImmediate(processRequest);
      };

      socket.on('data', (data) => {
        reqBuf = Buffer.concat([reqBuf, data]);
        processRequest();
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

    this._server.on('stream', (stream, headers) => {
      const method = headers[':method'] || 'GET';
      let body = Buffer.alloc(0);

      if (method === 'POST' || method === 'PUT') {
        stream.on('data', (chunk) => { body = Buffer.concat([body, chunk]); });
        stream.on('end', () => {
          try {
            stream.respond({ ':status': 200, 'content-type': 'application/octet-stream' });
            stream.end(body); // echo payload
          } catch (_) {}
        });
      } else {
        try {
          stream.respond({ ':status': 200, 'content-type': 'text/plain' });
          stream.end('OK');
        } catch (_) {}
      }
      stream.on('error', () => {});
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
    let listenPort = this.port;
    if (listenPort === 0) listenPort = 40000 + Math.floor(Math.random() * 20000);
    this._actualPort = listenPort;

    // Use a Node.js dgram-based QUIC responder instead of openssl s_server -quic
    // (OpenSSL s_server doesn't support -quic in most builds).
    // This responds to QUIC Initial packets with a proper protected Initial
    // containing a ServerHello, which is enough for client-side fuzz testing.
    this._quicSocket = dgram.createSocket('udp4');

    this._quicSocket.on('message', (msg, rinfo) => {
      if (msg.length < 5) return;
      const firstByte = msg[0];
      const isLong = (firstByte & 0x80) !== 0;
      if (!isLong) return; // ignore short header packets

      const version = msg.readUInt32BE(1);

      // Version 0 → respond with Version Negotiation
      if (version === 0x00000000 || version === 0x0a0a0a0a) {
        this._sendVersionNegotiation(msg, rinfo);
        return;
      }

      const pktType = (firstByte & 0x30) >> 4;
      // Only respond to Initial packets (type 0)
      if (pktType !== 0) return;

      // Parse DCID and SCID from the incoming packet
      const dcidLen = msg[5];
      const dcid = msg.slice(6, 6 + dcidLen);
      const scidLen = msg[6 + dcidLen];
      const scid = msg.slice(7 + dcidLen, 7 + dcidLen + scidLen);

      // Send a protected Initial with a ServerHello back
      this._sendServerInitial(dcid, scid, version, rinfo);
    });

    this._quicSocket.on('error', (err) => {
      if (this.logger) this.logger.info(`[quic-server] Socket error: ${err.message}`);
    });

    await new Promise((resolve, reject) => {
      this._quicSocket.bind(listenPort, '0.0.0.0', () => {
        if (this.logger) this.logger.info(`[local-server] Node QUIC server listening on UDP port ${this._actualPort}`);
        resolve();
      });
      this._quicSocket.once('error', reject);
    });
  }

  _sendVersionNegotiation(msg, rinfo) {
    // Parse DCID/SCID from incoming packet — swap them for response
    const dcidLen = msg[5];
    const clientDcid = msg.slice(6, 6 + dcidLen);
    const scidLen = msg[6 + dcidLen];
    const clientScid = msg.slice(7 + dcidLen, 7 + dcidLen + scidLen);

    // Version Negotiation: version=0, DCID=client's SCID, SCID=client's DCID
    const firstByte = Buffer.from([0x80 | (crypto.randomBytes(1)[0] & 0x7f)]);
    const versionZero = Buffer.alloc(4, 0);
    const respDcidLen = Buffer.from([clientScid.length]);
    const respScidLen = Buffer.from([clientDcid.length]);
    // Supported versions
    const v1 = Buffer.alloc(4); v1.writeUInt32BE(0x00000001, 0);
    const v2 = Buffer.alloc(4); v2.writeUInt32BE(0x6b3343cf, 0);

    const packet = Buffer.concat([
      firstByte, versionZero, respDcidLen, clientScid, respScidLen, clientDcid, v1, v2,
    ]);

    this._quicSocket.send(packet, rinfo.port, rinfo.address, () => {});
  }

  _sendServerInitial(clientDcid, clientScid, version, rinfo) {
    // Build a minimal ServerHello inside a protected QUIC Initial packet.
    // DCID = client's SCID, SCID = new random ID (our server CID).
    const serverScid = crypto.randomBytes(8);

    // Build ServerHello body (TLS 1.3)
    const serverRandom = crypto.randomBytes(32);
    const sessionId = Buffer.alloc(0);
    const selectedCipher = CipherSuite.TLS_AES_128_GCM_SHA256;

    const shBody = Buffer.concat([
      Buffer.from([0x03, 0x03]),          // legacy_version TLS 1.2
      serverRandom,
      Buffer.from([sessionId.length]),    // session_id_length
      sessionId,
      Buffer.from([selectedCipher >> 8, selectedCipher & 0xff]),
      Buffer.from([0x00]),                // compression_method: null
      // Extensions
      (() => {
        const exts = [];
        // supported_versions: TLS 1.3
        const svData = Buffer.from([0x03, 0x04]);
        const svExt = Buffer.concat([
          Buffer.from([0x00, 0x2b, 0x00, svData.length]),
          svData,
        ]);
        exts.push(svExt);
        // key_share: X25519 with dummy public key
        const ksPublic = crypto.randomBytes(32);
        const ksData = Buffer.concat([
          Buffer.from([0x00, 0x1d]),         // X25519
          Buffer.from([0x00, ksPublic.length]),
          ksPublic,
        ]);
        const ksExt = Buffer.concat([
          Buffer.from([0x00, 0x33, ksData.length >> 8, ksData.length & 0xff]),
          ksData,
        ]);
        exts.push(ksExt);
        const allExts = Buffer.concat(exts);
        return Buffer.concat([
          Buffer.from([allExts.length >> 8, allExts.length & 0xff]),
          allExts,
        ]);
      })(),
    ]);

    // TLS handshake message: type(1) + length(3) + body
    const shMsg = Buffer.concat([
      Buffer.from([HandshakeType.SERVER_HELLO]),
      Buffer.from([0x00, (shBody.length >> 8) & 0xff, shBody.length & 0xff]),
      shBody,
    ]);

    // CRYPTO frame: type(0x06) + offset(varint) + length(varint) + data
    const cryptoFrame = Buffer.concat([
      Buffer.from([0x06]),
      encodeVarInt(0),
      encodeVarInt(shMsg.length),
      shMsg,
    ]);

    const pn = 0;
    const pnLen = 2;
    const pnBuf = Buffer.alloc(pnLen);
    pnBuf.writeUInt16BE(pn & 0xffff, 0);

    // Response DCID = client's SCID, response SCID = our server CID
    const firstByte = Buffer.from([0x80 | 0x40 | (0 << 4) | (pnLen - 1)]);
    const versionBuf = Buffer.alloc(4);
    versionBuf.writeUInt32BE(version, 0);
    const dcidLenBuf = Buffer.from([clientScid.length]);
    const scidLenBuf = Buffer.from([serverScid.length]);
    const tokenLen = encodeVarInt(0);

    const headerPrefix = Buffer.concat([
      firstByte, versionBuf, dcidLenBuf, clientScid, scidLenBuf, serverScid, tokenLen,
    ]);

    // Pad payload so the total packet is reasonable (no need for 1200 min on server response)
    const payloadLen = pnLen + cryptoFrame.length + 16;
    const payloadLenEnc = encodeVarInt(payloadLen);

    const header = Buffer.concat([headerPrefix, payloadLenEnc, pnBuf]);

    // Derive server-side Initial keys from the client's original DCID
    const keys = this._deriveServerInitialKeys(clientDcid, version);
    const packet = protectPacket(header, cryptoFrame, pn, pnLen, keys);

    this._quicSocket.send(packet, rinfo.port, rinfo.address, () => {});
  }

  _deriveServerInitialKeys(dcid, version) {
    // Server Initial keys are derived from the same initial secret but using 'server in' label
    const QUIC_V1_SALT = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');
    const QUIC_V2_SALT = Buffer.from('0dede3def700a6db819381be6e269dcbf9bd2ed9', 'hex');
    const salt = (version === 0x6b3343cf) ? QUIC_V2_SALT : QUIC_V1_SALT;
    const initialSecret = crypto.createHmac('sha256', salt).update(dcid).digest();
    const emptyCtx = Buffer.alloc(0);
    const serverSecret = this._hkdfExpandLabel(initialSecret, 'server in', emptyCtx, 32);
    const key = this._hkdfExpandLabel(serverSecret, 'quic key', emptyCtx, 16);
    const iv  = this._hkdfExpandLabel(serverSecret, 'quic iv',  emptyCtx, 12);
    const hp  = this._hkdfExpandLabel(serverSecret, 'quic hp',  emptyCtx, 16);
    return { key, iv, hp };
  }

  _hkdfExpandLabel(prk, label, context, len) {
    const tlsLabel = Buffer.from('tls13 ' + label, 'ascii');
    const hkdfLabel = Buffer.concat([
      Buffer.from([0, len]),
      Buffer.from([tlsLabel.length]),
      tlsLabel,
      Buffer.from([context.length]),
      context,
    ]);
    const t1 = crypto.createHmac('sha256', prk).update(Buffer.concat([hkdfLabel, Buffer.from([1])])).digest();
    return t1.slice(0, len);
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
    if (this._quicSocket) {
      try { this._quicSocket.close(); } catch (_) {}
      this._quicSocket = null;
    }
  }
}

module.exports = { WellBehavedServer };
