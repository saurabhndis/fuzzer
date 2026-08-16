const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const dgram = require('dgram');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { generateServerCert } = require('./cert-gen');
const { deriveInitialKeys, protectPacket, encodeVarInt } = require('./quic-packet');
const hs = require('./handshake');
const { buildAlert } = require('./record');
const { Version, CipherSuite, ExtensionType, HandshakeType, NamedGroup, AlertLevel, AlertDescription } = require('./constants');

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = (b64.match(/.{1,64}/g) || []).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

// This server hands the group list to Node's own TLS stack, so it must ask
// that stack what it supports rather than the `openssl` binary on PATH —
// under Electron the two disagree. See lib/tls-groups.js.
const { getNodeTlsGroups } = require('./tls-groups');

function errorToAlertDescription(err) {
  const msg = (err.message || err.code || '').toLowerCase();
  if (msg.includes('bad record mac') || msg.includes('decryption failed'))
    return AlertDescription.BAD_RECORD_MAC;
  if (msg.includes('record overflow') || msg.includes('record too long') || msg.includes('packet length too long'))
    return AlertDescription.RECORD_OVERFLOW;
  if (msg.includes('unexpected message') || msg.includes('wrong message') || msg.includes('unexpected_message') || msg.includes('bad record type'))
    return AlertDescription.UNEXPECTED_MESSAGE;
  if (msg.includes('no shared cipher') || msg.includes('no ciphers'))
    return AlertDescription.HANDSHAKE_FAILURE;
  if (msg.includes('wrong version') || msg.includes('unsupported protocol') || msg.includes('version too'))
    return AlertDescription.PROTOCOL_VERSION;
  if (msg.includes('decode') || msg.includes('parse'))
    return AlertDescription.DECODE_ERROR;
  if (msg.includes('certificate'))
    return AlertDescription.BAD_CERTIFICATE;
  return AlertDescription.HANDSHAKE_FAILURE;
}

class WellBehavedServer {
  constructor(opts = {}) {
    this.port = opts.port || 0;
    this.hostname = opts.hostname || 'localhost';
    this.logger = opts.logger || null;
    this._server = null; // for Node APIs
    this._quicProcess = null; // for QUIC CLI
    this._actualPort = null;
    this.activeSockets = new Set();
    this._maxIdleMs = opts.maxIdleMs || 10000;
    this._maxVersion = opts.maxVersion || undefined;  // e.g. 'TLSv1.2'
    this._ciphers = opts.ciphers || undefined;         // OpenSSL cipher string

    const gen = generateServerCert(this.hostname);
    this.privateKeyPEM = gen.privateKeyPEM;
    this.certPEM = derToPem(gen.certDER);
  }

  get actualPort() { return this._actualPort; }

  /**
   * Periodically destroy stale sockets to prevent FD accumulation.
   * Started automatically by startTLS/startH2/startQuic.
   */
  _startCleanupTimer() {
    if (this._cleanupTimer) return;
    this._cleanupTimer = setInterval(() => {
      for (const socket of this.activeSockets) {
        if (socket.destroyed) {
          this.activeSockets.delete(socket);
        }
      }
    }, 5000);
    this._cleanupTimer.unref(); // Don't keep process alive
  }

  async startTLS() {
    // Node.js (v20+ with OpenSSL 3.2+) supports PQC named groups natively
    // via the ecdhCurve option. No need for an external openssl s_server
    // process — the Node TLS server handles PQC ClientHellos and also
    // provides full HTTP request/response support (POST, HEAD, keep-alive).
    const pqcGroups = getNodeTlsGroups();

    const secureContext = tls.createSecureContext({
      key: this.privateKeyPEM,
      cert: this.certPEM,
      ...(pqcGroups && { ecdhCurve: pqcGroups }),
      ...(this._maxVersion && { maxVersion: this._maxVersion }),
      ...(this._ciphers && { ciphers: this._ciphers }),
    });

    // Use net.createServer + manual tls.TLSSocket wrapping instead of tls.createServer.
    // This gives us control over the raw TCP socket so we can write TLS alert records
    // before closing — Node.js tls.createServer often sends FIN before alerts arrive,
    // causing fuzzer clients to see "Connection closed" instead of proper TLS alerts.
    this._server = net.createServer({ allowHalfOpen: true });

    this._server.on('connection', (rawSocket) => {
      const remote = `${rawSocket.remoteAddress}:${rawSocket.remotePort}`;
      // if (this.logger) this.logger.info(`[local-server] New TCP connection from ${remote}`);
      this.activeSockets.add(rawSocket);
      rawSocket.setNoDelay(true);
      rawSocket.on('error', () => {});

      // Override rawSocket.destroy to delay when an alert is being flushed,
      // preventing the TLS socket's internal cleanup from closing the FD
      // before alert bytes reach the kernel send buffer.
      const origDestroy = rawSocket.destroy.bind(rawSocket);
      rawSocket.destroy = function delayedDestroy(err) {
        if (rawSocket._alertFlushing) {
          setTimeout(() => origDestroy(err), 50);
        } else {
          origDestroy(err);
        }
      };

      // Auto-close idle connections to prevent FD accumulation during batch runs
      rawSocket.setTimeout(10000, () => {
        if (!rawSocket.destroyed) rawSocket.destroy();
      });

      const tlsSocket = new tls.TLSSocket(rawSocket, {
        isServer: true,
        secureContext,
        rejectUnauthorized: false,
      });
      this.activeSockets.add(tlsSocket);
      
      // Ensure data flows into the TLSSocket immediately
      rawSocket.resume();

      // Dummy listener to pull data through the TLS state machine
      tlsSocket.on('data', () => {});

      const cleanup = () => {
        this.activeSockets.delete(tlsSocket);
        this.activeSockets.delete(rawSocket);
      };
      rawSocket.on('close', cleanup);

      // Handshake timeout — if 'secure' hasn't fired within 5s the client
      // is stalled, fuzzing, or sent a malformed record that left Node's TLS
      // parser waiting for bytes that will never arrive. Send a fatal alert
      // and close so the fuzzer client sees DROPPED rather than TIMEOUT.
      const hsTimer = setTimeout(() => {
        if (rawSocket.writable && !rawSocket.destroyed) {
          const alert = buildAlert(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
          rawSocket._alertFlushing = true;
          try {
            rawSocket.write(alert, () => {
              // Final safety: if alert is still in kernel, give it a tiny bit longer
              setImmediate(() => { if (!rawSocket.destroyed) origDestroy(); });
            });
          } catch (_) {
            if (!rawSocket.destroyed) origDestroy();
          }
          if (this.logger) this.logger.info('[local-server] Handshake timeout — sent fatal alert');
        }
        cleanup();
      }, 5000);

      const clearTimer = () => clearTimeout(hsTimer);

      // Send a TLS alert on the raw socket before closing.
      // Covers both pre-handshake and post-handshake errors uniformly.
      tlsSocket.on('error', (err) => {
        clearTimer();
        if (rawSocket.writable && !rawSocket.destroyed) {
          const alertDesc = errorToAlertDescription(err);
          const alert = buildAlert(AlertLevel.FATAL, alertDesc);
          rawSocket._alertFlushing = true;
          try {
            rawSocket.write(alert, () => {
              setImmediate(() => {
                if (!rawSocket.destroyed) origDestroy();
              });
            });
          } catch (_) {
            if (!rawSocket.destroyed) origDestroy();
          }
          if (this.logger) {
            this.logger.info(`[local-server] TLS error: ${err.message} (sent alert)`);
          }
        }
        cleanup();
      });

      // Successful TLS handshake — serve HTTP requests
      tlsSocket.on('secure', () => {
        clearTimer();
        // if (this.logger) this.logger.info(`[local-server] TLS handshake secure with ${remote}`);
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
          const connectionClose = /connection:\s*close/i.test(headerStr);

          const bodyStart = headerEnd + 4;
          const isChunked = /transfer-encoding:\s*chunked/i.test(headerStr);

          let body;
          if (isChunked) {
            // Parse chunked Transfer-Encoding: sequence of size\r\ndata\r\n ending with 0\r\n\r\n
            const terminator = reqBuf.indexOf('\r\n0\r\n\r\n', bodyStart);
            // Also accept the simpler form: 0\r\n\r\n at the start of a line
            const terminator2 = reqBuf.indexOf('\r\n0\r\n', bodyStart);
            const endIdx = terminator !== -1 ? terminator : terminator2;
            if (endIdx === -1) return; // wait for final chunk
            // Reassemble chunks
            const chunks = [];
            let off = bodyStart;
            const raw = reqBuf;
            while (off < raw.length) {
              const lineEnd = raw.indexOf('\r\n', off);
              if (lineEnd === -1) break;
              const sizeStr = raw.slice(off, lineEnd).toString().trim();
              const chunkSize = parseInt(sizeStr, 16);
              if (isNaN(chunkSize) || chunkSize === 0) { off = lineEnd + 2; break; }
              off = lineEnd + 2;
              if (off + chunkSize > raw.length) return; // wait for more chunk data
              chunks.push(raw.slice(off, off + chunkSize));
              off += chunkSize + 2; // skip trailing \r\n
            }
            body = Buffer.concat(chunks);
            // Skip past the 0\r\n\r\n terminator
            const afterTerminator = terminator !== -1 ? terminator + 7 : terminator2 + 5;
            reqBuf = reqBuf.slice(afterTerminator);
          } else {
            const clMatch = headerStr.match(/content-length:\s*(\d+)/i);
            const contentLength = clMatch ? parseInt(clMatch[1]) : 0;
            const totalNeeded = bodyStart + contentLength;
            if (reqBuf.length < totalNeeded) return; // wait for more data
            body = reqBuf.slice(bodyStart, totalNeeded);
            reqBuf = reqBuf.slice(totalNeeded); // keep remainder for pipelining
          }

          processing = true;

          let responseBody;
          if (method === 'POST' || method === 'PUT') {
            responseBody = body; // echo the payload
          } else if (method === 'HEAD') {
            responseBody = Buffer.alloc(0);
          } else {
            // GET: check for ?size=N to return a specific number of bytes
            const rawPath = '/';
            responseBody = Buffer.from('OK');
          }

          try {
            const connHeader = connectionClose ? 'close' : 'keep-alive';
            const header = `HTTP/1.1 200 OK\r\nContent-Length: ${responseBody.length}\r\nConnection: ${connHeader}\r\n\r\n`;
            tlsSocket.write(header);
            if (responseBody.length > 0) tlsSocket.write(responseBody);
            if (connectionClose) {
              tlsSocket.end();
            }
          } catch (_) {}

          processing = false;
          // Process next pipelined request if any
          if (reqBuf.length > 0) setImmediate(processRequest);
        };

        tlsSocket.on('data', (data) => {
          reqBuf = Buffer.concat([reqBuf, data]);
          processRequest();
        });
      });
    });

    this._server.on('error', () => {});

    return new Promise((resolve, reject) => {
      this._server.listen(this.port, '::', () => {
        this._actualPort = this._server.address().port;
        this._startCleanupTimer();
        if (this.logger) this.logger.info(`[local-server] Node TLS server listening on port ${this._actualPort}`);
        resolve();
      });
      this._server.once('error', reject);
    });
  }

  async startH2() {
    this._server = http2.createServer({
      allowHTTP1: true,
    });

    this._server.on('session', (session) => {
      this.activeSockets.add(session);
      session.on('close', () => this.activeSockets.delete(session));
      session.on('error', () => this.activeSockets.delete(session));
      session.on('error', () => {});
    });

    this._server.on('stream', (stream, headers) => {
      this.activeSockets.add(stream);
      stream.on('close', () => this.activeSockets.delete(stream));
      stream.on('error', () => this.activeSockets.delete(stream));

      const method = headers[':method'] || 'GET';
      const rawPath = headers[':path'] || '/';
      let body = Buffer.alloc(0);

      if (method === 'POST' || method === 'PUT') {
        stream.on('data', (chunk) => { body = Buffer.concat([body, chunk]); });
        stream.on('end', () => {
          try {
            stream.respond({ ':status': '200', 'content-type': 'application/octet-stream' });
            stream.end(body); // echo payload
          } catch (_) {}
        });
      } else {
        // GET: check for ?size=N to return a specific number of bytes
        let responseBody = Buffer.from('OK');
        try {
          const qIdx = rawPath.indexOf('?');
          if (qIdx !== -1) {
            const params = new URLSearchParams(rawPath.slice(qIdx + 1));
            const size = parseInt(params.get('size') || '0', 10);
            if (size > 0) responseBody = Buffer.alloc(size, 0x42);
          }
        } catch (_) {}
        try {
          stream.respond({ ':status': '200', 'content-type': 'application/octet-stream' });
          stream.end(responseBody);
        } catch (_) {}
      }
      stream.on('error', () => {});
    });

    this._server.on('session', (session) => {
      session.on('error', () => {});
    });

    this._server.on('error', () => {});

    return new Promise((resolve, reject) => {
      this._server.listen(this.port, '::', () => {
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
      this.activeSockets.add(socket);
      socket.on('close', () => this.activeSockets.delete(socket));
      socket.on('error', () => this.activeSockets.delete(socket));

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
      this._server.listen(this.port, '::', () => {
        this._actualPort = this._server.address().port;
        if (this.logger) this.logger.info(`[local-server] Node TCP server listening on port ${this._actualPort}`);
        resolve();
      });
      this._server.once('error', reject);
    });
  }

  // NOTE: startTLS() above uses Node's native TLS stack (Node 20+ / OpenSSL 3.2+
  // negotiates PQC groups via ecdhCurve), so no external `openssl s_server` is
  // spawned here. For an OpenSSL-binary counterpart (verdict baselining), see
  // lib/openssl-peer.js (socat OPENSSL-LISTEN echo server) used by
  // run-tls-openssl-compare.js.

  async startQuic() {
    let quicheLib;
    try {
      quicheLib = require('@currentspace/http3');
    } catch (e) {
      console.error('\n[FATAL] The @currentspace/http3 native module is required for QUIC server but could not be loaded.');
      console.error(`Error details: ${e.message}\n`);
      process.exit(1);
    }

    this._quicServer = quicheLib.createSecureServer({
      key: this.privateKeyPEM,
      cert: this.certPEM,
      initialMaxStreamsBidi: 10000,
      initialMaxData: 100_000_000,
      initialMaxStreamDataBidiLocal: 10_000_000,
      maxIdleTimeoutMs: 30000,
    });

    this._quicServer.on('session', (session) => {
      this.activeSockets.add(session);
      session.on('close', () => this.activeSockets.delete(session));
      session.on('error', () => this.activeSockets.delete(session));

      if (this.logger) {
        const remote = session.remoteAddress ? `${session.remoteAddress}:${session.remotePort}` : 'unknown';
        this.logger.info(`[local-server] HTTP/3 client connected: ${remote}`);
      }
      session.on('error', () => {});
    });

    this._quicServer.on('stream', (stream, headers) => {
      this.activeSockets.add(stream);
      stream.on('close', () => this.activeSockets.delete(stream));
      stream.on('error', () => this.activeSockets.delete(stream));

      const method = headers[':method'] || 'GET';
      const rawPath = headers[':path'] || '/';
      let body = Buffer.alloc(0);

      if (method === 'POST' || method === 'PUT') {
        stream.on('data', (chunk) => { body = Buffer.concat([body, chunk]); });
        stream.on('end', () => {
          try {
            stream.respond({ ':status': '200', 'content-type': 'application/octet-stream' });
            stream.end(body); // echo payload
          } catch (_) {}
        });
      } else {
        // GET: check for ?size=N to return a specific number of bytes
        let responseBody = Buffer.from('OK');
        try {
          const qIdx = rawPath.indexOf('?');
          if (qIdx !== -1) {
            const params = new URLSearchParams(rawPath.slice(qIdx + 1));
            const size = parseInt(params.get('size') || '0', 10);
            if (size > 0) responseBody = Buffer.alloc(size, 0x42);
          }
        } catch (_) {}
        try {
          stream.respond({ ':status': '200', 'content-type': 'application/octet-stream' });
          stream.end(responseBody);
        } catch (_) {}
      }
      stream.on('error', () => {});
    });

    this._quicServer.on('error', () => {});

    let listenPort = this.port;
    if (listenPort === 0) listenPort = 40000 + Math.floor(Math.random() * 20000);

    const bindAddr = (this.hostname === 'localhost' || this.hostname === '::1') ? '::' : this.hostname;
    await this._quicServer.listen(listenPort, bindAddr);
    this._actualPort = listenPort;
    if (this.logger) this.logger.info(`[local-server] HTTP/3 server listening on UDP ${bindAddr}:${this._actualPort} (quiche)`);
  }

  async _startQuicRaw() {
    // Fallback: raw UDP QUIC responder for when quiche is not installed.
    // Responds to QUIC Initial packets with a protected ServerHello.
    let listenPort = this.port;
    if (listenPort === 0) listenPort = 40000 + Math.floor(Math.random() * 20000);
    this._actualPort = listenPort;

    const isIPv6 = this.hostname.includes(':') || this.hostname === 'localhost' || this.hostname === '::1';
    const type = isIPv6 ? 'udp6' : 'udp4';
    this._quicSocket = dgram.createSocket({ type, ipv6Only: false });

    this._quicSocket.on('message', (msg, rinfo) => {
      if (msg.length < 5) return;
      const firstByte = msg[0];
      const isLong = (firstByte & 0x80) !== 0;
      if (!isLong) return;

      const version = msg.readUInt32BE(1);

      if (version === 0x00000000 || version === 0x0a0a0a0a) {
        this._sendVersionNegotiation(msg, rinfo);
        return;
      }

      const pktType = (firstByte & 0x30) >> 4;
      if (pktType !== 0) return;

      const dcidLen = msg[5];
      const dcid = msg.slice(6, 6 + dcidLen);
      const scidLen = msg[6 + dcidLen];
      const scid = msg.slice(7 + dcidLen, 7 + dcidLen + scidLen);

      this._sendServerInitial(dcid, scid, version, rinfo);
    });

    this._quicSocket.on('error', (err) => {
      if (this.logger) this.logger.info(`[quic-server] Socket error: ${err.message}`);
    });

    await new Promise((resolve, reject) => {
      const bindAddr = (this.hostname === 'localhost' || this.hostname === '::1') ? '::' : this.hostname;
      this._quicSocket.bind(listenPort, bindAddr, () => {
        if (this.logger) this.logger.info(`[local-server] Node QUIC server listening on UDP ${bindAddr}:${this._actualPort} (raw fallback)`);
        resolve();
      });
      this._quicSocket.once('error', reject);
    });
  }

  _sendVersionNegotiation(msg, rinfo) {
    const dcidLen = msg[5];
    const clientDcid = msg.slice(6, 6 + dcidLen);
    const scidLen = msg[6 + dcidLen];
    const clientScid = msg.slice(7 + dcidLen, 7 + dcidLen + scidLen);

    const firstByte = Buffer.from([0x80 | (crypto.randomBytes(1)[0] & 0x7f)]);
    const versionZero = Buffer.alloc(4, 0);
    const respDcidLen = Buffer.from([clientScid.length]);
    const respScidLen = Buffer.from([clientDcid.length]);
    const v1 = Buffer.alloc(4); v1.writeUInt32BE(0x00000001, 0);
    const v2 = Buffer.alloc(4); v2.writeUInt32BE(0x6b3343cf, 0);

    const packet = Buffer.concat([
      firstByte, versionZero, respDcidLen, clientScid, respScidLen, clientDcid, v1, v2,
    ]);

    this._quicSocket.send(packet, rinfo.port, rinfo.address, () => {});
  }

  _sendServerInitial(clientDcid, clientScid, version, rinfo) {
    const serverScid = crypto.randomBytes(8);

    const serverRandom = crypto.randomBytes(32);
    const sessionId = Buffer.alloc(0);
    const selectedCipher = CipherSuite.TLS_AES_128_GCM_SHA256;

    const shBody = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      serverRandom,
      Buffer.from([sessionId.length]),
      sessionId,
      Buffer.from([selectedCipher >> 8, selectedCipher & 0xff]),
      Buffer.from([0x00]),
      (() => {
        const exts = [];
        const svData = Buffer.from([0x03, 0x04]);
        const svExt = Buffer.concat([
          Buffer.from([0x00, 0x2b, 0x00, svData.length]),
          svData,
        ]);
        exts.push(svExt);
        const ksPublic = crypto.randomBytes(32);
        const ksData = Buffer.concat([
          Buffer.from([0x00, 0x1d]),
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

    const shMsg = Buffer.concat([
      Buffer.from([HandshakeType.SERVER_HELLO]),
      Buffer.from([0x00, (shBody.length >> 8) & 0xff, shBody.length & 0xff]),
      shBody,
    ]);

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

    // QUICv2 (RFC 9369) remaps Initial to type 0b01; QUICv1 uses 0b00
    const packetType = (version === 0x6b3343cf) ? 1 : 0;
    const firstByte = Buffer.from([0x80 | 0x40 | (packetType << 4) | (pnLen - 1)]);
    const versionBuf = Buffer.alloc(4);
    versionBuf.writeUInt32BE(version, 0);
    const dcidLenBuf = Buffer.from([clientScid.length]);
    const scidLenBuf = Buffer.from([serverScid.length]);
    const tokenLen = encodeVarInt(0);

    const headerPrefix = Buffer.concat([
      firstByte, versionBuf, dcidLenBuf, clientScid, scidLenBuf, serverScid, tokenLen,
    ]);

    const payloadLen = pnLen + cryptoFrame.length + 16;
    const payloadLenEnc = encodeVarInt(payloadLen);

    const header = Buffer.concat([headerPrefix, payloadLenEnc, pnBuf]);

    const keys = this._deriveServerInitialKeys(clientDcid, version);
    const packet = protectPacket(header, cryptoFrame, pn, pnLen, keys);

    this._quicSocket.send(packet, rinfo.port, rinfo.address, () => {});
  }

  _deriveServerInitialKeys(dcid, version) {
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
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer);
      this._cleanupTimer = null;
    }
    if (this._server) {
      try { this._server.close(); } catch (_) {}
      this._server = null;
    }
    for (const socket of this.activeSockets) {
      try { socket.destroy(); } catch (_) {}
    }
    this.activeSockets.clear();

    if (this._quicServer) {
      try { this._quicServer.close(); } catch (_) {}
      this._quicServer = null;
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
