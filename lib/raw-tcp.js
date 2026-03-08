// Raw TCP Socket — full TCP stack using raw sockets for TCP-level fuzzing
// Linux only — requires CAP_NET_RAW capability
// Graceful fallback: isRawAvailable() returns false on unsupported platforms

const EventEmitter = require('events');
const net = require('net');
const { TCPFlags } = require('./constants');

// ── Capability detection ──────────────────────────────────────────────────────

let rawSocketAvailable = false;
let raw = null;

try {
  raw = require('raw-socket');
  // Test if we can actually create a raw socket (needs CAP_NET_RAW on Linux)
  const test = raw.createSocket({
    protocol: raw.Protocol.TCP,
    addressFamily: raw.AddressFamily.IPv4,
  });
  test.close();
  rawSocketAvailable = true;
} catch (_) {
  rawSocketAvailable = false;
}

function isRawAvailable() {
  return rawSocketAvailable;
}

// ── IP / TCP header construction ──────────────────────────────────────────────

function ipToBuffer(ip) {
  const parts = ip.split('.').map(Number);
  return Buffer.from(parts);
}

function computeChecksum(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length - 1; i += 2) {
    sum += buf.readUInt16BE(i);
  }
  if (buf.length % 2 === 1) {
    sum += buf[buf.length - 1] << 8;
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function buildIPHeader(srcIP, dstIP, payloadLength, id) {
  const totalLength = 20 + payloadLength;
  const buf = Buffer.alloc(20);
  buf[0] = 0x45;  // version 4, IHL 5
  buf[1] = 0x00;  // DSCP/ECN
  buf.writeUInt16BE(totalLength, 2);
  buf.writeUInt16BE(id & 0xffff, 4);
  buf.writeUInt16BE(0x4000, 6);  // Don't Fragment
  buf[8] = 64;    // TTL
  buf[9] = 6;     // protocol: TCP

  const src = ipToBuffer(srcIP);
  const dst = ipToBuffer(dstIP);
  src.copy(buf, 12);
  dst.copy(buf, 16);

  buf.writeUInt16BE(computeChecksum(buf), 10);
  return buf;
}

// ── TCP Options ──────────────────────────────────────────────────────────────

const TCP_OPT = {
  EOL: 0,
  NOP: 1,
  MSS: 2,
  WINDOW_SCALE: 3,
  SACK_PERMITTED: 4,
  SACK: 5,
  TIMESTAMP: 8,
};

/**
 * Build a TCP options buffer from an array of option descriptors.
 * Each option: { kind, data?: Buffer }
 * Options are padded to 4-byte alignment with NOP/EOL.
 */
function buildTCPOptions(options) {
  if (!options || options.length === 0) return Buffer.alloc(0);
  const parts = [];
  for (const opt of options) {
    if (opt.kind === TCP_OPT.NOP) {
      parts.push(Buffer.from([TCP_OPT.NOP]));
    } else if (opt.kind === TCP_OPT.EOL) {
      parts.push(Buffer.from([TCP_OPT.EOL]));
    } else if (opt.kind === TCP_OPT.MSS) {
      const b = Buffer.alloc(4);
      b[0] = TCP_OPT.MSS; b[1] = 4;
      b.writeUInt16BE(opt.value || 1460, 2);
      parts.push(b);
    } else if (opt.kind === TCP_OPT.WINDOW_SCALE) {
      parts.push(Buffer.from([TCP_OPT.WINDOW_SCALE, 3, opt.value || 7]));
    } else if (opt.kind === TCP_OPT.SACK_PERMITTED) {
      parts.push(Buffer.from([TCP_OPT.SACK_PERMITTED, 2]));
    } else if (opt.kind === TCP_OPT.TIMESTAMP) {
      const b = Buffer.alloc(10);
      b[0] = TCP_OPT.TIMESTAMP; b[1] = 10;
      b.writeUInt32BE((opt.tsval || 0) >>> 0, 2);
      b.writeUInt32BE((opt.tsecr || 0) >>> 0, 6);
      parts.push(b);
    } else if (opt.data) {
      const hdr = Buffer.from([opt.kind, 2 + opt.data.length]);
      parts.push(Buffer.concat([hdr, opt.data]));
    }
  }
  let combined = Buffer.concat(parts);
  // Pad to 4-byte boundary
  const remainder = combined.length % 4;
  if (remainder !== 0) {
    combined = Buffer.concat([combined, Buffer.alloc(4 - remainder)]);
  }
  return combined;
}

/**
 * Parse TCP options from a received TCP header.
 * Returns an object with parsed option values.
 */
function parseTCPOptions(tcpHeader, dataOffset) {
  const result = { mss: null, windowScale: null, sackPermitted: false, timestamp: null };
  const optionsStart = 20;
  if (dataOffset <= optionsStart) return result;
  let i = optionsStart;
  while (i < dataOffset && i < tcpHeader.length) {
    const kind = tcpHeader[i];
    if (kind === TCP_OPT.EOL) break;
    if (kind === TCP_OPT.NOP) { i++; continue; }
    if (i + 1 >= tcpHeader.length) break;
    const len = tcpHeader[i + 1];
    if (len < 2 || i + len > tcpHeader.length) break;
    if (kind === TCP_OPT.MSS && len === 4) {
      result.mss = tcpHeader.readUInt16BE(i + 2);
    } else if (kind === TCP_OPT.WINDOW_SCALE && len === 3) {
      result.windowScale = tcpHeader[i + 2];
    } else if (kind === TCP_OPT.SACK_PERMITTED && len === 2) {
      result.sackPermitted = true;
    } else if (kind === TCP_OPT.TIMESTAMP && len === 10) {
      result.timestamp = {
        tsval: tcpHeader.readUInt32BE(i + 2),
        tsecr: tcpHeader.readUInt32BE(i + 6),
      };
    }
    i += len;
  }
  return result;
}

function buildTCPHeader(srcPort, dstPort, seq, ack, flags, window, urgentPointer, payload, options) {
  const optionsBuf = options || Buffer.alloc(0);
  const headerLen = 20 + optionsBuf.length;
  const buf = Buffer.alloc(headerLen);

  buf.writeUInt16BE(srcPort, 0);
  buf.writeUInt16BE(dstPort, 2);
  buf.writeUInt32BE(seq >>> 0, 4);
  buf.writeUInt32BE(ack >>> 0, 8);
  buf[12] = ((headerLen / 4) & 0x0f) << 4;  // data offset
  buf[13] = flags & 0xff;
  buf.writeUInt16BE(window & 0xffff, 14);
  buf.writeUInt16BE(urgentPointer & 0xffff, 18);

  if (optionsBuf.length > 0) optionsBuf.copy(buf, 20);

  return buf;
}

function computeTCPChecksum(srcIP, dstIP, tcpHeader, payload) {
  const src = ipToBuffer(srcIP);
  const dst = ipToBuffer(dstIP);
  const tcpLen = tcpHeader.length + (payload ? payload.length : 0);

  // Pseudo-header: srcIP(4) + dstIP(4) + reserved(1) + protocol(1) + TCP length(2)
  const pseudo = Buffer.alloc(12);
  src.copy(pseudo, 0);
  dst.copy(pseudo, 4);
  pseudo[8] = 0;
  pseudo[9] = 6; // TCP
  pseudo.writeUInt16BE(tcpLen, 10);

  const combined = payload && payload.length > 0
    ? Buffer.concat([pseudo, tcpHeader, payload])
    : Buffer.concat([pseudo, tcpHeader]);

  return computeChecksum(combined);
}

function buildTCPPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, window, urgentPointer, payload, ipId, options) {
  const data = payload || Buffer.alloc(0);
  const tcpHeader = buildTCPHeader(srcPort, dstPort, seq, ack, flags, window, urgentPointer, data, options);

  // Compute and write TCP checksum
  const checksum = computeTCPChecksum(srcIP, dstIP, tcpHeader, data);
  tcpHeader.writeUInt16BE(checksum, 16);

  const ipHeader = buildIPHeader(srcIP, dstIP, tcpHeader.length + data.length, ipId || 0);
  return Buffer.concat([ipHeader, tcpHeader, data]);
}

// ── Parse incoming TCP flags from a raw IP packet ─────────────────────────────

function parseFlags(flagStr) {
  if (typeof flagStr === 'number') return flagStr;
  let flags = 0;
  const parts = flagStr.split('|').map(s => s.trim().toUpperCase());
  for (const p of parts) {
    if (TCPFlags[p] !== undefined) flags |= TCPFlags[p];
  }
  return flags;
}

function flagsToString(flags) {
  const names = [];
  if (flags & TCPFlags.SYN) names.push('SYN');
  if (flags & TCPFlags.ACK) names.push('ACK');
  if (flags & TCPFlags.FIN) names.push('FIN');
  if (flags & TCPFlags.RST) names.push('RST');
  if (flags & TCPFlags.PSH) names.push('PSH');
  if (flags & TCPFlags.URG) names.push('URG');
  return names.join('|') || 'NONE';
}

// ── RawTCPSocket ──────────────────────────────────────────────────────────────

class RawTCPSocket extends EventEmitter {
  /**
   * @param {Object} opts
   * @param {string} opts.srcIP - Source IP address
   * @param {string} opts.dstIP - Destination IP address
   * @param {number} opts.srcPort - Source port
   * @param {number} opts.dstPort - Destination port
   * @param {number} [opts.window=65535] - Initial TCP window size
   * @param {Object} [opts.logger] - Logger instance
   */
  constructor(opts = {}) {
    super();

    if (!rawSocketAvailable) {
      throw new Error('Raw sockets not available (requires CAP_NET_RAW on Linux)');
    }

    this.srcIP = opts.srcIP || this._getLocalIP(opts.dstIP || '127.0.0.1');
    this.dstIP = opts.dstIP || '127.0.0.1';
    this.srcPort = opts.srcPort || (49152 + Math.floor(Math.random() * 16000));
    this.dstPort = opts.dstPort || 443;
    this.windowSize = opts.window !== undefined ? opts.window : 65535;
    this.logger = opts.logger || null;

    // TCP state
    this.seq = Math.floor(Math.random() * 0xffffffff);
    this.ack = 0;
    this.state = 'CLOSED'; // CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED
    this.destroyed = false;
    this._ipId = Math.floor(Math.random() * 0xffff);

    // Receive buffer for reassembly
    this._recvBuf = Buffer.alloc(0);
    this._recvTimer = null;

    // Raw socket for sending
    this._sendSocket = raw.createSocket({
      protocol: raw.Protocol.TCP,
      addressFamily: raw.AddressFamily.IPv4,
    });
    this._sendSocket.setOption(
      raw.SocketLevel.IPPROTO_IP,
      raw.SocketOption.IP_HDRINCL,
      Buffer.from([1, 0, 0, 0])
    );

    // Raw socket for receiving (listens for all TCP)
    this._recvSocket = raw.createSocket({
      protocol: raw.Protocol.TCP,
      addressFamily: raw.AddressFamily.IPv4,
    });

    this._recvSocket.on('message', (buffer, source) => {
      this._handleIncoming(buffer, source);
    });

    this._recvSocket.on('error', (err) => {
      if (!this.destroyed) this.emit('error', err);
    });

    // Packet capture callback (for PCAP integration)
    this.onPacket = null;
  }

  _getLocalIP(dstIP) {
    // Determine local IP by creating a UDP socket to the destination
    try {
      const dgram = require('dgram');
      const sock = dgram.createSocket('udp4');
      sock.connect(1, dstIP);
      const addr = sock.address();
      sock.close();
      return addr.address;
    } catch (_) {
      return '0.0.0.0';
    }
  }

  _log(msg) {
    if (this.logger && this.logger.info) this.logger.info(msg);
  }

  _nextIPId() {
    this._ipId = (this._ipId + 1) & 0xffff;
    return this._ipId;
  }

  // ── Send a raw TCP segment ────────────────────────────────────────────────

  _sendPacket(flags, payload, opts = {}) {
    if (this.destroyed) return Promise.reject(new Error('Socket destroyed'));

    const seq = opts.seqOverride !== undefined ? opts.seqOverride : (this.seq + (opts.seqOffset || 0));
    const ackNum = opts.ackOverride !== undefined ? opts.ackOverride : (this.ack + (opts.ackOffset || 0));
    const window = opts.window !== undefined ? opts.window : this.windowSize;
    const urgentPointer = opts.urgentPointer || 0;
    const tcpOptions = opts.tcpOptions || null;

    const packet = buildTCPPacket(
      this.srcIP, this.dstIP,
      this.srcPort, this.dstPort,
      seq, ackNum, flags, window, urgentPointer,
      payload, this._nextIPId(), tcpOptions
    );

    return new Promise((resolve, reject) => {
      this._sendSocket.send(packet, 0, packet.length, this.dstIP, (err, bytes) => {
        if (err) return reject(err);

        // Notify PCAP callback
        if (this.onPacket) {
          this.onPacket(packet, 'sent');
        }

        // Update seq for data-bearing or SYN/FIN segments
        if (!opts.seqOffset && opts.seqOverride === undefined) {
          const dataLen = payload ? payload.length : 0;
          if (dataLen > 0) this.seq = (this.seq + dataLen) >>> 0;
          if (flags & TCPFlags.SYN) this.seq = (this.seq + 1) >>> 0;
          if (flags & TCPFlags.FIN) this.seq = (this.seq + 1) >>> 0;
        }

        resolve(bytes);
      });
    });
  }

  // ── Handle incoming raw TCP packets ───────────────────────────────────────

  _handleIncoming(buffer, source) {
    if (buffer.length < 40) return; // IP(20) + TCP(20) minimum

    // Parse IP header
    const ihl = (buffer[0] & 0x0f) * 4;
    const protocol = buffer[9];
    if (protocol !== 6) return; // Not TCP

    const srcIPBytes = buffer.slice(12, 16);
    const dstIPBytes = buffer.slice(16, 20);
    const srcIP = `${srcIPBytes[0]}.${srcIPBytes[1]}.${srcIPBytes[2]}.${srcIPBytes[3]}`;
    const dstIP = `${dstIPBytes[0]}.${dstIPBytes[1]}.${dstIPBytes[2]}.${dstIPBytes[3]}`;

    // Filter: only packets from our peer to us
    if (srcIP !== this.dstIP || dstIP !== this.srcIP) return;

    // Parse TCP header
    const tcp = buffer.slice(ihl);
    if (tcp.length < 20) return;

    const srcPort = tcp.readUInt16BE(0);
    const dstPort = tcp.readUInt16BE(2);
    if (srcPort !== this.dstPort || dstPort !== this.srcPort) return;

    const seq = tcp.readUInt32BE(4);
    const ackNum = tcp.readUInt32BE(8);
    const dataOffset = ((tcp[12] >> 4) & 0x0f) * 4;
    const flags = tcp[13];
    const payload = tcp.slice(dataOffset);

    // Notify PCAP callback
    if (this.onPacket) {
      this.onPacket(buffer, 'received');
    }

    // Handle based on state and flags
    if (flags & TCPFlags.RST) {
      this.state = 'CLOSED';
      this.emit('close');
      return;
    }

    if (this.state === 'SYN_SENT' && (flags & TCPFlags.SYN) && (flags & TCPFlags.ACK)) {
      // SYN-ACK received — complete handshake
      this.ack = (seq + 1) >>> 0;
      this.state = 'ESTABLISHED';
      // Parse peer's TCP options from SYN-ACK
      this.peerOptions = parseTCPOptions(tcp, dataOffset);
      // Send ACK to complete 3-way handshake (with optional ackOptions)
      const ackOpts = (this._connectOpts && this._connectOpts.ackOptions) || null;
      this._sendPacket(TCPFlags.ACK, null, { tcpOptions: ackOpts }).catch(() => {});
      this.emit('connect');
      return;
    }

    if (this.state === 'ESTABLISHED') {
      // Update ack number
      if (payload.length > 0) {
        this.ack = (seq + payload.length) >>> 0;
        // Send ACK
        this._sendPacket(TCPFlags.ACK, null).catch(() => {});

        // Buffer and emit data
        this._recvBuf = Buffer.concat([this._recvBuf, payload]);
        clearTimeout(this._recvTimer);
        this._recvTimer = setTimeout(() => {
          if (this._recvBuf.length > 0) {
            const data = this._recvBuf;
            this._recvBuf = Buffer.alloc(0);
            this.emit('data', data);
          }
        }, 50);
      }

      if (flags & TCPFlags.FIN) {
        this.ack = (seq + 1) >>> 0;
        this._sendPacket(TCPFlags.ACK, null).catch(() => {});
        this.emit('end');
        this.state = 'CLOSED';
        this.emit('close');
      }
    }
  }

  // ── Public API: Connection ────────────────────────────────────────────────

  /**
   * Perform TCP 3-way handshake via raw packets.
   * @param {number} [window] - Advertised window size for SYN
   * @param {number} [timeout=5000] - Handshake timeout in ms
   * @param {Object} [connectOpts] - Additional options
   * @param {Buffer} [connectOpts.synOptions] - TCP options for SYN packet
   * @param {Buffer} [connectOpts.ackOptions] - TCP options for handshake ACK packet
   */
  connect(window, timeout = 5000, connectOpts = {}) {
    if (window !== undefined) this.windowSize = window;
    this._connectOpts = connectOpts;

    return new Promise((resolve, reject) => {
      this.state = 'SYN_SENT';
      const timer = setTimeout(() => {
        this.removeAllListeners('connect');
        reject(new Error('TCP handshake timeout'));
      }, timeout);

      this.once('connect', () => {
        clearTimeout(timer);
        this._log(`Raw TCP connected to ${this.dstIP}:${this.dstPort}`);
        resolve();
      });

      this._sendPacket(TCPFlags.SYN, null, { tcpOptions: connectOpts.synOptions || null }).catch(reject);
    });
  }

  // ── Public API: net.Socket-compatible surface ─────────────────────────────

  /**
   * Send data (segments with PSH|ACK, proper seq tracking)
   */
  write(data, cb) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    this._sendPacket(TCPFlags.PSH | TCPFlags.ACK, buf)
      .then(() => { if (cb) cb(null); })
      .catch((err) => { if (cb) cb(err); });
    return true;
  }

  /**
   * Send FIN|ACK (half-close)
   */
  end(cb) {
    this.state = 'FIN_WAIT';
    this._sendPacket(TCPFlags.FIN | TCPFlags.ACK, null)
      .then(() => { if (cb) cb(); })
      .catch(() => { if (cb) cb(); });
  }

  /**
   * Send RST and destroy
   */
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    this._sendPacket(TCPFlags.RST, null).catch(() => {});
    this._cleanup();
    this.emit('close');
  }

  resetAndDestroy() {
    this.destroy();
  }

  setNoDelay() {} // no-op for compatibility
  setKeepAlive() {} // no-op for compatibility

  _cleanup() {
    clearTimeout(this._recvTimer);
    try { this._sendSocket.close(); } catch (_) {}
    try { this._recvSocket.close(); } catch (_) {}
  }

  // ── Public API: Raw attack methods ────────────────────────────────────────

  /**
   * Send an arbitrary TCP segment with custom flags, seq/ack offsets, etc.
   */
  sendSegment(opts = {}) {
    const flags = typeof opts.flags === 'string' ? parseFlags(opts.flags) : (opts.flags || 0);
    const payload = opts.data ? (Buffer.isBuffer(opts.data) ? opts.data : Buffer.from(opts.data)) : null;
    return this._sendPacket(flags, payload, {
      seqOffset: opts.seqOffset,
      ackOffset: opts.ackOffset,
      seqOverride: opts.seqOverride,
      ackOverride: opts.ackOverride,
      window: opts.window,
      urgentPointer: opts.urgentPointer,
      tcpOptions: opts.tcpOptions || null,
    });
  }

  /**
   * Send overlapping TCP segments with conflicting data.
   * Splits data into segments that overlap by `overlapBytes`.
   */
  async sendOverlapping(data, overlapBytes = 10) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const segSize = Math.max(overlapBytes + 1, Math.ceil(buf.length / 3));
    let offset = 0;
    let seqBase = this.seq;

    while (offset < buf.length) {
      const end = Math.min(offset + segSize, buf.length);
      const segment = buf.slice(offset, end);

      await this._sendPacket(TCPFlags.PSH | TCPFlags.ACK, segment, {
        seqOverride: (seqBase + offset) >>> 0,
      });

      // Next segment overlaps by overlapBytes
      offset = end - overlapBytes;
      if (offset <= 0 || end >= buf.length) break;
      await sleep(10);
    }

    // Update seq past all data
    this.seq = (seqBase + buf.length) >>> 0;
  }

  /**
   * Send TCP segments deliberately out of order.
   * @param {Buffer} data
   * @param {number} segmentCount - Number of segments to split into
   * @param {string} order - 'reverse' | 'random' | 'interleaved'
   */
  async sendOutOfOrder(data, segmentCount = 4, order = 'reverse') {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const segSize = Math.ceil(buf.length / segmentCount);
    const segments = [];
    let seqBase = this.seq;

    for (let i = 0; i < buf.length; i += segSize) {
      segments.push({
        offset: i,
        data: buf.slice(i, Math.min(i + segSize, buf.length)),
      });
    }

    // Reorder
    let ordered;
    switch (order) {
      case 'reverse':
        ordered = segments.slice().reverse();
        break;
      case 'random':
        ordered = segments.slice().sort(() => Math.random() - 0.5);
        break;
      case 'interleaved': {
        // Even indices first, then odd
        ordered = [];
        for (let i = 0; i < segments.length; i += 2) ordered.push(segments[i]);
        for (let i = 1; i < segments.length; i += 2) ordered.push(segments[i]);
        break;
      }
      default:
        ordered = segments;
    }

    for (const seg of ordered) {
      await this._sendPacket(TCPFlags.PSH | TCPFlags.ACK, seg.data, {
        seqOverride: (seqBase + seg.offset) >>> 0,
      });
      await sleep(10);
    }

    this.seq = (seqBase + buf.length) >>> 0;
  }

  /**
   * SYN flood — send many SYN packets.
   * Static method: creates its own raw socket, no connection state needed.
   * @param {string} dstIP
   * @param {number} dstPort
   * @param {number} count
   * @param {boolean} spoofSource - If true, use random source IPs
   */
  static async flood(dstIP, dstPort, count = 100, spoofSource = false) {
    if (!rawSocketAvailable) throw new Error('Raw sockets not available');

    const socket = raw.createSocket({
      protocol: raw.Protocol.TCP,
      addressFamily: raw.AddressFamily.IPv4,
    });
    socket.setOption(
      raw.SocketLevel.IPPROTO_IP,
      raw.SocketOption.IP_HDRINCL,
      Buffer.from([1, 0, 0, 0])
    );

    const srcIP = spoofSource ? null : '0.0.0.0';
    const promises = [];

    for (let i = 0; i < count; i++) {
      const src = spoofSource
        ? `${1 + Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${1 + Math.floor(Math.random() * 254)}`
        : (srcIP || '0.0.0.0');
      const srcPort = 1024 + Math.floor(Math.random() * 64000);
      const seq = Math.floor(Math.random() * 0xffffffff);

      const packet = buildTCPPacket(src, dstIP, srcPort, dstPort, seq, 0, TCPFlags.SYN, 65535, 0, null, i & 0xffff);

      promises.push(new Promise((resolve) => {
        socket.send(packet, 0, packet.length, dstIP, (err) => resolve(!err));
      }));

      // Batch: send 50 at a time to avoid overwhelming the event loop
      if (promises.length >= 50) {
        await Promise.all(promises);
        promises.length = 0;
      }
    }

    if (promises.length > 0) await Promise.all(promises);
    socket.close();
    return count;
  }

  /**
   * TCP connect probe — check if target is still alive using net.Socket
   */
  static probe(host, port, timeout = 2000) {
    return new Promise((resolve) => {
      const sock = net.createConnection({ host, port }, () => {
        sock.destroy();
        resolve(true);
      });
      sock.setTimeout(timeout);
      sock.on('timeout', () => { sock.destroy(); resolve(false); });
      sock.on('error', () => { sock.destroy(); resolve(false); });
    });
  }
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

module.exports = {
  RawTCPSocket,
  isRawAvailable,
  parseFlags,
  flagsToString,
  buildTCPPacket,
  buildTCPOptions,
  parseTCPOptions,
  computeTCPChecksum,
  TCP_OPT,
};
