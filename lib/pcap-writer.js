// PCAP File Writer — write standard pcap format readable by Wireshark
// Supports both IPv4 and IPv6 addresses.
const fs = require('fs');
const { TCPFlags } = require('./constants');

// PCAP magic number and header constants
const PCAP_MAGIC = 0xa1b2c3d4; // Canonical magic
const PCAP_VERSION_MAJOR = 2;
const PCAP_VERSION_MINOR = 4;
const PCAP_SNAPLEN = 65535;
const PCAP_LINKTYPE_ETHERNET = 1;

// Header sizes
const ETH_HEADER_SIZE = 14;
const IPV4_HEADER_SIZE = 20;
const IPV6_HEADER_SIZE = 40;
const TCP_HEADER_SIZE = 20;
const UDP_HEADER_SIZE = 8;

/**
 * Resolve a hostname to client/server IPs suitable for pcap headers.
 * Returns { clientIP, serverIP } with actual addresses instead of dummies.
 */
function resolveIPs(host) {
  const isIPv6 = host.includes(':');
  const isLoopback = /^(localhost|127\.\d+\.\d+\.\d+|::1)$/i.test(host);
  const isIPv4 = /^\d+\.\d+\.\d+\.\d+$/.test(host);

  const serverIP = isLoopback ? (isIPv6 ? '::1' : '127.0.0.1')
    : isIPv4 ? host
    : isIPv6 ? host
    : '127.0.0.1';
  const clientIP = isLoopback ? (isIPv6 ? '::1' : '127.0.0.1')
    : isIPv6 ? '::1' : '10.0.0.1';

  return { clientIP, serverIP };
}

/**
 * Parse an IPv4 dotted-quad string to a 4-byte Buffer.
 */
function ipv4ToBuffer(ip) {
  const parts = ip.split('.').map(n => parseInt(n, 10));
  return Buffer.from(parts);
}

/**
 * Parse an IPv6 address string to a 16-byte Buffer.
 * Handles full, compressed (::), and mixed (::ffff:1.2.3.4) notation.
 */
function ipv6ToBuffer(ip) {
  const buf = Buffer.alloc(16);

  // Handle mixed IPv4-mapped notation (e.g. ::ffff:192.168.1.1)
  const mixedMatch = ip.match(/^(.*):((\d+)\.(\d+)\.(\d+)\.(\d+))$/);
  let ipv6Part = ip;
  let ipv4Suffix = null;
  if (mixedMatch) {
    ipv6Part = mixedMatch[1];
    ipv4Suffix = [
      parseInt(mixedMatch[3], 10), parseInt(mixedMatch[4], 10),
      parseInt(mixedMatch[5], 10), parseInt(mixedMatch[6], 10),
    ];
  }

  // Expand :: into the correct number of zero groups
  let halves;
  if (ipv6Part.includes('::')) {
    const [left, right] = ipv6Part.split('::');
    const leftGroups = left ? left.split(':') : [];
    const rightGroups = right ? right.split(':') : [];
    const ipv4Groups = ipv4Suffix ? 2 : 0; // IPv4 suffix occupies 2 groups (4 bytes)
    const fillCount = 8 - leftGroups.length - rightGroups.length - ipv4Groups;
    halves = [...leftGroups, ...Array(fillCount).fill('0'), ...rightGroups];
  } else {
    halves = ipv6Part.split(':');
  }

  // Write 16-bit groups
  const groupCount = ipv4Suffix ? Math.min(halves.length, 6) : halves.length;
  for (let i = 0; i < groupCount; i++) {
    buf.writeUInt16BE(parseInt(halves[i] || '0', 16), i * 2);
  }

  // Write IPv4 suffix bytes into the last 4 bytes
  if (ipv4Suffix) {
    buf[12] = ipv4Suffix[0]; buf[13] = ipv4Suffix[1];
    buf[14] = ipv4Suffix[2]; buf[15] = ipv4Suffix[3];
  }

  return buf;
}

/**
 * Detect if an IP string is IPv6.
 */
function isIPv6Address(ip) {
  return ip.includes(':');
}

/**
 * Convert an IP string to a Buffer (4 bytes for IPv4, 16 bytes for IPv6).
 */
function ipToBuffer(ip) {
  return isIPv6Address(ip) ? ipv6ToBuffer(ip) : ipv4ToBuffer(ip);
}

/**
 * Compute ones-complement checksum over an array of Buffers.
 */
function onesComplement(parts) {
  let sum = 0;
  for (const part of parts) {
    for (let i = 0; i < part.length - 1; i += 2) {
      sum += part.readUInt16BE(i);
    }
    if (part.length % 2 !== 0) {
      sum += part[part.length - 1] << 8;
    }
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

class PcapWriter {
  constructor(filepath, opts = {}) {
    if (!filepath || typeof filepath !== 'string') {
      throw new Error('Valid filepath is required for PCAP writer');
    }

    const path = require('path');
    const normalizedPath = path.normalize(filepath);
    if (!normalizedPath.toLowerCase().endsWith('.pcap')) {
      throw new Error('PCAP filepath must end with .pcap');
    }

    this.filepath = normalizedPath;
    this.role = opts.role || 'client';

    // IPs: always client=src, server=dst regardless of role
    this.clientIP = opts.clientIP || '10.0.0.1';
    this.serverIP = opts.serverIP || '10.0.0.2';
    this.clientPort = opts.clientPort || opts.srcPort || 49152;
    this.serverPort = opts.serverPort || opts.dstPort || 443;
    this.protocol = opts.protocol || 'tcp';

    // For backwards compat: if srcIP/dstIP provided, use them mapped by role
    if (opts.srcIP || opts.dstIP) {
      if (this.role === 'client') {
        this.clientIP = opts.srcIP || this.clientIP;
        this.serverIP = opts.dstIP || this.serverIP;
      } else {
        this.serverIP = opts.srcIP || this.serverIP;
        this.clientIP = opts.dstIP || this.clientIP;
      }
    }

    // Auto-detect IPv6 from the configured IPs
    this.isIPv6 = isIPv6Address(this.clientIP) || isIPv6Address(this.serverIP);
    this._ipHeaderSize = this.isIPv6 ? IPV6_HEADER_SIZE : IPV4_HEADER_SIZE;

    // TCP state tracking
    this.clientSeq = Math.floor(Math.random() * 0xffffffff);
    this.serverSeq = Math.floor(Math.random() * 0xffffffff);

    this.fd = opts.append && fs.existsSync(this.filepath)
      ? fs.openSync(this.filepath, 'a')
      : fs.openSync(this.filepath, 'w');

    if (!opts.append || !fs.statSync(this.filepath).size) {
      this._writeGlobalHeader();
    }
    this.packetCount = 0;
  }

  _writeGlobalHeader() {
    const buf = Buffer.alloc(24);
    buf.writeUInt32LE(PCAP_MAGIC, 0);
    buf.writeUInt16LE(PCAP_VERSION_MAJOR, 4);
    buf.writeUInt16LE(PCAP_VERSION_MINOR, 6);
    buf.writeInt32LE(0, 8);  // thiszone
    buf.writeUInt32LE(0, 12); // sigfigs
    buf.writeUInt32LE(PCAP_SNAPLEN, 16);
    buf.writeUInt32LE(PCAP_LINKTYPE_ETHERNET, 20);
    fs.writeSync(this.fd, buf);
    try { fs.fsyncSync(this.fd); } catch (_) {}
  }

  /**
   * Resolve 'outbound'/'inbound' to src/dst IP, port, and sequence owner
   */
  _resolveDirection(direction) {
    if (direction === 'outbound') {
      if (this.role === 'client') {
        return { srcIP: this.clientIP, dstIP: this.serverIP, srcPort: this.clientPort, dstPort: this.serverPort, seqOwner: 'client' };
      } else {
        return { srcIP: this.serverIP, dstIP: this.clientIP, srcPort: this.serverPort, dstPort: this.clientPort, seqOwner: 'server' };
      }
    } else {
      if (this.role === 'client') {
        return { srcIP: this.serverIP, dstIP: this.clientIP, srcPort: this.serverPort, dstPort: this.clientPort, seqOwner: 'server' };
      } else {
        return { srcIP: this.clientIP, dstIP: this.serverIP, srcPort: this.clientPort, dstPort: this.serverPort, seqOwner: 'client' };
      }
    }
  }

  /**
   * Build a 14-byte Ethernet header with appropriate EtherType.
   * @param {object} dir - resolved direction
   * @param {number} [etherTypeOverride] - override EtherType (for writeRawPacket)
   */
  _buildEthernetHeader(dir, etherTypeOverride) {
    const buf = Buffer.alloc(ETH_HEADER_SIZE);
    const dstMAC = dir.seqOwner === 'client'
      ? [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
      : [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    const srcMAC = dir.seqOwner === 'client'
      ? [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
      : [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
    for (let i = 0; i < 6; i++) { buf[i] = dstMAC[i]; buf[i + 6] = srcMAC[i]; }

    const etherType = etherTypeOverride !== undefined ? etherTypeOverride
      : (this.isIPv6 ? 0x86DD : 0x0800);
    buf.writeUInt16BE(etherType, 12);
    return buf;
  }

  /**
   * Build a 20-byte IPv4 header.
   * @param {number} nextHeader - IP protocol number (6=TCP, 17=UDP)
   */
  _buildIPv4Header(dir, transportHeaderSize, payloadLength, nextHeader) {
    const totalLength = IPV4_HEADER_SIZE + transportHeaderSize + payloadLength;
    const buf = Buffer.alloc(IPV4_HEADER_SIZE);

    buf[0] = 0x45; // version 4, IHL 5
    buf[1] = 0x00;
    buf.writeUInt16BE(totalLength, 2);
    buf.writeUInt16BE(this.packetCount & 0xffff, 4);
    buf.writeUInt16BE(0x4000, 6); // Don't Fragment
    buf[8] = 64; // TTL
    buf[9] = nextHeader;
    buf.writeUInt16BE(0, 10); // checksum placeholder

    const srcIP = ipv4ToBuffer(dir.srcIP);
    const dstIP = ipv4ToBuffer(dir.dstIP);
    srcIP.copy(buf, 12);
    dstIP.copy(buf, 16);

    // Calculate IPv4 header checksum
    buf.writeUInt16BE(onesComplement([buf]), 10);

    return buf;
  }

  /**
   * Build a 40-byte IPv6 header.
   * @param {number} nextHeader - 6 for TCP, 17 for UDP
   */
  _buildIPv6Header(dir, transportHeaderSize, payloadLength, nextHeader) {
    const buf = Buffer.alloc(IPV6_HEADER_SIZE);

    // Version(4)=6, Traffic Class(8)=0, Flow Label(20)=0
    buf.writeUInt32BE(0x60000000, 0);
    // Payload Length = transport header + payload (does NOT include IPv6 header itself)
    buf.writeUInt16BE(transportHeaderSize + payloadLength, 4);
    buf[6] = nextHeader; // Next Header: TCP=6, UDP=17
    buf[7] = 64; // Hop Limit

    const srcIP = ipv6ToBuffer(dir.srcIP);
    const dstIP = ipv6ToBuffer(dir.dstIP);
    srcIP.copy(buf, 8);  // bytes 8–23
    dstIP.copy(buf, 24); // bytes 24–39

    // IPv6 has no header checksum
    return buf;
  }

  /**
   * Build the network-layer (IP) header, dispatching to IPv4 or IPv6.
   * @param {number} nextHeader - protocol number (6=TCP, 17=UDP)
   */
  _buildNetworkHeader(dir, transportHeaderSize, payloadLength, nextHeader) {
    if (this.isIPv6) {
      return this._buildIPv6Header(dir, transportHeaderSize, payloadLength, nextHeader);
    }
    return this._buildIPv4Header(dir, transportHeaderSize, payloadLength, nextHeader);
  }

  _buildTCPHeader(dir, flags, payloadLength) {
    const buf = Buffer.alloc(TCP_HEADER_SIZE);

    buf.writeUInt16BE(dir.srcPort, 0);
    buf.writeUInt16BE(dir.dstPort, 2);

    if (dir.seqOwner === 'client') {
      buf.writeUInt32BE(this.clientSeq >>> 0, 4);
      buf.writeUInt32BE((flags & TCPFlags.ACK) ? (this.serverSeq >>> 0) : 0, 8);
      this.clientSeq = (this.clientSeq + payloadLength) >>> 0;
      if (flags & TCPFlags.SYN) this.clientSeq = (this.clientSeq + 1) >>> 0;
      if (flags & TCPFlags.FIN) this.clientSeq = (this.clientSeq + 1) >>> 0;
    } else {
      buf.writeUInt32BE(this.serverSeq >>> 0, 4);
      buf.writeUInt32BE((flags & TCPFlags.ACK) ? (this.clientSeq >>> 0) : 0, 8);
      this.serverSeq = (this.serverSeq + payloadLength) >>> 0;
      if (flags & TCPFlags.SYN) this.serverSeq = (this.serverSeq + 1) >>> 0;
      if (flags & TCPFlags.FIN) this.serverSeq = (this.serverSeq + 1) >>> 0;
    }

    buf[12] = 0x50; // data offset: 5 (20 bytes)
    buf[13] = flags & 0xff;
    buf.writeUInt16BE(65535, 14); // window size
    buf.writeUInt16BE(0, 16); // checksum placeholder
    buf.writeUInt16BE(0, 18); // urgent pointer

    return buf;
  }

  /**
   * Build a pseudo-header for transport checksum (TCP or UDP).
   * IPv4: srcIP(4) + dstIP(4) + zero(1) + proto(1) + len(2) = 12 bytes
   * IPv6: srcIP(16) + dstIP(16) + len(4) + zeros(3) + nextHeader(1) = 40 bytes
   */
  _buildPseudoHeader(dir, transportLen, nextHeader) {
    if (this.isIPv6) {
      const pseudo = Buffer.alloc(40);
      ipv6ToBuffer(dir.srcIP).copy(pseudo, 0);
      ipv6ToBuffer(dir.dstIP).copy(pseudo, 16);
      pseudo.writeUInt32BE(transportLen, 32);
      pseudo[36] = 0; pseudo[37] = 0; pseudo[38] = 0;
      pseudo[39] = nextHeader;
      return pseudo;
    }
    const pseudo = Buffer.alloc(12);
    ipv4ToBuffer(dir.srcIP).copy(pseudo, 0);
    ipv4ToBuffer(dir.dstIP).copy(pseudo, 4);
    pseudo[8] = 0;
    pseudo[9] = nextHeader;
    pseudo.writeUInt16BE(transportLen, 10);
    return pseudo;
  }

  /**
   * Compute transport-layer checksum (TCP or UDP) over pseudo-header + header + payload.
   */
  _computeTransportChecksum(dir, transportHeader, payload, nextHeader) {
    const transportLen = transportHeader.length + payload.length;
    const pseudo = this._buildPseudoHeader(dir, transportLen, nextHeader);
    return onesComplement([pseudo, transportHeader, payload]);
  }

  /**
   * Ensure data is a Node.js Buffer, handling strings and typed arrays safely.
   */
  _toBuffer(data) {
    if (!data) return Buffer.alloc(0);
    if (Buffer.isBuffer(data)) return data;
    if (typeof data === 'string') return Buffer.from(data, 'binary');
    if (data instanceof Uint8Array || Array.isArray(data)) return Buffer.from(data);
    return Buffer.alloc(0);
  }

  /**
   * Write a pcap packet record (pcap header + ethernet + ip + transport + payload).
   */
  _writePcapRecord(packetBuf, origPacketLen) {
    const now = Date.now();
    const tsSec = Math.floor(now / 1000);
    const tsUsec = (now % 1000) * 1000;

    const packetHeader = Buffer.alloc(16);
    packetHeader.writeUInt32LE(tsSec, 0);
    packetHeader.writeUInt32LE(tsUsec, 4);
    packetHeader.writeUInt32LE(packetBuf.length, 8);  // incl_len
    packetHeader.writeUInt32LE(Math.min(origPacketLen, 0xFFFFFF), 12); // orig_len

    fs.writeSync(this.fd, Buffer.concat([packetHeader, packetBuf]));
    try { fs.fsyncSync(this.fd); } catch (_) {}
    this.packetCount++;
  }

  /**
   * Write a TCP packet record to the pcap file.
   * @param {Buffer} payload - TLS/application data (can be empty for control packets)
   * @param {string} direction - 'outbound' or 'inbound'
   * @param {number} flags - TCP flags bitmask
   */
  writePacket(payload, direction, flags = TCPFlags.PSH | TCPFlags.ACK) {
    let data = this._toBuffer(payload);
    const dir = this._resolveDirection(direction);

    const totalHeaderSize = ETH_HEADER_SIZE + this._ipHeaderSize + TCP_HEADER_SIZE;
    const origLen = data.length;
    const maxPayload = PCAP_SNAPLEN - totalHeaderSize;
    if (data.length > maxPayload) {
      data = data.slice(0, maxPayload);
    }

    const eth = this._buildEthernetHeader(dir);
    const ip = this._buildNetworkHeader(dir, TCP_HEADER_SIZE, data.length, 6);
    const tcp = this._buildTCPHeader(dir, flags, data.length);

    const checksum = this._computeTransportChecksum(dir, tcp, data, 6);
    tcp.writeUInt16BE(checksum, 16);

    const packet = Buffer.concat([eth, ip, tcp, data]);
    const totalOrigLen = totalHeaderSize + origLen;
    this._writePcapRecord(packet, totalOrigLen);
  }

  /**
   * Write a TCP SYN handshake (3-way).
   * Always client-initiated regardless of role.
   */
  writeTCPHandshake() {
    if (this.protocol === 'udp') return;

    const clientSends = this.role === 'client' ? 'outbound' : 'inbound';
    const serverSends = this.role === 'client' ? 'inbound' : 'outbound';

    this.writePacket(Buffer.alloc(0), clientSends, TCPFlags.SYN);
    this.writePacket(Buffer.alloc(0), serverSends, TCPFlags.SYN | TCPFlags.ACK);
    this.writePacket(Buffer.alloc(0), clientSends, TCPFlags.ACK);
  }

  writeTLSData(data, direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(data, dir, TCPFlags.PSH | TCPFlags.ACK);
  }

  writeFIN(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.FIN | TCPFlags.ACK);
  }

  writeRST(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.RST);
  }

  writeACK(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.ACK);
  }

  /**
   * Write a UDP packet record.
   */
  writeUDPPacket(payload, direction) {
    let data = this._toBuffer(payload);

    const maxPayload = PCAP_SNAPLEN - (ETH_HEADER_SIZE + this._ipHeaderSize + UDP_HEADER_SIZE);
    if (data.length > maxPayload) {
      data = data.slice(0, maxPayload);
    }

    const resolvedDirection = direction === 'sent' ? 'outbound' : (direction === 'received' ? 'inbound' : direction);
    const dir = this._resolveDirection(resolvedDirection);

    const eth = this._buildEthernetHeader(dir);
    const ip = this._buildNetworkHeader(dir, UDP_HEADER_SIZE, data.length, 17);

    // UDP header
    const udp = Buffer.alloc(UDP_HEADER_SIZE);
    udp.writeUInt16BE(dir.srcPort, 0);
    udp.writeUInt16BE(dir.dstPort, 2);
    udp.writeUInt16BE(UDP_HEADER_SIZE + data.length, 4);
    udp.writeUInt16BE(0, 6); // checksum placeholder

    // UDP checksum is mandatory for IPv6, optional for IPv4
    if (this.isIPv6) {
      const cksum = this._computeTransportChecksum(dir, udp, data, 17);
      // RFC 2460: if computed checksum is 0, must transmit as 0xFFFF
      udp.writeUInt16BE(cksum === 0 ? 0xFFFF : cksum, 6);
    }

    const packet = Buffer.concat([eth, ip, udp, data]);
    this._writePcapRecord(packet, packet.length);
  }

  /**
   * Write an actual raw IP+TCP packet (from raw socket capture) to the pcap file.
   * Wraps with ethernet header for Wireshark compatibility.
   * @param {Buffer} ipPacket - Raw IP packet (IP header + transport + payload)
   * @param {string} direction - 'sent' or 'received'
   */
  writeRawPacket(ipPacket, direction) {
    let packet = this._toBuffer(ipPacket);
    const resolvedDirection = direction === 'sent' ? 'outbound' : (direction === 'received' ? 'inbound' : direction);
    const dir = this._resolveDirection(resolvedDirection);
    const origLen = packet.length;
    const maxPacket = PCAP_SNAPLEN - ETH_HEADER_SIZE;
    if (packet.length > maxPacket) {
      packet = packet.slice(0, maxPacket);
      // Update IP total length in the truncated packet if it's IPv4
      if (packet.length >= 20 && (packet[0] >> 4) === 4) {
        packet.writeUInt16BE(packet.length, 2);
      }
    }

    // Detect IP version from first nibble of the raw packet
    const ipVersion = packet.length > 0 ? (packet[0] >> 4) : 4;
    const etherType = ipVersion === 6 ? 0x86DD : 0x0800;
    const eth = this._buildEthernetHeader(dir, etherType);
    const fullPacket = Buffer.concat([eth, packet]);

    const totalOrigLen = ETH_HEADER_SIZE + origLen;
    this._writePcapRecord(fullPacket, totalOrigLen);
  }

  close() {
    try {
      fs.closeSync(this.fd);
    } catch (_) {}
  }
}

module.exports = { PcapWriter, resolveIPs };
