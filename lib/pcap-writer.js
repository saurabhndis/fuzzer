// PCAP File Writer — write standard pcap format readable by Wireshark
const fs = require('fs');
const { TCPFlags } = require('./constants');

// PCAP magic number and header constants
const PCAP_MAGIC = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR = 2;
const PCAP_VERSION_MINOR = 4;
const PCAP_SNAPLEN = 65535;
const PCAP_LINKTYPE_ETHERNET = 1;
const PCAP_LINKTYPE_RAW_IP = 101;

// Ethernet + IP + TCP header sizes
const ETH_HEADER_SIZE = 14;
const IP_HEADER_SIZE = 20;
const TCP_HEADER_SIZE = 20;
const TOTAL_HEADER_SIZE = ETH_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE;

class PcapWriter {
  constructor(filepath, opts = {}) {
    if (!filepath || typeof filepath !== 'string') {
      throw new Error('Valid filepath is required for PCAP writer');
    }

    const path = require('path');
    // Sanity check: must have .pcap extension and be a clean path
    const normalizedPath = path.normalize(filepath);
    if (!normalizedPath.toLowerCase().endsWith('.pcap')) {
      throw new Error('PCAP filepath must end with .pcap');
    }

    this.filepath = normalizedPath;

    // role determines perspective: 'client' means outbound=client→server,
    // 'server' means outbound=server→client. Affects handshake direction only.
    this.role = opts.role || 'client';

    // IPs: always client=src, server=dst regardless of role
    this.clientIP = opts.clientIP || '10.0.0.1';
    this.serverIP = opts.serverIP || '10.0.0.2';
    this.clientPort = opts.clientPort || opts.srcPort || 49152;
    this.serverPort = opts.serverPort || opts.dstPort || 443;

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

    // TCP state tracking — named by who owns the sequence
    this.clientSeq = Math.floor(Math.random() * 0xffffffff);
    this.serverSeq = Math.floor(Math.random() * 0xffffffff);

    this.fd = fs.openSync(this.filepath, 'w');
    this._writeGlobalHeader();
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
  }

  _ipToBytes(ip) {
    return ip.split('.').map(Number);
  }

  /**
   * Resolve 'outbound'/'inbound' to actual client→server or server→client
   * based on role. 'outbound' always means "this endpoint sends".
   * Returns { srcIP, dstIP, srcPort, dstPort, seqOwner: 'client'|'server' }
   */
  _resolveDirection(direction) {
    if (this.role === 'client') {
      // outbound = client→server, inbound = server→client
      if (direction === 'outbound') {
        return { srcIP: this.clientIP, dstIP: this.serverIP, srcPort: this.clientPort, dstPort: this.serverPort, seqOwner: 'client' };
      } else {
        return { srcIP: this.serverIP, dstIP: this.clientIP, srcPort: this.serverPort, dstPort: this.clientPort, seqOwner: 'server' };
      }
    } else {
      // server role: outbound = server→client, inbound = client→server
      if (direction === 'outbound') {
        return { srcIP: this.serverIP, dstIP: this.clientIP, srcPort: this.serverPort, dstPort: this.clientPort, seqOwner: 'server' };
      } else {
        return { srcIP: this.clientIP, dstIP: this.serverIP, srcPort: this.clientPort, dstPort: this.serverPort, seqOwner: 'client' };
      }
    }
  }

  _buildEthernetHeader(dir) {
    const buf = Buffer.alloc(ETH_HEADER_SIZE);
    // Use different MACs based on actual network direction (client→server vs server→client)
    const isClientToServer = dir.srcPort === this.clientPort;
    if (isClientToServer) {
      // client MAC → server MAC
      buf[0] = 0x00; buf[1] = 0x1a; buf[2] = 0x2b; buf[3] = 0x3c; buf[4] = 0x4d; buf[5] = 0x5e;
      buf[6] = 0xaa; buf[7] = 0xbb; buf[8] = 0xcc; buf[9] = 0xdd; buf[10] = 0xee; buf[11] = 0xff;
    } else {
      // server MAC → client MAC
      buf[0] = 0xaa; buf[1] = 0xbb; buf[2] = 0xcc; buf[3] = 0xdd; buf[4] = 0xee; buf[5] = 0xff;
      buf[6] = 0x00; buf[7] = 0x1a; buf[8] = 0x2b; buf[9] = 0x3c; buf[10] = 0x4d; buf[11] = 0x5e;
    }
    // EtherType: IPv4
    buf.writeUInt16BE(0x0800, 12);
    return buf;
  }

  _buildIPHeader(dir, payloadLength) {
    const totalLength = IP_HEADER_SIZE + TCP_HEADER_SIZE + payloadLength;
    const buf = Buffer.alloc(IP_HEADER_SIZE);

    buf[0] = 0x45; // version 4, IHL 5
    buf[1] = 0x00; // DSCP/ECN
    buf.writeUInt16BE(totalLength, 2); // total length
    buf.writeUInt16BE(this.packetCount & 0xffff, 4); // identification
    buf.writeUInt16BE(0x4000, 6); // flags (Don't Fragment) + offset
    buf[8] = 64; // TTL
    buf[9] = 6;  // protocol: TCP
    buf.writeUInt16BE(0, 10); // checksum (0 for now)

    const srcIP = this._ipToBytes(dir.srcIP);
    const dstIP = this._ipToBytes(dir.dstIP);

    buf[12] = srcIP[0]; buf[13] = srcIP[1]; buf[14] = srcIP[2]; buf[15] = srcIP[3];
    buf[16] = dstIP[0]; buf[17] = dstIP[1]; buf[18] = dstIP[2]; buf[19] = dstIP[3];

    // Calculate IP checksum
    let sum = 0;
    for (let i = 0; i < 20; i += 2) {
      sum += buf.readUInt16BE(i);
    }
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    buf.writeUInt16BE(~sum & 0xffff, 10);

    return buf;
  }

  _buildTCPHeader(dir, flags, payloadLength) {
    const buf = Buffer.alloc(TCP_HEADER_SIZE);

    buf.writeUInt16BE(dir.srcPort, 0);
    buf.writeUInt16BE(dir.dstPort, 2);

    // Sequence numbers are tracked per TCP endpoint (client vs server)
    if (dir.seqOwner === 'client') {
      buf.writeUInt32BE(this.clientSeq >>> 0, 4);
      // Only write ack if ACK flag is set; otherwise write 0
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
   * Compute TCP checksum over pseudo-header + TCP header + payload
   */
  _computeTCPChecksum(dir, tcpHeader, payload) {
    const srcIP = this._ipToBytes(dir.srcIP);
    const dstIP = this._ipToBytes(dir.dstIP);
    const tcpLen = tcpHeader.length + payload.length;

    // Pseudo-header: srcIP(4) + dstIP(4) + zero(1) + protocol(1) + tcpLen(2) = 12 bytes
    const pseudo = Buffer.alloc(12);
    pseudo[0] = srcIP[0]; pseudo[1] = srcIP[1]; pseudo[2] = srcIP[2]; pseudo[3] = srcIP[3];
    pseudo[4] = dstIP[0]; pseudo[5] = dstIP[1]; pseudo[6] = dstIP[2]; pseudo[7] = dstIP[3];
    pseudo[8] = 0;
    pseudo[9] = 6; // TCP protocol
    pseudo.writeUInt16BE(tcpLen, 10);

    // Sum all 16-bit words: pseudo + tcp header + payload
    let sum = 0;
    const parts = [pseudo, tcpHeader, payload];
    for (const part of parts) {
      for (let i = 0; i < part.length - 1; i += 2) {
        sum += part.readUInt16BE(i);
      }
      // If odd length, pad last byte
      if (part.length % 2 !== 0) {
        sum += part[part.length - 1] << 8;
      }
    }
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum & 0xffff;
  }

  /**
   * Write a packet record to the pcap file
   * @param {Buffer} payload - TLS/application data (can be empty for control packets)
   * @param {string} direction - 'outbound' or 'inbound'
   * @param {number} flags - TCP flags bitmask
   */
  writePacket(payload, direction, flags = TCPFlags.PSH | TCPFlags.ACK) {
    const data = payload || Buffer.alloc(0);
    const dir = this._resolveDirection(direction);
    const eth = this._buildEthernetHeader(dir);
    const ip = this._buildIPHeader(dir, data.length);
    const tcp = this._buildTCPHeader(dir, flags, data.length);

    // Compute and write TCP checksum
    const checksum = this._computeTCPChecksum(dir, tcp, data);
    tcp.writeUInt16BE(checksum, 16);

    const packet = Buffer.concat([eth, ip, tcp, data]);

    // PCAP packet header
    const now = Date.now();
    const tsSec = Math.floor(now / 1000);
    const tsUsec = (now % 1000) * 1000;

    const packetHeader = Buffer.alloc(16);
    packetHeader.writeUInt32LE(tsSec, 0);
    packetHeader.writeUInt32LE(tsUsec, 4);
    packetHeader.writeUInt32LE(packet.length, 8);  // incl_len
    packetHeader.writeUInt32LE(packet.length, 12); // orig_len

    fs.writeSync(this.fd, packetHeader);
    fs.writeSync(this.fd, packet);
    this.packetCount++;
  }

  /**
   * Write a TCP SYN handshake (3-way).
   * Always client-initiated regardless of role.
   */
  writeTCPHandshake() {
    // SYN is always client→server, SYN-ACK is server→client, ACK is client→server.
    // Map to outbound/inbound based on role.
    const clientSends = this.role === 'client' ? 'outbound' : 'inbound';
    const serverSends = this.role === 'client' ? 'inbound' : 'outbound';

    this.writePacket(Buffer.alloc(0), clientSends, TCPFlags.SYN);
    this.writePacket(Buffer.alloc(0), serverSends, TCPFlags.SYN | TCPFlags.ACK);
    this.writePacket(Buffer.alloc(0), clientSends, TCPFlags.ACK);
  }

  /**
   * Write a TLS data packet
   */
  writeTLSData(data, direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(data, dir, TCPFlags.PSH | TCPFlags.ACK);
  }

  /**
   * Write a FIN packet
   */
  writeFIN(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.FIN | TCPFlags.ACK);
  }

  /**
   * Write a RST packet
   */
  writeRST(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.RST);
  }

  /**
   * Write an ACK packet
   */
  writeACK(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.ACK);
  }

  /**
   * Write an actual raw IP+TCP packet (from raw socket capture) to the pcap file.
   * Wraps with ethernet header for Wireshark compatibility.
   * @param {Buffer} ipPacket - Raw IP packet (IP header + TCP header + payload)
   * @param {string} direction - 'sent' or 'received'
   */
  writeRawPacket(ipPacket, direction) {
    // For raw packets, determine direction from the IP packet itself
    const dir = direction === 'sent'
      ? this._resolveDirection('outbound')
      : this._resolveDirection('inbound');
    const eth = this._buildEthernetHeader(dir);
    const packet = Buffer.concat([eth, ipPacket]);

    const now = Date.now();
    const tsSec = Math.floor(now / 1000);
    const tsUsec = (now % 1000) * 1000;

    const packetHeader = Buffer.alloc(16);
    packetHeader.writeUInt32LE(tsSec, 0);
    packetHeader.writeUInt32LE(tsUsec, 4);
    packetHeader.writeUInt32LE(packet.length, 8);
    packetHeader.writeUInt32LE(packet.length, 12);

    fs.writeSync(this.fd, packetHeader);
    fs.writeSync(this.fd, packet);
    this.packetCount++;
  }

  close() {
    try {
      fs.closeSync(this.fd);
    } catch (_) {}
  }
}

module.exports = { PcapWriter };
