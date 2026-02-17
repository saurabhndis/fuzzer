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
    this.filepath = filepath;
    this.srcIP = opts.srcIP || '10.0.0.1';
    this.dstIP = opts.dstIP || '10.0.0.2';
    this.srcPort = opts.srcPort || 49152;
    this.dstPort = opts.dstPort || 443;

    // TCP state tracking
    this.clientSeq = Math.floor(Math.random() * 0xffffffff);
    this.serverSeq = Math.floor(Math.random() * 0xffffffff);
    this.clientAck = 0;
    this.serverAck = 0;

    this.fd = fs.openSync(filepath, 'w');
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

  _buildEthernetHeader(direction) {
    const buf = Buffer.alloc(ETH_HEADER_SIZE);
    // Dst MAC
    if (direction === 'outbound') {
      buf[0] = 0x00; buf[1] = 0x1a; buf[2] = 0x2b; buf[3] = 0x3c; buf[4] = 0x4d; buf[5] = 0x5e;
      buf[6] = 0xaa; buf[7] = 0xbb; buf[8] = 0xcc; buf[9] = 0xdd; buf[10] = 0xee; buf[11] = 0xff;
    } else {
      buf[0] = 0xaa; buf[1] = 0xbb; buf[2] = 0xcc; buf[3] = 0xdd; buf[4] = 0xee; buf[5] = 0xff;
      buf[6] = 0x00; buf[7] = 0x1a; buf[8] = 0x2b; buf[9] = 0x3c; buf[10] = 0x4d; buf[11] = 0x5e;
    }
    // EtherType: IPv4
    buf.writeUInt16BE(0x0800, 12);
    return buf;
  }

  _buildIPHeader(direction, payloadLength) {
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

    const srcIP = this._ipToBytes(direction === 'outbound' ? this.srcIP : this.dstIP);
    const dstIP = this._ipToBytes(direction === 'outbound' ? this.dstIP : this.srcIP);

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

  _buildTCPHeader(direction, flags, payloadLength) {
    const buf = Buffer.alloc(TCP_HEADER_SIZE);

    const srcPort = direction === 'outbound' ? this.srcPort : this.dstPort;
    const dstPort = direction === 'outbound' ? this.dstPort : this.srcPort;

    buf.writeUInt16BE(srcPort, 0);
    buf.writeUInt16BE(dstPort, 2);

    if (direction === 'outbound') {
      buf.writeUInt32BE(this.clientSeq >>> 0, 4);
      buf.writeUInt32BE(this.serverSeq >>> 0, 8); // ack number
      this.clientSeq = (this.clientSeq + payloadLength) >>> 0;
      if (flags & TCPFlags.SYN) this.clientSeq = (this.clientSeq + 1) >>> 0;
      if (flags & TCPFlags.FIN) this.clientSeq = (this.clientSeq + 1) >>> 0;
    } else {
      buf.writeUInt32BE(this.serverSeq >>> 0, 4);
      buf.writeUInt32BE(this.clientSeq >>> 0, 8); // ack number
      this.serverSeq = (this.serverSeq + payloadLength) >>> 0;
      if (flags & TCPFlags.SYN) this.serverSeq = (this.serverSeq + 1) >>> 0;
      if (flags & TCPFlags.FIN) this.serverSeq = (this.serverSeq + 1) >>> 0;
    }

    buf[12] = 0x50; // data offset: 5 (20 bytes)
    buf[13] = flags & 0xff;
    buf.writeUInt16BE(65535, 14); // window size
    buf.writeUInt16BE(0, 16); // checksum (0, optional for pcap)
    buf.writeUInt16BE(0, 18); // urgent pointer

    return buf;
  }

  /**
   * Write a packet record to the pcap file
   * @param {Buffer} payload - TLS/application data (can be empty for control packets)
   * @param {string} direction - 'outbound' or 'inbound'
   * @param {number} flags - TCP flags bitmask
   */
  writePacket(payload, direction, flags = TCPFlags.PSH | TCPFlags.ACK) {
    const data = payload || Buffer.alloc(0);
    const eth = this._buildEthernetHeader(direction);
    const ip = this._buildIPHeader(direction, data.length);
    const tcp = this._buildTCPHeader(direction, flags, data.length);

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
   * Write a TCP SYN handshake (3-way)
   */
  writeTCPHandshake() {
    this.writePacket(Buffer.alloc(0), 'outbound', TCPFlags.SYN);
    this.writePacket(Buffer.alloc(0), 'inbound', TCPFlags.SYN | TCPFlags.ACK);
    this.writePacket(Buffer.alloc(0), 'outbound', TCPFlags.ACK);
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

  close() {
    try {
      fs.closeSync(this.fd);
    } catch (_) {}
  }
}

module.exports = { PcapWriter };
