const crypto = require('crypto');

class PacketBuilder {
    constructor() {
        this.buffer = Buffer.alloc(1200); // Max UDP payload usually
        this.offset = 0;
    }

    reset() {
        this.buffer.fill(0);
        this.offset = 0;
    }

    // Variable Length Integer Encoding (RFC 9000 16)
    writeVarInt(value) {
        if (value < 64) {
            this.buffer.writeUInt8(value, this.offset++);
        } else if (value < 16384) {
            this.buffer.writeUInt16BE((value | 0x4000) >>> 0, this.offset);
            this.offset += 2;
        } else if (value < 1073741824) {
            this.buffer.writeUInt32BE((value | 0x80000000) >>> 0, this.offset);
            this.offset += 4;
        } else {
            this.buffer.writeBigUInt64BE(BigInt(value) | 0xC000000000000000n, this.offset);
            this.offset += 8;
        }
    }

    writeBytes(buffer) {
        buffer.copy(this.buffer, this.offset);
        this.offset += buffer.length;
    }

    writeUInt8(value) {
        this.buffer.writeUInt8(value, this.offset++);
    }

    writeUInt16(value) {
        this.buffer.writeUInt16BE(value, this.offset);
        this.offset += 2;
    }

    writeUInt32(value) {
        this.buffer.writeUInt32BE(value, this.offset);
        this.offset += 4;
    }

    // Build Long Header
    buildLongHeader(type, version, dcid, scid) {
        // Header Form (1) | Fixed (1) | Long Packet Type (2) | Type Specific (4)
        // Type: 0x0=Initial, 0x1=0-RTT, 0x2=Handshake, 0x3=Retry
        const firstByte = 0x80 | 0x40 | (type << 4); 
        this.writeUInt8(firstByte);
        this.writeUInt32(version);
        
        this.writeUInt8(dcid.length);
        this.writeBytes(dcid);
        
        this.writeUInt8(scid.length);
        this.writeBytes(scid);
    }

    // Build Short Header
    buildShortHeader(spin, keyPhase, dcid, packetNumber) {
        // Header Form (0) | Fixed (1) | Spin (1) | Reserved (2) | Key Phase (1) | PN Length (2)
        const firstByte = 0x40 | (spin ? 0x20 : 0) | (keyPhase ? 0x04 : 0) | 0x03; // PN Length 4 bytes
        this.writeUInt8(firstByte);
        this.writeBytes(dcid);
        // Packet Number (assuming 4 bytes for simplicity in fuzzer)
        this.writeUInt32(packetNumber);
    }
    
    getBuffer() {
        return this.buffer.slice(0, this.offset);
    }
}

/**
 * Encode a QUIC variable-length integer into a Buffer.
 */
function encodeVarInt(value) {
  if (value < 64) {
    const b = Buffer.alloc(1);
    b.writeUInt8(value, 0);
    return b;
  } else if (value < 16384) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE((value | 0x4000) >>> 0, 0);
    return b;
  } else if (value < 1073741824) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE((value | 0x80000000) >>> 0, 0);
    return b;
  } else {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(value) | 0xC000000000000000n, 0);
    return b;
  }
}

/**
 * Build a complete QUIC Initial packet with a CRYPTO frame containing the given TLS payload.
 * Uses Buffer.concat for dynamic sizing (supports PQC payloads >1200 bytes).
 * Pads to minimum 1200 bytes per RFC 9000 §14.1.
 */
function buildQuicInitialWithCrypto(cryptoPayload, opts = {}) {
  const dcid = opts.dcid || crypto.randomBytes(8);
  const scid = opts.scid || crypto.randomBytes(8);
  const pn = opts.packetNumber || 1;
  const cryptoOffset = opts.cryptoOffset || 0;

  // Long Header: first byte + version(4) + DCID len(1) + DCID + SCID len(1) + SCID
  const firstByte = Buffer.from([0x80 | 0x40 | (0 << 4)]); // Initial type=0
  const version = Buffer.alloc(4);
  version.writeUInt32BE(0x00000001, 0); // QUIC v1

  const dcidLen = Buffer.from([dcid.length]);
  const scidLen = Buffer.from([scid.length]);

  // Token length = 0
  const tokenLen = encodeVarInt(0);

  // Build CRYPTO frame: type(1) + offset(varint) + length(varint) + data
  const cryptoFrameType = Buffer.from([0x06]);
  const cryptoOffsetEnc = encodeVarInt(cryptoOffset);
  const cryptoLenEnc = encodeVarInt(cryptoPayload.length);
  const cryptoFrame = Buffer.concat([cryptoFrameType, cryptoOffsetEnc, cryptoLenEnc, cryptoPayload]);

  // Packet payload: PN(2) + CRYPTO frame
  const pnBuf = Buffer.alloc(2);
  pnBuf.writeUInt16BE(pn, 0);
  const payload = Buffer.concat([pnBuf, cryptoFrame]);

  // Packet length (varint)
  const packetLen = encodeVarInt(payload.length);

  const packet = Buffer.concat([
    firstByte, version, dcidLen, dcid, scidLen, scid,
    tokenLen, packetLen, payload,
  ]);

  // Pad to minimum 1200 bytes
  if (packet.length < 1200) {
    return Buffer.concat([packet, Buffer.alloc(1200 - packet.length, 0)]);
  }
  return packet;
}

/**
 * Build a QUIC CONNECTION_CLOSE frame in a Short Header packet.
 * Used to adapt TCP FIN/RST actions to QUIC.
 */
function buildQuicConnectionClose(errorCode, reason) {
  const dcid = crypto.randomBytes(8);
  const pn = crypto.randomInt(1, 100000);

  const b = new PacketBuilder();
  b.buildShortHeader(false, false, dcid, pn);
  b.writeUInt8(0x1c); // CONNECTION_CLOSE (QUIC layer)
  b.writeVarInt(errorCode || 0x00);
  b.writeVarInt(0x00); // Triggering frame type
  const reasonBuf = Buffer.from(reason || '', 'utf8');
  b.writeVarInt(reasonBuf.length);
  if (reasonBuf.length > 0) b.writeBytes(reasonBuf);
  return b.getBuffer();
}

module.exports = PacketBuilder;
module.exports.buildQuicInitialWithCrypto = buildQuicInitialWithCrypto;
module.exports.buildQuicConnectionClose = buildQuicConnectionClose;
