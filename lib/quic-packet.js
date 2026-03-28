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

// ═══════════════════════════════════════════════════════════════════════
// QUIC Initial Packet Protection (RFC 9001 §5)
//
// Initial packets are protected using keys derived from the Destination
// Connection ID via HKDF.  The algorithm is always AES-128-GCM with
// AES-128-ECB header protection.
// ═══════════════════════════════════════════════════════════════════════

// Initial salt for QUIC v1 (RFC 9001 §5.2)
const QUIC_V1_INITIAL_SALT = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');
// Initial salt for QUIC v2 (RFC 9369 §5.2)
const QUIC_V2_INITIAL_SALT = Buffer.from('0dede3def700a6db819381be6e269dcbf9bd2ed9', 'hex');

/**
 * HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
 */
function hkdfExtract(salt, ikm) {
  return crypto.createHmac('sha256', salt).update(ikm).digest();
}

/**
 * HKDF-Expand-Label (TLS 1.3 style, used by QUIC)
 * PRK + Label + Context → OKM of length `len`
 */
function hkdfExpandLabel(prk, label, context, len) {
  const tlsLabel = Buffer.from('tls13 ' + label, 'ascii');
  // HkdfLabel: length(2) + label_length(1) + label + context_length(1) + context
  const hkdfLabel = Buffer.concat([
    Buffer.from([0, len]),           // uint16 length
    Buffer.from([tlsLabel.length]),  // uint8 label length
    tlsLabel,
    Buffer.from([context.length]),   // uint8 context length
    context,
  ]);
  // HKDF-Expand with T(1) is enough for our key sizes (≤32 bytes)
  const t1 = crypto.createHmac('sha256', prk).update(Buffer.concat([hkdfLabel, Buffer.from([1])])).digest();
  return t1.slice(0, len);
}

/**
 * Derive QUIC Initial keys from the Destination Connection ID.
 * Returns { key, iv, hp } for the client side.
 */
function deriveInitialKeys(dcid, version) {
  const salt = (version === 0x6b3343cf) ? QUIC_V2_INITIAL_SALT : QUIC_V1_INITIAL_SALT;
  const initialSecret = hkdfExtract(salt, dcid);
  const emptyCtx = Buffer.alloc(0);

  // Client Initial secret
  const clientSecret = hkdfExpandLabel(initialSecret, 'client in', emptyCtx, 32);

  // Derive key (16 bytes for AES-128), IV (12 bytes), HP key (16 bytes)
  const key = hkdfExpandLabel(clientSecret, 'quic key', emptyCtx, 16);
  const iv  = hkdfExpandLabel(clientSecret, 'quic iv',  emptyCtx, 12);
  const hp  = hkdfExpandLabel(clientSecret, 'quic hp',  emptyCtx, 16);

  return { key, iv, hp };
}

/**
 * Apply QUIC packet protection to an Initial packet.
 *
 * Takes a fully assembled unprotected packet (header + payload with PN)
 * and returns the protected packet with AEAD-encrypted payload and
 * header protection applied.
 *
 * @param {Buffer} header    - The unprotected header (up to and including packet number)
 * @param {Buffer} payload   - The plaintext payload (after packet number)
 * @param {number} pn        - The packet number value
 * @param {number} pnLen     - The packet number length in bytes (1-4)
 * @param {Object} keys      - { key, iv, hp } from deriveInitialKeys()
 * @returns {Buffer} The fully protected packet
 */
function protectPacket(header, payload, pn, pnLen, keys) {
  // 1. Build the nonce: IV XOR'd with the packet number (left-padded to 12 bytes)
  const nonce = Buffer.from(keys.iv);
  const pnBuf = Buffer.alloc(12, 0);
  pnBuf.writeUInt32BE(pn, 8); // right-align in 12-byte buffer
  for (let i = 0; i < 12; i++) nonce[i] ^= pnBuf[i];

  // 2. AEAD encrypt: plaintext = payload, AAD = header
  const cipher = crypto.createCipheriv('aes-128-gcm', keys.key, nonce);
  cipher.setAAD(header);
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes

  // 3. Header protection: sample 16 bytes starting 4 bytes into the ciphertext
  const sampleOffset = 4 - pnLen;
  const ciphertext = Buffer.concat([encrypted, tag]);
  const sample = ciphertext.slice(
    Math.max(0, sampleOffset),
    Math.max(0, sampleOffset) + 16
  );

  // AES-ECB encrypt the sample to get the mask
  const hpCipher = crypto.createCipheriv('aes-128-ecb', keys.hp, null);
  hpCipher.setAutoPadding(false);
  const mask = hpCipher.update(sample);

  // 4. Apply header protection
  const protectedHeader = Buffer.from(header);
  // First byte: mask lower 4 bits (long header)
  if (protectedHeader[0] & 0x80) {
    protectedHeader[0] ^= (mask[0] & 0x0f);
  } else {
    protectedHeader[0] ^= (mask[0] & 0x1f);
  }
  // Mask the packet number bytes
  const pnOffset = protectedHeader.length - pnLen;
  for (let i = 0; i < pnLen; i++) {
    protectedHeader[pnOffset + i] ^= mask[1 + i];
  }

  return Buffer.concat([protectedHeader, ciphertext]);
}

/**
 * Build and protect a QUIC Initial packet with a CRYPTO frame.
 * This produces a packet that real QUIC servers will accept and process.
 *
 * @param {Buffer} cryptoPayload - The TLS handshake data for the CRYPTO frame
 * @param {Object} opts
 * @param {Buffer} [opts.dcid]         - Destination Connection ID
 * @param {Buffer} [opts.scid]         - Source Connection ID
 * @param {number} [opts.packetNumber] - Packet number (default 1)
 * @param {number} [opts.cryptoOffset] - CRYPTO frame offset (default 0)
 * @param {number} [opts.version]      - QUIC version (default v1)
 * @param {boolean}[opts.noProtection] - Skip protection (for intentionally malformed packets)
 * @returns {Buffer}
 */
function buildQuicInitialWithCrypto(cryptoPayload, opts = {}) {
  const dcid = opts.dcid || crypto.randomBytes(8);
  const scid = opts.scid || crypto.randomBytes(8);
  const pn = opts.packetNumber || 1;
  const cryptoOffset = opts.cryptoOffset || 0;
  const version = opts.version || 0x00000001;

  // Build CRYPTO frame: type(0x06) + offset(varint) + length(varint) + data
  const cryptoFrameType = Buffer.from([0x06]);
  const cryptoOffsetEnc = encodeVarInt(cryptoOffset);
  const cryptoLenEnc = encodeVarInt(cryptoPayload.length);
  const cryptoFrame = Buffer.concat([cryptoFrameType, cryptoOffsetEnc, cryptoLenEnc, cryptoPayload]);

  // Packet number encoding: use 2-byte PN
  const pnLen = 2;
  const pnBuf = Buffer.alloc(pnLen);
  pnBuf.writeUInt16BE(pn & 0xffff, 0);

  // Plaintext payload (everything after PN)
  const plaintext = cryptoFrame;

  // We need to know the total payload length including PN + ciphertext + AEAD tag (16 bytes)
  // to encode it in the header. Ciphertext length = plaintext length + 16 (AES-GCM tag).
  const payloadLen = pnLen + plaintext.length + 16;

  // Long header: first byte encodes PN length (pnLen - 1 in low 2 bits)
  const firstByte = Buffer.from([0x80 | 0x40 | (0 << 4) | (pnLen - 1)]); // Initial type=0
  const versionBuf = Buffer.alloc(4);
  versionBuf.writeUInt32BE(version, 0);
  const dcidLenBuf = Buffer.from([dcid.length]);
  const scidLenBuf = Buffer.from([scid.length]);
  const token = opts.token || Buffer.alloc(0);
  const tokenLenEnc = encodeVarInt(token.length);
  const packetLenEnc = encodeVarInt(payloadLen);

  // Build unprotected header (everything up to and including PN)
  const header = Buffer.concat([
    firstByte, versionBuf, dcidLenBuf, dcid, scidLenBuf, scid,
    tokenLenEnc, token, packetLenEnc, pnBuf,
  ]);

  if (opts.noProtection) {
    // No protection — return unencrypted packet (for intentionally malformed fuzz packets)
    const packet = Buffer.concat([header, plaintext]);
    if (packet.length < 1200) {
      return Buffer.concat([packet, Buffer.alloc(1200 - packet.length, 0)]);
    }
    return packet;
  }

  // Pad plaintext so the total packet is at least 1200 bytes.
  // Total = header.length + pnLen(already in header) + ciphertext(plaintext.length + 16)
  // But header already includes pnLen, so total = header.length + plaintext.length + 16
  const minPadding = Math.max(0, 1200 - header.length - plaintext.length - 16);
  const paddedPlaintext = minPadding > 0
    ? Buffer.concat([plaintext, Buffer.alloc(minPadding, 0)]) // PADDING frames are 0x00
    : plaintext;

  // Recalculate payload length with padding
  const actualPayloadLen = pnLen + paddedPlaintext.length + 16;
  const actualPacketLenEnc = encodeVarInt(actualPayloadLen);

  // Rebuild header if payload length encoding changed size
  let finalHeader;
  if (actualPacketLenEnc.length !== packetLenEnc.length) {
    finalHeader = Buffer.concat([
      firstByte, versionBuf, dcidLenBuf, dcid, scidLenBuf, scid,
      tokenLenEnc, token, actualPacketLenEnc, pnBuf,
    ]);
  } else {
    // Overwrite the packet length in place
    finalHeader = Buffer.concat([
      firstByte, versionBuf, dcidLenBuf, dcid, scidLenBuf, scid,
      tokenLenEnc, token, actualPacketLenEnc, pnBuf,
    ]);
  }

  // Derive keys and protect
  const keys = deriveInitialKeys(dcid, version);
  return protectPacket(finalHeader, paddedPlaintext, pn, pnLen, keys);
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

/**
 * Parse a QUIC Retry packet (RFC 9000 §17.2.5).
 * Returns { scid, token } or null if not a Retry packet.
 *
 * Retry packet layout (long header, type 0x03):
 *   First Byte | Version (4B) | DCID Len (1B) | DCID | SCID Len (1B) | SCID | Retry Token | Retry Integrity Tag (16B)
 */
function parseQuicRetry(data) {
  if (!data || data.length < 7) return null;
  const firstByte = data[0];
  if ((firstByte & 0x80) === 0) return null; // Must be long header
  const pktType = (firstByte & 0x30) >> 4;
  if (pktType !== 3) return null; // Must be Retry (type 3)

  let off = 1;
  // const version = data.readUInt32BE(off);
  off += 4;
  const dcidLen = data[off++];
  // const dcid = data.slice(off, off + dcidLen);
  off += dcidLen;
  const scidLen = data[off++];
  const scid = data.slice(off, off + scidLen);
  off += scidLen;
  // Retry Token = everything after SCID up to last 16 bytes (Retry Integrity Tag)
  if (data.length - off < 16) return null; // Malformed — no room for integrity tag
  const token = data.slice(off, data.length - 16);
  return { scid, token };
}

module.exports = PacketBuilder;
module.exports.encodeVarInt = encodeVarInt;
module.exports.buildQuicInitialWithCrypto = buildQuicInitialWithCrypto;
module.exports.buildQuicConnectionClose = buildQuicConnectionClose;
module.exports.parseQuicRetry = parseQuicRetry;
module.exports.deriveInitialKeys = deriveInitialKeys;
module.exports.protectPacket = protectPacket;
