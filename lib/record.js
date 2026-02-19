// TLS Record Layer — build and parse raw TLS records
const crypto = require('crypto');
const { ContentType, Version, AlertLevel, AlertDescription, HeartbeatMessageType } = require('./constants');

/**
 * Build a TLS record: 5-byte header + payload
 *   [content_type:1][version:2][length:2][payload:N]
 */
function buildRecord(contentType, version, payload) {
  const buf = Buffer.alloc(5 + payload.length);
  buf[0] = contentType;
  buf.writeUInt16BE(version, 1);
  buf.writeUInt16BE(payload.length, 3);
  payload.copy(buf, 5);
  return buf;
}

/**
 * Build an Alert record
 */
function buildAlert(level, description, version = Version.TLS_1_2) {
  const payload = Buffer.from([level, description]);
  return buildRecord(ContentType.ALERT, version, payload);
}

/**
 * Build a ChangeCipherSpec record (payload is always [0x01])
 */
function buildChangeCipherSpec(version = Version.TLS_1_2) {
  return buildRecord(ContentType.CHANGE_CIPHER_SPEC, version, Buffer.from([0x01]));
}

/**
 * Build a CCS record with extra garbage bytes
 */
function buildChangeCipherSpecWithPayload(version = Version.TLS_1_2, extraSize = 16) {
  const payload = Buffer.alloc(1 + extraSize);
  payload[0] = 0x01;
  crypto.randomFillSync(payload, 1);
  return buildRecord(ContentType.CHANGE_CIPHER_SPEC, version, payload);
}

/**
 * Parse TLS records from a buffer. Returns array of { type, version, payload, raw }.
 * Handles partial records by returning what's complete.
 */
function parseRecords(buffer) {
  const records = [];
  let offset = 0;

  while (offset + 5 <= buffer.length) {
    const type = buffer[offset];
    const version = buffer.readUInt16BE(offset + 1);
    const length = buffer.readUInt16BE(offset + 3);

    if (offset + 5 + length > buffer.length) break; // incomplete record

    const payload = buffer.slice(offset + 5, offset + 5 + length);
    const raw = buffer.slice(offset, offset + 5 + length);
    records.push({ type, version, length, payload, raw });
    offset += 5 + length;
  }

  return { records, remainder: offset < buffer.length ? buffer.slice(offset) : null };
}

/**
 * Build a record with random garbage payload but valid-looking header
 */
function buildGarbageRecord(size = 256) {
  const payload = crypto.randomBytes(size);
  // Random content type between valid range
  const types = [ContentType.HANDSHAKE, ContentType.ALERT, ContentType.APPLICATION_DATA];
  const type = types[Math.floor(Math.random() * types.length)];
  return buildRecord(type, Version.TLS_1_2, payload);
}

/**
 * Build an oversized record (> 16384 bytes, violating TLS spec)
 */
function buildOversizedRecord(contentType = ContentType.APPLICATION_DATA, version = Version.TLS_1_2, size = 20000) {
  const payload = crypto.randomBytes(size);
  return buildRecord(contentType, version, payload);
}

/**
 * Build a zero-length record
 */
function buildZeroLengthRecord(contentType = ContentType.HANDSHAKE, version = Version.TLS_1_2) {
  return buildRecord(contentType, version, Buffer.alloc(0));
}

/**
 * Build a record where the length field doesn't match actual payload
 */
function buildWrongLengthRecord(contentType, version, payload, fakeLength) {
  const buf = Buffer.alloc(5 + payload.length);
  buf[0] = contentType;
  buf.writeUInt16BE(version, 1);
  buf.writeUInt16BE(fakeLength, 3); // lie about length
  payload.copy(buf, 5);
  return buf;
}

/**
 * Build raw garbage bytes (not a valid TLS record at all)
 */
function buildRawGarbage(size = 32) {
  return crypto.randomBytes(size);
}

/**
 * Build a Heartbeat request (RFC 6520) — used for Heartbleed detection
 * CVE-2014-0160: payload_length claims more data than actually sent
 * @param {number} claimedLength - The length field value (lie: larger than actual)
 * @param {number} actualPayload - Actual payload bytes to send
 */
function buildHeartbeatRequest(claimedLength = 16384, actualPayload = 1, version = Version.TLS_1_2) {
  // Heartbeat: [type:1][payload_length:2][payload:N][padding:>=16]
  const padding = crypto.randomBytes(16);
  const payload = crypto.randomBytes(actualPayload);
  const hbBody = Buffer.alloc(1 + 2 + payload.length + padding.length);
  hbBody[0] = HeartbeatMessageType.HEARTBEAT_REQUEST;
  hbBody.writeUInt16BE(claimedLength, 1); // lie about payload length
  payload.copy(hbBody, 3);
  padding.copy(hbBody, 3 + payload.length);
  return buildRecord(ContentType.HEARTBEAT, version, hbBody);
}

/**
 * Build an SSLv2 ClientHello (for DROWN detection)
 * SSLv2 format: [msg_length:2][msg_type:1][version:2][cipher_spec_length:2]
 *               [session_id_length:2][challenge_length:2][cipher_specs:N][challenge:N]
 */
function buildSSLv2ClientHello() {
  const cipherSpecs = Buffer.from([
    // SSLv2 cipher specs are 3 bytes each
    0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
    0x05, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
    0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
    0x01, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
    0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
  ]);
  const challenge = crypto.randomBytes(16);
  const sessionIdLen = 0;

  const bodyLen = 1 + 2 + 2 + 2 + 2 + cipherSpecs.length + challenge.length;
  const buf = Buffer.alloc(2 + bodyLen);
  // SSLv2 record header: high bit set, length in remaining 15 bits
  buf.writeUInt16BE(0x8000 | bodyLen, 0);
  buf[2] = 0x01; // CLIENT-HELLO
  buf.writeUInt16BE(0x0002, 3); // Version: SSL 2.0
  buf.writeUInt16BE(cipherSpecs.length, 5); // cipher_spec_length
  buf.writeUInt16BE(sessionIdLen, 7); // session_id_length
  buf.writeUInt16BE(challenge.length, 9); // challenge_length
  cipherSpecs.copy(buf, 11);
  challenge.copy(buf, 11 + cipherSpecs.length);
  return buf;
}

/**
 * Build an SSLv2 ClientHello with configurable fields (for mutation fuzzing)
 * @param {Object} opts
 * @param {number} opts.version - SSLv2 version field (default 0x0002 = SSL 2.0)
 * @param {Buffer} opts.cipherSpecs - Raw cipher specs buffer (default: standard 5 specs)
 * @param {number} opts.challengeLength - Challenge length (default 16); set to 0 for empty challenge
 */
function buildSSLv2ClientHelloMutated(opts = {}) {
  const version = opts.version !== undefined ? opts.version : 0x0002;
  const cipherSpecs = opts.cipherSpecs || Buffer.from([
    0x07, 0x00, 0xc0,
    0x05, 0x00, 0x80,
    0x03, 0x00, 0x80,
    0x01, 0x00, 0x80,
    0x06, 0x00, 0x40,
  ]);
  const challengeLen = opts.challengeLength !== undefined ? opts.challengeLength : 16;
  const challenge = challengeLen > 0 ? crypto.randomBytes(challengeLen) : Buffer.alloc(0);
  const sessionIdLen = 0;

  const bodyLen = 1 + 2 + 2 + 2 + 2 + cipherSpecs.length + challenge.length;
  const buf = Buffer.alloc(2 + bodyLen);
  buf.writeUInt16BE(0x8000 | bodyLen, 0);
  buf[2] = 0x01; // CLIENT-HELLO
  buf.writeUInt16BE(version, 3);
  buf.writeUInt16BE(cipherSpecs.length, 5);
  buf.writeUInt16BE(sessionIdLen, 7);
  buf.writeUInt16BE(challenge.length, 9);
  cipherSpecs.copy(buf, 11);
  challenge.copy(buf, 11 + cipherSpecs.length);
  return buf;
}

module.exports = {
  buildRecord,
  buildAlert,
  buildChangeCipherSpec,
  buildChangeCipherSpecWithPayload,
  parseRecords,
  buildGarbageRecord,
  buildOversizedRecord,
  buildZeroLengthRecord,
  buildWrongLengthRecord,
  buildRawGarbage,
  buildHeartbeatRequest,
  buildSSLv2ClientHello,
  buildSSLv2ClientHelloMutated,
};
