// TLS Content Validation — deep inspection of ClientHello and ServerFlight messages
// to match OpenSSL's validation behavior for well-behaved counterparts.
const { ContentType, HandshakeType, AlertDescription } = require('./constants');
const { parseRecords } = require('./record');

// Standard TLS cipher suites that a typical server will accept (RSA + ECDHE)
const ACCEPTABLE_CIPHER_SUITES = new Set([
  // TLS 1.3
  0x1301, 0x1302, 0x1303,
  // TLS 1.2 ECDHE
  0xc02b, 0xc02c, 0xc02f, 0xc030, 0xc023, 0xc024, 0xc027, 0xc028,
  0xc009, 0xc00a, 0xc013, 0xc014,
  // TLS 1.2 RSA
  0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d,
  // TLS 1.2 DHE
  0x0033, 0x0039, 0x0067, 0x006b, 0x009e, 0x009f,
]);

// Parse handshake messages from raw buffer, returns array of {type, offset, length, body}
function parseHandshakeMessages(buffer) {
  const { records } = parseRecords(buffer);
  const messages = [];
  for (const rec of records) {
    if (rec.type !== ContentType.HANDSHAKE) continue;
    let off = 0;
    while (off + 4 <= rec.payload.length) {
      const type = rec.payload[off];
      const msgLen = (rec.payload[off + 1] << 16) | (rec.payload[off + 2] << 8) | rec.payload[off + 3];
      if (off + 4 + msgLen > rec.payload.length) {
        return { messages, error: 'DECODE_ERROR', reason: 'handshake message length exceeds record' };
      }
      messages.push({
        type,
        body: rec.payload.subarray(off + 4, off + 4 + msgLen),
        recordVersion: rec.version,
      });
      off += 4 + msgLen;
    }
    if (off !== rec.payload.length) {
      return { messages, error: 'DECODE_ERROR', reason: 'trailing data after handshake messages' };
    }
  }
  return { messages, error: null };
}

// Validate a ClientHello body (everything after the 4-byte handshake header)
function validateClientHelloBody(body) {
  if (body.length < 38) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'ClientHello too short' };
  }
  let off = 0;

  // client_version (2 bytes)
  const majorVer = body[off]; off++;
  const minorVer = body[off]; off++;
  // Accept 0x0300-0x0304 (SSLv3 through TLS 1.3 legacy)
  if (majorVer !== 3 || minorVer > 4) {
    return { valid: false, alertDescription: AlertDescription.PROTOCOL_VERSION, reason: 'invalid client_version' };
  }

  // random (32 bytes)
  off += 32;

  // session_id (1 byte length + data)
  if (off >= body.length) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'truncated session_id' };
  const sidLen = body[off]; off++;
  if (sidLen > 32 || off + sidLen > body.length) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'invalid session_id length' };
  }
  off += sidLen;

  // cipher_suites (2 byte length + data)
  if (off + 2 > body.length) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'truncated cipher_suites' };
  const csLen = (body[off] << 8) | body[off + 1]; off += 2;
  if (csLen === 0 || csLen % 2 !== 0 || off + csLen > body.length) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'invalid cipher_suites length' };
  }
  // Check if any acceptable cipher suite is offered
  let hasAcceptable = false;
  for (let i = 0; i < csLen; i += 2) {
    const cs = (body[off + i] << 8) | body[off + i + 1];
    if (ACCEPTABLE_CIPHER_SUITES.has(cs)) { hasAcceptable = true; break; }
  }
  if (!hasAcceptable) {
    return { valid: false, alertDescription: AlertDescription.HANDSHAKE_FAILURE, reason: 'no acceptable cipher suite offered' };
  }
  off += csLen;

  // compression_methods (1 byte length + data)
  if (off >= body.length) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'truncated compression_methods' };
  const cmLen = body[off]; off++;
  if (cmLen === 0 || off + cmLen > body.length) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'invalid compression_methods' };
  }
  // Must contain null (0x00) compression
  let hasNull = false;
  for (let i = 0; i < cmLen; i++) {
    if (body[off + i] === 0x00) { hasNull = true; break; }
  }
  if (!hasNull) {
    return { valid: false, alertDescription: AlertDescription.ILLEGAL_PARAMETER, reason: 'compression_methods missing null' };
  }
  off += cmLen;

  // Extensions (optional)
  if (off < body.length) {
    if (off + 2 > body.length) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'truncated extensions length' };
    }
    const extLen = (body[off] << 8) | body[off + 1]; off += 2;
    if (off + extLen > body.length) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'extensions length exceeds body' };
    }
    if (extLen === 0 && off < body.length) {
      return { valid: false, alertDescription: AlertDescription.ILLEGAL_PARAMETER, reason: 'zero extensions length with trailing data' };
    }
    const extEnd = off + extLen;
    const seenExtTypes = new Set();
    while (off + 4 <= extEnd) {
      const extType = (body[off] << 8) | body[off + 1]; off += 2;
      const extDataLen = (body[off] << 8) | body[off + 1]; off += 2;
      if (off + extDataLen > extEnd) {
        return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: `extension ${extType} data exceeds extensions block` };
      }
      if (seenExtTypes.has(extType)) {
        return { valid: false, alertDescription: AlertDescription.ILLEGAL_PARAMETER, reason: `duplicate extension ${extType}` };
      }
      seenExtTypes.add(extType);

      const extData = body.subarray(off, off + extDataLen);

      // Validate specific extensions
      const result = validateExtension(extType, extData);
      if (!result.valid) return result;

      off += extDataLen;
    }
    if (off !== extEnd) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'extensions block length mismatch' };
    }
  }

  return { valid: true };
}

// Validate individual extensions
function validateExtension(extType, data) {
  switch (extType) {
    case 0x0000: // SNI
      return validateSNI(data);
    case 0x0010: // ALPN
      return validateALPN(data);
    case 0x002b: // supported_versions
      return validateSupportedVersions(data);
    case 0x0033: // key_share
      return validateKeyShare(data);
    case 0x0029: // pre_shared_key
      return validatePSK(data);
    default:
      return { valid: true };
  }
}

function validateSNI(data) {
  if (data.length < 2) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'SNI too short' };
  const listLen = (data[0] << 8) | data[1];
  if (2 + listLen > data.length) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'SNI list length overflow' };
  let off = 2;
  let count = 0;
  while (off + 3 <= 2 + listLen) {
    const nameType = data[off]; off++;
    const nameLen = (data[off] << 8) | data[off + 1]; off += 2;
    if (off + nameLen > 2 + listLen) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'SNI entry length overflow' };
    if (nameType === 0 && nameLen > 255) {
      return { valid: false, alertDescription: AlertDescription.UNRECOGNIZED_NAME, reason: 'SNI hostname too long' };
    }
    off += nameLen;
    count++;
  }
  if (count > 1) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'multiple SNI entries' };
  }
  return { valid: true };
}

function validateALPN(data) {
  if (data.length < 2) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'ALPN too short' };
  const listLen = (data[0] << 8) | data[1];
  if (2 + listLen > data.length || listLen !== data.length - 2) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'ALPN list length mismatch' };
  }
  let off = 2;
  let count = 0;
  while (off < 2 + listLen) {
    const protoLen = data[off]; off++;
    if (protoLen === 0) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'ALPN empty protocol name' };
    }
    if (off + protoLen > 2 + listLen) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'ALPN protocol length overflow' };
    }
    off += protoLen;
    count++;
  }
  if (count === 0) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'ALPN no protocols' };
  }
  // Check for oversized list (more than 64KB worth of unknown protocols - likely fuzz)
  if (listLen > 16384) {
    return { valid: false, alertDescription: AlertDescription.NO_APPLICATION_PROTOCOL, reason: 'ALPN list too large' };
  }
  return { valid: true };
}

function validateSupportedVersions(data) {
  if (data.length < 1) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'supported_versions too short' };
  const len = data[0];
  if (len === 0 || len % 2 !== 0 || 1 + len > data.length) {
    return { valid: false, alertDescription: AlertDescription.PROTOCOL_VERSION, reason: 'invalid supported_versions' };
  }
  // Check that at least one valid version is offered
  let hasValid = false;
  for (let i = 1; i < 1 + len; i += 2) {
    const ver = (data[i] << 8) | data[i + 1];
    // Valid versions: 0x0300-0x0304, GREASE values (0x?a?a)
    if (ver >= 0x0300 && ver <= 0x0304) hasValid = true;
    if ((ver & 0x0f0f) === 0x0a0a) hasValid = true; // GREASE
  }
  if (!hasValid) {
    return { valid: false, alertDescription: AlertDescription.PROTOCOL_VERSION, reason: 'no acceptable version in supported_versions' };
  }
  return { valid: true };
}

function validateKeyShare(data) {
  if (data.length < 2) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'key_share too short' };
  const listLen = (data[0] << 8) | data[1];
  if (2 + listLen > data.length) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'key_share length overflow' };
  let off = 2;
  while (off + 4 <= 2 + listLen) {
    const group = (data[off] << 8) | data[off + 1]; off += 2;
    const keyLen = (data[off] << 8) | data[off + 1]; off += 2;
    if (group === 0) {
      return { valid: false, alertDescription: AlertDescription.ILLEGAL_PARAMETER, reason: 'key_share group ID zero' };
    }
    if (keyLen === 0) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'key_share empty key data' };
    }
    if (off + keyLen > 2 + listLen) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'key_share entry length overflow' };
    }
    off += keyLen;
  }
  return { valid: true };
}

function validatePSK(data) {
  if (data.length < 2) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'PSK too short' };
  const identitiesLen = (data[0] << 8) | data[1];
  if (2 + identitiesLen > data.length) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'PSK identities length overflow' };
  }
  return { valid: true };
}

// Validate the full received buffer as a ClientHello
// Returns { valid: true } or { valid: false, alertDescription, reason }
function validateClientHello(rawBuffer) {
  const { records } = parseRecords(rawBuffer);
  if (records.length === 0) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'no records' };
  }

  // Check record sizes (max 16384 bytes payload per TLS record)
  for (const rec of records) {
    if (rec.payload.length > 16384) {
      return { valid: false, alertDescription: AlertDescription.RECORD_OVERFLOW, reason: 'record payload exceeds 16384 bytes' };
    }
  }

  // Check record version
  const firstRec = records[0];
  if (firstRec.type !== ContentType.HANDSHAKE) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'first record not Handshake' };
  }
  const recVer = firstRec.version;
  // Record layer version: accept 0x0300-0x0303 and 0x0301 (common for TLS 1.3 compat)
  if (recVer < 0x0300 || recVer > 0x0303) {
    // Some implementations send 0x0304 but OpenSSL rejects very high versions
    if (recVer > 0x03ff) {
      return { valid: false, alertDescription: AlertDescription.PROTOCOL_VERSION, reason: 'record version too high' };
    }
  }

  // Parse all handshake messages
  const { messages, error } = parseHandshakeMessages(rawBuffer);
  if (error) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: error };
  }

  // First message must be ClientHello
  if (messages.length === 0 || messages[0].type !== HandshakeType.CLIENT_HELLO) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'first handshake message not ClientHello' };
  }

  // Must be exactly one handshake message in initial flight
  if (messages.length > 1) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'multiple handshake messages in initial record' };
  }

  // Validate ClientHello body content
  return validateClientHelloBody(messages[0].body);
}

// Validate the full received buffer as a server flight (ServerHello + Certificate + ServerHelloDone)
function validateServerFlight(rawBuffer) {
  const { messages, error } = parseHandshakeMessages(rawBuffer);
  if (error) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: error };
  }

  if (messages.length < 3) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'insufficient messages in server flight' };
  }

  // Check sequence
  if (messages[0].type !== HandshakeType.SERVER_HELLO) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'first message not ServerHello' };
  }
  if (messages[1].type !== HandshakeType.CERTIFICATE) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'second message not Certificate' };
  }
  if (messages[2].type !== HandshakeType.SERVER_HELLO_DONE) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'third message not ServerHelloDone' };
  }
  if (messages.length > 3) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'extra messages after ServerHelloDone' };
  }

  // Validate ServerHello body
  const shBody = messages[0].body;
  const shResult = validateServerHelloBody(shBody);
  if (!shResult.valid) return shResult;

  // Validate Certificate body
  const certBody = messages[1].body;
  const certResult = validateCertificateBody(certBody);
  if (!certResult.valid) return certResult;

  return { valid: true };
}

function validateServerHelloBody(body) {
  if (body.length < 38) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'ServerHello too short' };
  }
  let off = 0;

  // server_version
  const majorVer = body[off]; off++;
  const minorVer = body[off]; off++;
  if (majorVer !== 3 || minorVer > 3) {
    return { valid: false, alertDescription: AlertDescription.PROTOCOL_VERSION, reason: 'invalid server_version' };
  }

  // random (32 bytes)
  off += 32;

  // session_id
  const sidLen = body[off]; off++;
  if (sidLen > 32 || off + sidLen > body.length) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'invalid session_id' };
  }
  off += sidLen;

  // cipher_suite (2 bytes)
  if (off + 2 > body.length) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'truncated cipher suite' };
  const cs = (body[off] << 8) | body[off + 1]; off += 2;
  if (!ACCEPTABLE_CIPHER_SUITES.has(cs)) {
    return { valid: false, alertDescription: AlertDescription.ILLEGAL_PARAMETER, reason: 'unacceptable cipher suite selected' };
  }

  // compression_method (1 byte, must be 0)
  if (off >= body.length) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'truncated compression' };
  const cm = body[off]; off++;
  if (cm !== 0) {
    return { valid: false, alertDescription: AlertDescription.ILLEGAL_PARAMETER, reason: 'non-null compression method' };
  }

  // Extensions (optional) - basic length check
  if (off < body.length) {
    if (off + 2 > body.length) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'truncated extensions length' };
    }
    const extLen = (body[off] << 8) | body[off + 1]; off += 2;
    if (off + extLen > body.length) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'extensions exceed body' };
    }

    // Check for ALPN in extensions
    const extEnd = off + extLen;
    while (off + 4 <= extEnd) {
      const extType = (body[off] << 8) | body[off + 1]; off += 2;
      const extDataLen = (body[off] << 8) | body[off + 1]; off += 2;
      if (off + extDataLen > extEnd) {
        return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'extension data overflow' };
      }

      // ALPN (0x0010): check server selected a known protocol
      if (extType === 0x0010) {
        if (extDataLen < 4) {
          return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'ALPN too short' };
        }
        const alpnListLen = (body[off] << 8) | body[off + 1];
        if (alpnListLen + 2 !== extDataLen) {
          return { valid: false, alertDescription: AlertDescription.UNSUPPORTED_EXTENSION, reason: 'ALPN length mismatch' };
        }
        const protoLen = body[off + 2];
        if (protoLen === 0) {
          return { valid: false, alertDescription: AlertDescription.UNSUPPORTED_EXTENSION, reason: 'ALPN empty protocol' };
        }
        const proto = body.subarray(off + 3, off + 3 + protoLen).toString('ascii');
        if (!['h2', 'http/1.1', 'http/1.0'].includes(proto)) {
          return { valid: false, alertDescription: AlertDescription.UNSUPPORTED_EXTENSION, reason: 'ALPN unknown protocol: ' + proto };
        }
      }

      off += extDataLen;
    }
  }

  return { valid: true };
}

function validateCertificateBody(body) {
  if (body.length < 3) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'Certificate message too short' };
  }

  // certificates_length (3 bytes)
  const chainLen = (body[0] << 16) | (body[1] << 8) | body[2];
  if (3 + chainLen > body.length) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'certificate chain length overflow' };
  }
  if (3 + chainLen < body.length) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'trailing data after certificate chain' };
  }

  // Parse certificate entries
  let off = 3;
  let certCount = 0;
  const chainEnd = 3 + chainLen;
  while (off + 3 <= chainEnd) {
    const certLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2]; off += 3;
    if (certLen === 0) {
      return { valid: false, alertDescription: AlertDescription.BAD_CERTIFICATE, reason: 'zero-length certificate entry' };
    }
    if (off + certLen > chainEnd) {
      return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'certificate entry length overflow' };
    }
    // Minimal DER check: first byte should be 0x30 (SEQUENCE)
    if (body[off] !== 0x30) {
      return { valid: false, alertDescription: AlertDescription.BAD_CERTIFICATE, reason: 'certificate not a DER SEQUENCE' };
    }
    off += certLen;
    certCount++;
  }

  if (certCount === 0) {
    return { valid: false, alertDescription: AlertDescription.BAD_CERTIFICATE, reason: 'empty certificate chain' };
  }

  if (certCount > 50) {
    return { valid: false, alertDescription: AlertDescription.RECORD_OVERFLOW, reason: 'excessive certificate chain depth' };
  }

  if (off !== chainEnd) {
    return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: 'certificate chain parse error' };
  }

  return { valid: true };
}

// Validate ClientKeyExchange content (basic checks)
// The WB-server always negotiates TLS 1.2, so CKE record version must be 0x0303
function validateClientKeyExchange(rawBuffer) {
  const { records } = parseRecords(rawBuffer);
  // Check record version is consistent with negotiated TLS 1.2
  for (const rec of records) {
    if (rec.type === ContentType.HANDSHAKE) {
      // After TLS 1.2 negotiation, record version should be 0x0303
      if (rec.version !== 0x0303) {
        return { valid: false, alertDescription: AlertDescription.PROTOCOL_VERSION, reason: 'record version mismatch in CKE (expected TLS 1.2)' };
      }
    }
  }

  const { messages, error } = parseHandshakeMessages(rawBuffer);
  if (error) return { valid: false, alertDescription: AlertDescription.DECODE_ERROR, reason: error };

  // Should contain CLIENT_KEY_EXCHANGE
  const hasCKE = messages.some(m => m.type === HandshakeType.CLIENT_KEY_EXCHANGE);
  if (!hasCKE) {
    return { valid: false, alertDescription: AlertDescription.UNEXPECTED_MESSAGE, reason: 'no ClientKeyExchange message' };
  }

  return { valid: true };
}

/**
 * Detailed parser for ClientHello to extract parameters for scenario generation.
 */
function parseClientHello(body) {
  if (body.length < 38) return null;
  let off = 0;

  const version = (body[off] << 8) | body[off + 1]; off += 2;
  const random = body.subarray(off, off + 32); off += 32;
  const sidLen = body[off]; off++;
  const sessionId = body.subarray(off, off + sidLen); off += sidLen;

  const csLen = (body[off] << 8) | body[off + 1]; off += 2;
  const cipherSuites = [];
  for (let i = 0; i < csLen; i += 2) {
    if (off + i + 1 < body.length) {
      cipherSuites.push((body[off + i] << 8) | body[off + i + 1]);
    }
  }
  off += csLen;

  if (off >= body.length) return { version, random, sessionId, cipherSuites, compressionMethods: [], extensions: [] };
  const cmLen = body[off]; off++;
  const compressionMethods = Array.from(body.subarray(off, off + cmLen));
  off += cmLen;

  const extensions = [];
  if (off + 2 <= body.length) {
    const extLen = (body[off] << 8) | body[off + 1]; off += 2;
    const extEnd = Math.min(off + extLen, body.length);
    while (off + 4 <= extEnd) {
      const type = (body[off] << 8) | body[off + 1]; off += 2;
      const len = (body[off] << 8) | body[off + 1]; off += 2;
      const data = body.subarray(off, off + len);
      extensions.push({ type, data });
      off += len;
    }
  }

  return {
    version, random, sessionId, cipherSuites, compressionMethods, extensions
  };
}

/**
 * Detailed parser for ServerHello to extract chosen parameters.
 */
function parseServerHello(body) {
  if (body.length < 38) return null;
  let off = 0;
  const version = (body[off] << 8) | body[off + 1]; off += 2;
  const random = body.subarray(off, off + 32); off += 32;
  const sidLen = body[off]; off++;
  const sessionId = body.subarray(off, off + sidLen); off += sidLen;
  const cipherSuite = (body[off] << 8) | body[off + 1]; off += 2;
  const compressionMethod = body[off]; off++;

  const extensions = [];
  if (off + 2 <= body.length) {
    const extLen = (body[off] << 8) | body[off + 1]; off += 2;
    const extEnd = Math.min(off + extLen, body.length);
    while (off + 4 <= extEnd) {
      const type = (body[off] << 8) | body[off + 1]; off += 2;
      const len = (body[off] << 8) | body[off + 1]; off += 2;
      const data = body.subarray(off, off + len);
      extensions.push({ type, data });
      off += len;
    }
  }

  return { version, random, sessionId, cipherSuite, compressionMethod, extensions };
}

/**
 * Parse CertificateRequest handshake message.
 */
function parseCertificateRequest(body) {
  // TLS 1.2: certificate_types(1+N) + supported_signature_algorithms(2+N) + certificate_authorities(2+N)
  // This is a simplified parser.
  try {
    let off = 0;
    const typesLen = body[off++];
    const types = Array.from(body.subarray(off, off + typesLen));
    off += typesLen;
    const sigAlgsLen = (body[off] << 8) | body[off + 1]; off += 2;
    const sigAlgs = [];
    for (let i = 0; i < sigAlgsLen; i += 2) {
      sigAlgs.push((body[off + i] << 8) | body[off + i + 1]);
    }
    return { types, sigAlgs };
  } catch (_) {
    return {};
  }
}

/**
 * Detect STARTTLS plain text before actual TLS records.
 * Returns { plain: Buffer, tls: Buffer } or null if no TLS record found.
 */
function parseSTARTTLS(buffer) {
  for (let i = 0; i < buffer.length - 5; i++) {
    // Look for TLS Record Header: [ContentType][VersionMajor:0x03][VersionMinor:0x00-0x04]
    if ((buffer[i] >= 0x14 && buffer[i] <= 0x18) && buffer[i + 1] === 0x03 && buffer[i + 2] <= 0x04) {
      return {
        plain: buffer.subarray(0, i),
        tls: buffer.subarray(i)
      };
    }
  }
  return null;
}

/**
 * Extract specific extension data from parsed extensions array.
 */
function getExtension(extensions, type) {
  return extensions.find(e => e.type === type);
}

/**
 * Parse SNI extension data to extract the hostname.
 */
function parseSNI(data) {
  try {
    const listLen = (data[0] << 8) | data[1];
    let off = 2;
    while (off + 3 <= 2 + listLen && off + 3 <= data.length) {
      const nameType = data[off]; off++;
      const nameLen = (data[off] << 8) | data[off + 1]; off += 2;
      if (nameType === 0) return data.subarray(off, off + nameLen).toString('ascii');
      off += nameLen;
    }
  } catch (_) {}
  return null;
}

/**
 * Parse ALPN extension data to extract protocol names.
 */
function parseALPN(data) {
  try {
    const listLen = (data[0] << 8) | data[1];
    let off = 2;
    const protocols = [];
    while (off < 2 + listLen && off < data.length) {
      const len = data[off]; off++;
      protocols.push(data.subarray(off, off + len).toString('ascii'));
      off += len;
    }
    return protocols;
  } catch (_) {}
  return [];
}

module.exports = {
  validateClientHello,
  validateServerFlight,
  validateClientKeyExchange,
  parseHandshakeMessages,
  parseClientHello,
  parseServerHello,
  parseCertificateRequest,
  parseSTARTTLS,
  getExtension,
  parseSNI,
  parseALPN,
};
