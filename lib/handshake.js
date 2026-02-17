// TLS Handshake Message Builders — construct raw handshake messages byte-by-byte
const crypto = require('crypto');
const { buildRecord } = require('./record');
const {
  ContentType, Version, HandshakeType,
  CipherSuite, ExtensionType, CompressionMethod,
  NamedGroup, SignatureScheme, ECPointFormat,
} = require('./constants');

// Default cipher suites for a realistic ClientHello
const DEFAULT_CIPHER_SUITES = [
  CipherSuite.TLS_AES_128_GCM_SHA256,
  CipherSuite.TLS_AES_256_GCM_SHA384,
  CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
  CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
  CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
];

/**
 * Build a handshake message wrapper: [type:1][length:3][body:N]
 */
function buildHandshakeMessage(type, body) {
  const buf = Buffer.alloc(4 + body.length);
  buf[0] = type;
  buf[1] = (body.length >> 16) & 0xff;
  buf[2] = (body.length >> 8) & 0xff;
  buf[3] = body.length & 0xff;
  body.copy(buf, 4);
  return buf;
}

/**
 * Wrap handshake message in a TLS record
 */
function buildHandshakeRecord(type, body, version = Version.TLS_1_2) {
  const hsMsg = buildHandshakeMessage(type, body);
  return buildRecord(ContentType.HANDSHAKE, version, hsMsg);
}

/**
 * Build SNI extension
 */
function buildSNIExtension(hostname) {
  const nameBytes = Buffer.from(hostname, 'ascii');
  // ServerNameList: length(2) + [ type(1) + name_length(2) + name(N) ]
  const entryLen = 1 + 2 + nameBytes.length;
  const listLen = 2 + entryLen;
  const buf = Buffer.alloc(listLen);
  buf.writeUInt16BE(entryLen, 0);     // server_name_list length
  buf[2] = 0;                          // host_name type
  buf.writeUInt16BE(nameBytes.length, 3);
  nameBytes.copy(buf, 5);
  return buf;
}

/**
 * Build supported_versions extension (TLS 1.3 style)
 */
function buildSupportedVersionsExtension(versions) {
  const buf = Buffer.alloc(1 + versions.length * 2);
  buf[0] = versions.length * 2; // length of version list
  for (let i = 0; i < versions.length; i++) {
    buf.writeUInt16BE(versions[i], 1 + i * 2);
  }
  return buf;
}

/**
 * Build supported_groups extension
 */
function buildSupportedGroupsExtension(groups) {
  const buf = Buffer.alloc(2 + groups.length * 2);
  buf.writeUInt16BE(groups.length * 2, 0);
  for (let i = 0; i < groups.length; i++) {
    buf.writeUInt16BE(groups[i], 2 + i * 2);
  }
  return buf;
}

/**
 * Build signature_algorithms extension
 */
function buildSignatureAlgorithmsExtension(schemes) {
  const buf = Buffer.alloc(2 + schemes.length * 2);
  buf.writeUInt16BE(schemes.length * 2, 0);
  for (let i = 0; i < schemes.length; i++) {
    buf.writeUInt16BE(schemes[i], 2 + i * 2);
  }
  return buf;
}

/**
 * Build ec_point_formats extension
 */
function buildECPointFormatsExtension() {
  return Buffer.from([0x01, ECPointFormat.UNCOMPRESSED]); // length=1, uncompressed
}

/**
 * Build a key_share extension with a dummy x25519 key
 */
function buildKeyShareExtension() {
  const keyData = crypto.randomBytes(32); // dummy x25519 public key
  // client_shares length (2) + group(2) + key_len(2) + key(32) = 36 + 2 = 38
  const buf = Buffer.alloc(2 + 2 + 2 + 32);
  buf.writeUInt16BE(2 + 2 + 32, 0); // client_shares length
  buf.writeUInt16BE(NamedGroup.X25519, 2); // group
  buf.writeUInt16BE(32, 4); // key_exchange length
  keyData.copy(buf, 6);
  return buf;
}

/**
 * Build an extension entry: [type:2][length:2][data:N]
 */
function buildExtension(type, data) {
  const buf = Buffer.alloc(4 + data.length);
  buf.writeUInt16BE(type, 0);
  buf.writeUInt16BE(data.length, 2);
  data.copy(buf, 4);
  return buf;
}

/**
 * Build a ClientHello message body (without handshake header)
 */
function buildClientHelloBody(opts = {}) {
  const version = opts.version || Version.TLS_1_2;
  const random = opts.random || crypto.randomBytes(32);
  const sessionId = opts.sessionId || crypto.randomBytes(32);
  const cipherSuites = opts.cipherSuites || DEFAULT_CIPHER_SUITES;
  const hostname = opts.hostname || 'localhost';
  const compressionMethods = opts.compressionMethods || [CompressionMethod.NULL];
  const includeExtensions = opts.includeExtensions !== false;
  const extraExtensions = opts.extraExtensions || [];
  const duplicateExtensions = opts.duplicateExtensions || false;

  const parts = [];

  // client_version (2 bytes)
  const vBuf = Buffer.alloc(2);
  vBuf.writeUInt16BE(version, 0);
  parts.push(vBuf);

  // random (32 bytes)
  parts.push(random.length === 32 ? random : random.slice(0, 32));

  // session_id (1 byte length + data)
  const sidLen = Buffer.from([sessionId.length]);
  parts.push(sidLen);
  parts.push(sessionId);

  // cipher_suites (2 byte length + 2 bytes each)
  const csLen = Buffer.alloc(2);
  csLen.writeUInt16BE(cipherSuites.length * 2, 0);
  parts.push(csLen);
  for (const cs of cipherSuites) {
    const csBuf = Buffer.alloc(2);
    csBuf.writeUInt16BE(cs, 0);
    parts.push(csBuf);
  }

  // compression_methods (1 byte length + 1 byte each)
  parts.push(Buffer.from([compressionMethods.length]));
  parts.push(Buffer.from(compressionMethods));

  // extensions
  if (includeExtensions) {
    const extensions = [];

    // SNI
    extensions.push(buildExtension(ExtensionType.SERVER_NAME, buildSNIExtension(hostname)));

    // supported_groups
    extensions.push(buildExtension(ExtensionType.SUPPORTED_GROUPS,
      buildSupportedGroupsExtension([NamedGroup.X25519, NamedGroup.SECP256R1, NamedGroup.SECP384R1])));

    // signature_algorithms
    extensions.push(buildExtension(ExtensionType.SIGNATURE_ALGORITHMS,
      buildSignatureAlgorithmsExtension([
        SignatureScheme.ECDSA_SECP256R1_SHA256,
        SignatureScheme.RSA_PSS_RSAE_SHA256,
        SignatureScheme.RSA_PKCS1_SHA256,
        SignatureScheme.ECDSA_SECP384R1_SHA384,
        SignatureScheme.RSA_PSS_RSAE_SHA384,
        SignatureScheme.RSA_PKCS1_SHA384,
      ])));

    // ec_point_formats
    extensions.push(buildExtension(ExtensionType.EC_POINT_FORMATS, buildECPointFormatsExtension()));

    // supported_versions (advertise TLS 1.3 + 1.2)
    extensions.push(buildExtension(ExtensionType.SUPPORTED_VERSIONS,
      buildSupportedVersionsExtension([Version.TLS_1_3, Version.TLS_1_2])));

    // key_share
    extensions.push(buildExtension(ExtensionType.KEY_SHARE, buildKeyShareExtension()));

    // renegotiation_info (empty)
    extensions.push(buildExtension(ExtensionType.RENEGOTIATION_INFO, Buffer.from([0x00])));

    // Duplicate extensions if requested
    if (duplicateExtensions) {
      extensions.push(buildExtension(ExtensionType.SERVER_NAME, buildSNIExtension(hostname)));
    }

    // Extra extensions
    for (const ext of extraExtensions) {
      extensions.push(buildExtension(ext.type, ext.data));
    }

    const extData = Buffer.concat(extensions);
    const extLen = Buffer.alloc(2);
    extLen.writeUInt16BE(extData.length, 0);
    parts.push(extLen);
    parts.push(extData);
  }

  return Buffer.concat(parts);
}

/**
 * Build a full ClientHello TLS record
 */
function buildClientHello(opts = {}) {
  const body = buildClientHelloBody(opts);
  const recordVersion = opts.recordVersion || Version.TLS_1_0; // record layer typically says 1.0
  return buildHandshakeRecord(HandshakeType.CLIENT_HELLO, body, recordVersion);
}

/**
 * Build a ServerHello message body
 */
function buildServerHelloBody(opts = {}) {
  const version = opts.version || Version.TLS_1_2;
  const random = opts.random || crypto.randomBytes(32);
  const sessionId = opts.sessionId || crypto.randomBytes(32);
  const cipherSuite = opts.cipherSuite || CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
  const compressionMethod = opts.compressionMethod || CompressionMethod.NULL;

  const parts = [];
  const vBuf = Buffer.alloc(2);
  vBuf.writeUInt16BE(version, 0);
  parts.push(vBuf);
  parts.push(random);
  parts.push(Buffer.from([sessionId.length]));
  parts.push(sessionId);
  const csBuf = Buffer.alloc(2);
  csBuf.writeUInt16BE(cipherSuite, 0);
  parts.push(csBuf);
  parts.push(Buffer.from([compressionMethod]));

  // Extensions (minimal)
  const extensions = [];
  extensions.push(buildExtension(ExtensionType.RENEGOTIATION_INFO, Buffer.from([0x00])));

  if (opts.extraExtensions) {
    for (const ext of opts.extraExtensions) {
      extensions.push(buildExtension(ext.type, ext.data));
    }
  }

  const extData = Buffer.concat(extensions);
  const extLen = Buffer.alloc(2);
  extLen.writeUInt16BE(extData.length, 0);
  parts.push(extLen);
  parts.push(extData);

  return Buffer.concat(parts);
}

function buildServerHello(opts = {}) {
  const body = buildServerHelloBody(opts);
  return buildHandshakeRecord(HandshakeType.SERVER_HELLO, body, opts.recordVersion || Version.TLS_1_2);
}

/**
 * Build a Certificate message with dummy/empty certificate
 */
function buildCertificate(opts = {}) {
  const version = opts.recordVersion || Version.TLS_1_2;
  let certsData;
  if (opts.empty) {
    certsData = Buffer.from([0x00, 0x00, 0x00]); // certificates_length = 0
  } else {
    // Dummy self-signed cert (just random bytes, enough to look like a cert)
    const dummyCert = crypto.randomBytes(opts.certSize || 512);
    const certEntry = Buffer.alloc(3 + dummyCert.length);
    certEntry[0] = (dummyCert.length >> 16) & 0xff;
    certEntry[1] = (dummyCert.length >> 8) & 0xff;
    certEntry[2] = dummyCert.length & 0xff;
    dummyCert.copy(certEntry, 3);

    const totalLen = certEntry.length;
    certsData = Buffer.alloc(3 + totalLen);
    certsData[0] = (totalLen >> 16) & 0xff;
    certsData[1] = (totalLen >> 8) & 0xff;
    certsData[2] = totalLen & 0xff;
    certEntry.copy(certsData, 3);
  }

  return buildHandshakeRecord(HandshakeType.CERTIFICATE, certsData, version);
}

/**
 * Build ServerHelloDone (empty body)
 */
function buildServerHelloDone(version = Version.TLS_1_2) {
  return buildHandshakeRecord(HandshakeType.SERVER_HELLO_DONE, Buffer.alloc(0), version);
}

/**
 * Build ClientKeyExchange with dummy premaster secret
 */
function buildClientKeyExchange(opts = {}) {
  const version = opts.recordVersion || Version.TLS_1_2;
  // Dummy RSA-encrypted premaster secret
  const pms = crypto.randomBytes(opts.size || 130);
  const body = Buffer.alloc(2 + pms.length);
  body.writeUInt16BE(pms.length, 0);
  pms.copy(body, 2);
  return buildHandshakeRecord(HandshakeType.CLIENT_KEY_EXCHANGE, body, version);
}

/**
 * Build Finished with dummy verify data
 */
function buildFinished(opts = {}) {
  const version = opts.recordVersion || Version.TLS_1_2;
  const verifyData = opts.verifyData || crypto.randomBytes(12);
  return buildHandshakeRecord(HandshakeType.FINISHED, verifyData, version);
}

/**
 * Build EncryptedExtensions (TLS 1.3, empty)
 */
function buildEncryptedExtensions(version = Version.TLS_1_2) {
  const body = Buffer.from([0x00, 0x00]); // extensions length = 0
  return buildHandshakeRecord(HandshakeType.ENCRYPTED_EXTENSIONS, body, version);
}

/**
 * Build ServerKeyExchange with dummy data
 */
function buildServerKeyExchange(opts = {}) {
  const version = opts.recordVersion || Version.TLS_1_2;
  const data = crypto.randomBytes(opts.size || 200);
  return buildHandshakeRecord(HandshakeType.SERVER_KEY_EXCHANGE, data, version);
}

/**
 * Pack multiple handshake messages into a single TLS record
 */
function buildMultiHandshakeRecord(messages, version = Version.TLS_1_2) {
  // messages is array of { type, body } objects
  const hsMsgs = messages.map(m => buildHandshakeMessage(m.type, m.body));
  const payload = Buffer.concat(hsMsgs);
  return buildRecord(ContentType.HANDSHAKE, version, payload);
}

/**
 * Build an ALPN extension
 * protocols: array of protocol name strings, e.g. ['h2', 'http/1.1']
 */
function buildALPNExtension(protocols) {
  const entries = protocols.map(p => {
    const nameBytes = Buffer.from(p, 'ascii');
    const entry = Buffer.alloc(1 + nameBytes.length);
    entry[0] = nameBytes.length;
    nameBytes.copy(entry, 1);
    return entry;
  });
  const protocolList = Buffer.concat(entries);
  const buf = Buffer.alloc(2 + protocolList.length);
  buf.writeUInt16BE(protocolList.length, 0);
  protocolList.copy(buf, 2);
  return buf;
}

/**
 * Build a PQC key_share extension entry for a given named group
 * Generates a key share of the specified size (PQC keys are much larger than ECDH)
 */
function buildPQCKeyShareExtension(groups) {
  // groups: array of { group: namedGroupId, keySize: number }
  const entries = groups.map(g => {
    const keyData = crypto.randomBytes(g.keySize);
    const entry = Buffer.alloc(2 + 2 + keyData.length);
    entry.writeUInt16BE(g.group, 0);
    entry.writeUInt16BE(keyData.length, 2);
    keyData.copy(entry, 4);
    return entry;
  });
  const sharesData = Buffer.concat(entries);
  const buf = Buffer.alloc(2 + sharesData.length);
  buf.writeUInt16BE(sharesData.length, 0);
  sharesData.copy(buf, 2);
  return buf;
}

/**
 * Build a multi-hostname SNI extension (multiple server_name entries)
 */
function buildMultiSNIExtension(hostnames) {
  const entries = hostnames.map(h => {
    const nameBytes = Buffer.from(h, 'ascii');
    const entry = Buffer.alloc(1 + 2 + nameBytes.length);
    entry[0] = 0; // host_name type
    entry.writeUInt16BE(nameBytes.length, 1);
    nameBytes.copy(entry, 3);
    return entry;
  });
  const entriesData = Buffer.concat(entries);
  const buf = Buffer.alloc(2 + entriesData.length);
  buf.writeUInt16BE(entriesData.length, 0);
  entriesData.copy(buf, 2);
  return buf;
}

module.exports = {
  buildHandshakeMessage,
  buildHandshakeRecord,
  buildClientHello,
  buildClientHelloBody,
  buildServerHello,
  buildServerHelloBody,
  buildCertificate,
  buildServerHelloDone,
  buildClientKeyExchange,
  buildFinished,
  buildEncryptedExtensions,
  buildServerKeyExchange,
  buildMultiHandshakeRecord,
  buildExtension,
  buildSNIExtension,
  buildMultiSNIExtension,
  buildSupportedVersionsExtension,
  buildALPNExtension,
  buildPQCKeyShareExtension,
  DEFAULT_CIPHER_SUITES,
};
