// TLS Protocol Constants for raw record construction

// Content types
const ContentType = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23,
  HEARTBEAT: 24,
};

// TLS versions (big-endian uint16)
const Version = {
  SSL_3_0: 0x0300,
  TLS_1_0: 0x0301,
  TLS_1_1: 0x0302,
  TLS_1_2: 0x0303,
  TLS_1_3: 0x0304,
};

const VersionName = {
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3',
};

// Handshake message types
const HandshakeType = {
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  NEW_SESSION_TICKET: 4,
  END_OF_EARLY_DATA: 5,
  ENCRYPTED_EXTENSIONS: 8,
  CERTIFICATE: 11,
  SERVER_KEY_EXCHANGE: 12,
  CERTIFICATE_REQUEST: 13,
  SERVER_HELLO_DONE: 14,
  CERTIFICATE_VERIFY: 15,
  CLIENT_KEY_EXCHANGE: 16,
  FINISHED: 20,
  KEY_UPDATE: 24,
  MESSAGE_HASH: 254,
};

const HandshakeTypeName = {};
for (const [k, v] of Object.entries(HandshakeType)) HandshakeTypeName[v] = k;

// Alert levels
const AlertLevel = {
  WARNING: 1,
  FATAL: 2,
};

// Alert descriptions
const AlertDescription = {
  CLOSE_NOTIFY: 0,
  UNEXPECTED_MESSAGE: 10,
  BAD_RECORD_MAC: 20,
  DECRYPTION_FAILED: 21,
  RECORD_OVERFLOW: 22,
  DECOMPRESSION_FAILURE: 30,
  HANDSHAKE_FAILURE: 40,
  NO_CERTIFICATE: 41,
  BAD_CERTIFICATE: 42,
  UNSUPPORTED_CERTIFICATE: 43,
  CERTIFICATE_REVOKED: 44,
  CERTIFICATE_EXPIRED: 45,
  CERTIFICATE_UNKNOWN: 46,
  ILLEGAL_PARAMETER: 47,
  UNKNOWN_CA: 48,
  ACCESS_DENIED: 49,
  DECODE_ERROR: 50,
  DECRYPT_ERROR: 51,
  PROTOCOL_VERSION: 70,
  INSUFFICIENT_SECURITY: 71,
  INTERNAL_ERROR: 80,
  INAPPROPRIATE_FALLBACK: 86,
  USER_CANCELED: 90,
  NO_RENEGOTIATION: 100,
  MISSING_EXTENSION: 109,
  UNSUPPORTED_EXTENSION: 110,
  UNRECOGNIZED_NAME: 112,
  NO_APPLICATION_PROTOCOL: 120,
};

const AlertDescriptionName = {};
for (const [k, v] of Object.entries(AlertDescription)) AlertDescriptionName[v] = k;

// Cipher suites (uint16 codes)
const CipherSuite = {
  TLS_RSA_WITH_AES_128_CBC_SHA:              0x002f,
  TLS_RSA_WITH_AES_256_CBC_SHA:              0x0035,
  TLS_RSA_WITH_AES_128_CBC_SHA256:           0x003c,
  TLS_RSA_WITH_AES_256_CBC_SHA256:           0x003d,
  TLS_RSA_WITH_AES_128_GCM_SHA256:           0x009c,
  TLS_RSA_WITH_AES_256_GCM_SHA384:           0x009d,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:        0xc013,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:        0xc014,
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:     0xc027,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:     0xc028,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:     0xc02f,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:     0xc030,
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:   0xc02b,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:   0xc02c,
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:      0xcca8,
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:    0xcca9,
  // TLS 1.3
  TLS_AES_128_GCM_SHA256:                    0x1301,
  TLS_AES_256_GCM_SHA384:                    0x1302,
  TLS_CHACHA20_POLY1305_SHA256:              0x1303,
  // Insecure (for fuzzing & CVE detection)
  TLS_RSA_WITH_RC4_128_SHA:                  0x0005,
  TLS_RSA_WITH_RC4_128_MD5:                  0x0004,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA:             0x000a,
  TLS_RSA_WITH_NULL_SHA:                     0x0002,
  TLS_RSA_WITH_NULL_SHA256:                  0x003b,
  TLS_RSA_WITH_NULL_MD5:                     0x0001,
  TLS_RSA_WITH_DES_CBC_SHA:                  0x0009,
  // Export ciphers (FREAK / Logjam)
  TLS_RSA_EXPORT_WITH_RC4_40_MD5:            0x0003,
  TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:        0x0006,
  TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:         0x0008,
  TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:     0x0014,
  TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5:        0x0017,
  TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA:     0x0019,
  // DHE suites (for Logjam testing)
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA:          0x0033,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA:          0x0039,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:         0x0016,
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:       0x009e,
  // Anonymous DH (no authentication)
  TLS_DH_ANON_WITH_AES_128_CBC_SHA:          0x0034,
  TLS_DH_ANON_WITH_AES_256_CBC_SHA:          0x003a,
  TLS_DH_ANON_WITH_RC4_128_MD5:              0x0018,
  // TLS_FALLBACK_SCSV (RFC 7507)
  TLS_FALLBACK_SCSV:                         0x5600,
  // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
  TLS_EMPTY_RENEGOTIATION_INFO_SCSV:         0x00ff,
};

const CipherSuiteName = {};
for (const [k, v] of Object.entries(CipherSuite)) CipherSuiteName[v] = k;

// Extension types
const ExtensionType = {
  SERVER_NAME: 0,
  EC_POINT_FORMATS: 11,
  SUPPORTED_GROUPS: 10,
  SIGNATURE_ALGORITHMS: 13,
  APPLICATION_LAYER_PROTOCOL_NEGOTIATION: 16,
  SIGNED_CERTIFICATE_TIMESTAMP: 18,
  EXTENDED_MASTER_SECRET: 23,
  COMPRESS_CERTIFICATE: 27,
  SESSION_TICKET: 35,
  PRE_SHARED_KEY: 41,
  EARLY_DATA: 42,
  SUPPORTED_VERSIONS: 43,
  PSK_KEY_EXCHANGE_MODES: 45,
  KEY_SHARE: 51,
  RENEGOTIATION_INFO: 0xff01,
  HEARTBEAT: 15,
  SESSION_TICKET_TLS: 35,
  ENCRYPT_THEN_MAC: 22,
};

// Compression methods
const CompressionMethod = {
  NULL: 0,
  DEFLATE: 1,
};

// Named groups (for supported_groups extension)
const NamedGroup = {
  SECP192R1: 0x0013,
  SECP224R1: 0x0015,
  SECP256R1: 0x0017,
  SECP384R1: 0x0018,
  SECP521R1: 0x0019,
  X25519: 0x001d,
  X448: 0x001e,
  FFDHE2048: 0x0100,
  FFDHE3072: 0x0101,
  // Post-Quantum / ML-KEM (FIPS 203) named groups — IANA TLS Supported Groups registry
  X25519_MLKEM768: 0x11ec,      // 4588: Hybrid X25519 + ML-KEM-768
  SECP256R1_MLKEM768: 0x11eb,   // 4587: Hybrid P-256 + ML-KEM-768
  SECP384R1_MLKEM1024: 0x11ed,  // 4589: Hybrid P-384 + ML-KEM-1024
  MLKEM512: 0x0200,             // 512: Standalone ML-KEM-512
  MLKEM768: 0x0201,             // 513: Standalone ML-KEM-768
  MLKEM1024: 0x0202,            // 514: Standalone ML-KEM-1024
  X25519_KYBER768_DRAFT: 0x6399, // Chrome/Firefox experimental Kyber draft
  X25519_KYBER512_DRAFT: 0xfe30, // Experimental draft
  X25519_KYBER1024_DRAFT: 0xfe31, // Experimental draft
  X25519_FRODOKEM_640_SHAKE: 0xfe50, // Experimental hybrid
  X25519_CLASSIC_MCELIECE_348864: 0xfe60, // Experimental hybrid
};

// Signature algorithms
const SignatureScheme = {
  RSA_PKCS1_SHA256: 0x0401,
  RSA_PKCS1_SHA384: 0x0501,
  RSA_PKCS1_SHA512: 0x0601,
  ECDSA_SECP256R1_SHA256: 0x0403,
  ECDSA_SECP384R1_SHA384: 0x0503,
  ECDSA_SECP521R1_SHA512: 0x0603,
  RSA_PSS_RSAE_SHA256: 0x0804,
  RSA_PSS_RSAE_SHA384: 0x0805,
  RSA_PSS_RSAE_SHA512: 0x0806,
};

const NamedGroupName = {};
for (const [k, v] of Object.entries(NamedGroup)) NamedGroupName[v] = k;

const SignatureSchemeName = {};
for (const [k, v] of Object.entries(SignatureScheme)) SignatureSchemeName[v] = k;

// Alert cause hints — human-readable explanations for common alert descriptions
const AlertCauseHint = {
  0: 'Connection closed normally',
  10: 'Server received a message it did not expect at this point',
  20: 'Record MAC verification failed — possible tampering or key mismatch',
  21: 'Decryption failed (deprecated in TLS 1.2+)',
  22: 'Record exceeded maximum allowed length',
  30: 'Decompression failure (CRIME attack vector)',
  40: 'No common cipher suite or protocol version between client and server',
  42: 'A certificate in the chain was deemed unacceptable (untrusted CA, wrong identity, or policy violation)',
  43: 'Certificate type is not supported',
  44: 'Certificate has been revoked',
  45: 'Certificate has expired',
  46: 'Certificate is unknown or untrusted',
  47: 'A handshake parameter was out of range or inconsistent',
  48: 'Certificate issuer (CA) is not trusted',
  49: 'Access denied by server policy',
  50: 'Message could not be decoded — malformed handshake',
  51: 'Decrypt error — signature verification or Finished verify data mismatch',
  70: 'Client and server do not support a common TLS version',
  71: 'Server requires stronger cipher suites than offered',
  80: 'Server hit an internal error during handshake processing',
  86: 'Inappropriate fallback detected (RFC 7507 TLS_FALLBACK_SCSV)',
  90: 'Handshake cancelled by user/application',
  100: 'Renegotiation not permitted',
  109: 'A required extension is missing from the handshake',
  110: 'An unsupported extension was received',
  112: 'Server does not recognize the SNI hostname',
  120: 'No common application protocol (ALPN mismatch)',
};

// EC point formats
const ECPointFormat = {
  UNCOMPRESSED: 0,
};

// Heartbeat (RFC 6520)
const HeartbeatMessageType = {
  HEARTBEAT_REQUEST: 1,
  HEARTBEAT_RESPONSE: 2,
};

// SSLv2 message types
const SSLv2MessageType = {
  CLIENT_HELLO: 1,
  SERVER_HELLO: 4,
};

// TCP flags (for PCAP)
const TCPFlags = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
};

/**
 * Extract the negotiated version from a ServerHello handshake payload.
 * Checks the supported_versions extension (TLS 1.3) first, then falls
 * back to the legacy_version field.
 */
function getServerHelloVersion(payload) {
  if (payload.length < 40) return (payload[4] << 8) | payload[5];

  const bodyVersion = (payload[4] << 8) | payload[5];
  const sidLen = payload[38];
  const csOffset = 39 + sidLen;
  // Skip cipher_suite (2) + compression_method (1)
  const extLenOffset = csOffset + 3;
  if (extLenOffset + 1 >= payload.length) return bodyVersion;

  const extLen = (payload[extLenOffset] << 8) | payload[extLenOffset + 1];
  let pos = extLenOffset + 2;
  const end = Math.min(pos + extLen, payload.length);

  while (pos + 4 <= end) {
    const extType = (payload[pos] << 8) | payload[pos + 1];
    const extDataLen = (payload[pos + 2] << 8) | payload[pos + 3];
    pos += 4;
    if (extType === ExtensionType.SUPPORTED_VERSIONS && extDataLen >= 2 && pos + 1 < payload.length) {
      return (payload[pos] << 8) | payload[pos + 1];
    }
    pos += extDataLen;
  }
  return bodyVersion;
}

module.exports = {
  ContentType, Version, VersionName,
  HandshakeType, HandshakeTypeName,
  AlertLevel, AlertDescription, AlertDescriptionName, AlertCauseHint,
  CipherSuite, CipherSuiteName,
  ExtensionType, CompressionMethod,
  NamedGroup, NamedGroupName, SignatureScheme, SignatureSchemeName, ECPointFormat,
  HeartbeatMessageType, SSLv2MessageType,
  TCPFlags,
  getServerHelloVersion,
};
