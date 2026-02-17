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
  SECP256R1: 0x0017,
  SECP384R1: 0x0018,
  SECP521R1: 0x0019,
  X25519: 0x001d,
  X448: 0x001e,
  FFDHE2048: 0x0100,
  FFDHE3072: 0x0101,
  // Post-Quantum / ML-KEM (FIPS 203) named groups
  X25519_MLKEM768: 0x4588,      // Hybrid X25519 + ML-KEM-768 (IANA assigned)
  SECP256R1_MLKEM768: 0x4589,   // Hybrid P-256 + ML-KEM-768
  MLKEM768: 0x0200,             // Standalone ML-KEM-768
  MLKEM1024: 0x0201,            // Standalone ML-KEM-1024
  X25519_KYBER768_DRAFT: 0x6399, // Chrome/Firefox experimental Kyber draft
  X25519_KYBER512_DRAFT: 0xfe30, // Experimental draft
  X25519_KYBER1024_DRAFT: 0xfe31, // Experimental draft
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

module.exports = {
  ContentType, Version, VersionName,
  HandshakeType, HandshakeTypeName,
  AlertLevel, AlertDescription, AlertDescriptionName,
  CipherSuite, CipherSuiteName,
  ExtensionType, CompressionMethod,
  NamedGroup, SignatureScheme, ECPointFormat,
  HeartbeatMessageType, SSLv2MessageType,
  TCPFlags,
};
