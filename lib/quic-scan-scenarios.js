// QUIC Compatibility Scan Scenarios — probe QUIC server support for protocol combinations
//
// QUIC mandates TLS 1.3, so we test:
//   - QUIC versions: v1 (RFC 9000), v2 (RFC 9369)
//   - TLS 1.3 cipher suites: AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305
//   - Named groups: X25519, P-256, P-384, P-521, PQC hybrids (ML-KEM)
//   - ALPN protocols: h3, h3-29, h3-32 (draft versions)
//
// Each scenario sends a valid QUIC Initial packet containing a TLS 1.3
// ClientHello (as a handshake message inside a CRYPTO frame, per RFC 9001).

const crypto = require('crypto');
const { Version, CipherSuite, CipherSuiteName, NamedGroup, ExtensionType, SignatureScheme, HandshakeType } = require('./constants');
const hs = require('./handshake');
const { encodeVarInt, deriveInitialKeys, protectPacket } = require('./quic-packet');

function encodeTransportParam(id, value) {
  return Buffer.concat([encodeVarInt(id), encodeVarInt(value.length), value]);
}

function buildScanTransportParams(scid) {
  return Buffer.concat([
    encodeTransportParam(0x0f, scid || Buffer.alloc(0)),
    encodeTransportParam(0x04, encodeVarInt(1048576)),
    encodeTransportParam(0x05, encodeVarInt(524288)),
    encodeTransportParam(0x06, encodeVarInt(524288)),
    encodeTransportParam(0x07, encodeVarInt(524288)),
    encodeTransportParam(0x08, encodeVarInt(100)),
    encodeTransportParam(0x09, encodeVarInt(100)),
  ]);
}

const QUIC_SCAN_CATEGORIES = {
  QSCAN: 'QUIC Compatibility Scanning (Non-fuzzing)',
};

const QUIC_SCAN_SCENARIOS = [];

// ── QUIC versions ──────────────────────────────────────────────────────
const QUIC_VERSIONS = [
  { id: 0x00000001, name: 'QUICv1' },
  { id: 0x6b3343cf, name: 'QUICv2' },
];

// ── TLS 1.3 cipher suites (only ones valid for QUIC) ──────────────────
const TLS13_CIPHERS = [
  CipherSuite.TLS_AES_128_GCM_SHA256,
  CipherSuite.TLS_AES_256_GCM_SHA384,
  CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
];

// ── Named groups to test ───────────────────────────────────────────────
const SCAN_GROUPS = [
  { id: NamedGroup.X25519,              name: 'X25519',              keySize: 32 },
  { id: NamedGroup.SECP256R1,           name: 'P-256',              keySize: 65 },
  { id: NamedGroup.SECP384R1,           name: 'P-384',              keySize: 97 },
  { id: NamedGroup.SECP521R1,           name: 'P-521',              keySize: 133 },
  // Post-Quantum / Hybrid Groups
  { id: NamedGroup.MLKEM768,            name: 'MLKEM768',           keySize: 1184 },
  { id: NamedGroup.MLKEM1024,           name: 'MLKEM1024',          keySize: 1568 },
  { id: NamedGroup.X25519_MLKEM768,     name: 'X25519_MLKEM768',   keySize: 1216 },
  { id: NamedGroup.SECP256R1_MLKEM768,  name: 'P256_MLKEM768',     keySize: 1249 },
  { id: NamedGroup.X25519_FRODOKEM_640_SHAKE, name: 'X25519_FRODOKEM_640_SHAKE', keySize: 9648 },
  { id: NamedGroup.X25519_CLASSIC_MCELIECE_348864, name: 'X25519_CLASSIC_MCELIECE_348864', keySize: 0 }, // Too large for key_share
];

// ── ALPN protocols ─────────────────────────────────────────────────────
const ALPN_PROTOCOLS = [
  'h3',      // RFC 9114
  'h3-29',   // Draft-29 (widely deployed)
  'h3-32',   // Draft-32
];

// ── Helpers ────────────────────────────────────────────────────────────

function getGroupName(id) {
  for (const [k, v] of Object.entries(NamedGroup)) {
    if (v === id) return k;
  }
  return `0x${id.toString(16)}`;
}

/**
 * Build a protected QUIC Initial packet with a TLS 1.3 ClientHello in a CRYPTO frame.
 * Applies QUIC Initial packet protection (RFC 9001 §5) so real servers will process it.
 */
function buildQuicScanInitial(quicVersion, clientHelloBody, opts = {}) {
  const dcid = opts.dcid || crypto.randomBytes(8);
  const scid = opts.scid || crypto.randomBytes(8);
  const pn = opts.packetNumber || 1;
  const pnLen = 2;

  // TLS handshake message: type(1) + length(3) + body
  const chMsg = hs.buildHandshakeMessage(HandshakeType.CLIENT_HELLO, clientHelloBody);

  // CRYPTO frame: type(0x06) + offset(varint) + length(varint) + data
  const cryptoFrameType = Buffer.from([0x06]);
  const cryptoOffset = encodeVarInt(0);
  const cryptoLen = encodeVarInt(chMsg.length);
  const cryptoFrame = Buffer.concat([cryptoFrameType, cryptoOffset, cryptoLen, chMsg]);

  // Plaintext payload (after PN)
  const plaintext = cryptoFrame;

  // Packet number
  const pnBuf = Buffer.alloc(pnLen);
  pnBuf.writeUInt16BE(pn & 0xffff, 0);

  // Payload length includes PN + ciphertext + 16-byte AEAD tag
  // We also need to account for padding to reach 1200 bytes minimum

  // Long header: Initial type (0), PN length encoded in low 2 bits
  const firstByte = Buffer.from([0x80 | 0x40 | (0 << 4) | (pnLen - 1)]);
  const versionBuf = Buffer.alloc(4);
  versionBuf.writeUInt32BE(quicVersion, 0);
  const dcidLenBuf = Buffer.from([dcid.length]);
  const scidLenBuf = Buffer.from([scid.length]);
  const tokenLenEnc = encodeVarInt(0);

  // Calculate header size without payload length and PN to determine padding
  const headerPrefix = Buffer.concat([
    firstByte, versionBuf, dcidLenBuf, dcid, scidLenBuf, scid, tokenLenEnc,
  ]);

  // Estimate total: headerPrefix + packetLen(2) + pnLen + plaintext + 16 (tag)
  const estimatedTotal = headerPrefix.length + 2 + pnLen + plaintext.length + 16;
  const minPadding = Math.max(0, 1200 - estimatedTotal);
  const paddedPlaintext = minPadding > 0
    ? Buffer.concat([plaintext, Buffer.alloc(minPadding, 0)])
    : plaintext;

  const payloadLen = pnLen + paddedPlaintext.length + 16;
  const payloadLenEnc = encodeVarInt(payloadLen);

  // Build unprotected header (up to and including PN)
  const header = Buffer.concat([
    firstByte, versionBuf, dcidLenBuf, dcid, scidLenBuf, scid,
    tokenLenEnc, payloadLenEnc, pnBuf,
  ]);

  // Derive keys and protect
  const keys = deriveInitialKeys(dcid, quicVersion);
  return protectPacket(header, paddedPlaintext, pn, pnLen, keys);
}

// ── Scenario generation ────────────────────────────────────────────────

function generateQuicScanScenarios() {
  // 1. Version × Cipher × Group scans
  for (const qv of QUIC_VERSIONS) {
    for (const cs of TLS13_CIPHERS) {
      const csName = CipherSuiteName[cs] || `0x${cs.toString(16)}`;

      for (const group of SCAN_GROUPS) {
        const name = `qscan-${qv.name.toLowerCase()}-${csName.toLowerCase().replace(/_/g, '-')}-${group.name.toLowerCase().replace(/_/g, '-')}`;

        QUIC_SCAN_SCENARIOS.push({
          name,
          category: 'QSCAN',
          description: `QUIC scan: ${qv.name} + ${csName} + ${group.name}`,
          side: 'client',
          actions: (opts) => {
            const hostname = opts.hostname || 'localhost';
            const dcid = crypto.randomBytes(8);
            const scid = crypto.randomBytes(8);

            const extraExtensions = [];
            const suppressExtensions = [];

            // TLS 1.3 supported_versions: only 0x0304
            extraExtensions.push({ type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x04]) });

            // Suppress ec_point_formats (not used in TLS 1.3)
            suppressExtensions.push(ExtensionType.EC_POINT_FORMATS);
            // Suppress renegotiation_info (not used in TLS 1.3)
            suppressExtensions.push(ExtensionType.RENEGOTIATION_INFO);

            // Supported groups: only the group under test
            extraExtensions.push({
              type: ExtensionType.SUPPORTED_GROUPS,
              data: (() => {
                const buf = Buffer.alloc(4);
                buf.writeUInt16BE(2, 0);
                buf.writeUInt16BE(group.id, 2);
                return buf;
              })(),
            });

            // Key share for this group
            if (group.keySize <= 65535) {
              extraExtensions.push({
                type: ExtensionType.KEY_SHARE,
                data: hs.buildPQCKeyShareExtension([{ group: group.id, keySize: group.keySize }]),
              });
            } else {
              suppressExtensions.push(ExtensionType.KEY_SHARE);
            }

            // ALPN: h3 (standard)
            extraExtensions.push({
              type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
              data: hs.buildALPNExtension(['h3']),
            });

            // QUIC transport parameters
            extraExtensions.push({ type: 0x39, data: buildScanTransportParams(scid) });

            const chBody = hs.buildClientHelloBody({
              hostname,
              version: Version.TLS_1_2, // TLS 1.3 legacy_version is 0x0303
              cipherSuites: [cs],
              variant: 'small',
              extraExtensions,
              suppressExtensions,
            });

            return [
              { type: 'send', data: buildQuicScanInitial(qv.id, chBody, { dcid, scid }), label: `QUIC Scan: ${qv.name} | ${csName} | ${group.name}` },
              { type: 'recv', timeout: 5000 },
            ];
          },
          expected: 'PASSED',
        });
      }
    }
  }

  // 2. ALPN protocol support scans (using default cipher + group)
  for (const alpn of ALPN_PROTOCOLS) {
    const name = `qscan-alpn-${alpn.replace(/[^a-z0-9]/g, '-')}`;

    QUIC_SCAN_SCENARIOS.push({
      name,
      category: 'QSCAN',
      description: `QUIC scan: ALPN ${alpn} support`,
      side: 'client',
      actions: (opts) => {
        const hostname = opts.hostname || 'localhost';
        const dcid = crypto.randomBytes(8);
        const scid = crypto.randomBytes(8);

        const extraExtensions = [];
        const suppressExtensions = [];

        extraExtensions.push({ type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x04]) });
        suppressExtensions.push(ExtensionType.EC_POINT_FORMATS);
        suppressExtensions.push(ExtensionType.RENEGOTIATION_INFO);

        // Supported groups + key share (X25519)
        extraExtensions.push({
          type: ExtensionType.SUPPORTED_GROUPS,
          data: (() => { const b = Buffer.alloc(4); b.writeUInt16BE(2, 0); b.writeUInt16BE(NamedGroup.X25519, 2); return b; })(),
        });
        extraExtensions.push({
          type: ExtensionType.KEY_SHARE,
          data: hs.buildPQCKeyShareExtension([{ group: NamedGroup.X25519, keySize: 32 }]),
        });

        // ALPN: single protocol under test
        extraExtensions.push({
          type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
          data: hs.buildALPNExtension([alpn]),
        });

        // QUIC transport parameters
        extraExtensions.push({ type: 0x39, data: buildScanTransportParams(scid) });

        const chBody = hs.buildClientHelloBody({
          hostname,
          version: Version.TLS_1_2,
          cipherSuites: [CipherSuite.TLS_AES_128_GCM_SHA256],
          variant: 'small',
          extraExtensions,
          suppressExtensions,
        });

        return [
          { type: 'send', data: buildQuicScanInitial(0x00000001, chBody, { dcid, scid }), label: `QUIC Scan: ALPN ${alpn}` },
          { type: 'recv', timeout: 5000 },
        ];
      },
      expected: 'PASSED',
    });
  }

  // 3. QUIC version negotiation probe — send unknown version to discover supported versions
  QUIC_SCAN_SCENARIOS.push({
    name: 'qscan-version-negotiation',
    category: 'QSCAN',
    description: 'QUIC scan: Version Negotiation probe — sends unknown version to discover supported versions',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);

      // Send Initial with a bogus version to trigger Version Negotiation
      const firstByte = Buffer.from([0x80 | 0x40]);
      const version = Buffer.alloc(4);
      version.writeUInt32BE(0x0a0a0a0a, 0); // Unknown version
      const dcidLen = Buffer.from([dcid.length]);
      const scidLen = Buffer.from([scid.length]);
      const tokenLen = encodeVarInt(0);
      const payload = Buffer.alloc(2); // minimal packet number
      const packetLen = encodeVarInt(payload.length);

      let packet = Buffer.concat([
        firstByte, version, dcidLen, dcid, scidLen, scid,
        tokenLen, packetLen, payload,
      ]);

      // Pad to 1200 bytes
      if (packet.length < 1200) {
        packet = Buffer.concat([packet, Buffer.alloc(1200 - packet.length, 0)]);
      }

      return [
        { type: 'send', data: packet, label: 'QUIC Version Negotiation probe (unknown version 0x0a0a0a0a)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should respond with Version Negotiation listing supported versions',
    });

    // 4. Grease Extensions Scan — probe if server tolerates GREASE (RFC 8701)
    QUIC_SCAN_SCENARIOS.push({
    name: 'qscan-grease-extensions',
    category: 'QSCAN',
    description: 'QUIC scan: GREASE (RFC 8701) tolerance — sends random unknown extensions',
    side: 'client',
    actions: (opts) => {
    const hostname = opts.hostname || 'localhost';
    const dcid = crypto.randomBytes(8);
    const scid = crypto.randomBytes(8);

    const extraExtensions = [
      { type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x04]) },
      { type: 0x1a1a, data: crypto.randomBytes(4) }, // GREASE
      { type: 0x39, data: buildScanTransportParams(scid) }, // Transport Params
    ];

    const chBody = hs.buildClientHelloBody({
      hostname,
      version: Version.TLS_1_2,
      cipherSuites: [CipherSuite.TLS_AES_128_GCM_SHA256],
      extraExtensions,
    });

    return [
      { type: 'send', data: buildQuicScanInitial(0x00000001, chBody, { dcid, scid }), label: 'QUIC Scan: GREASE Extensions' },
      { type: 'recv', timeout: 5000 },
    ];
    },
    expected: 'PASSED',
    });

    // 5. Signature Algorithms Scan — probe supported signature schemes
    const SIG_SCHEMES = [
      { id: SignatureScheme.ECDSA_SECP256R1_SHA256, name: 'ecdsa-p256' },
      { id: SignatureScheme.RSA_PSS_RSAE_SHA256,     name: 'rsa-pss-sha256' },
      { id: SignatureScheme.ED25519,                 name: 'ed25519' },
    ];

    for (const sig of SIG_SCHEMES) {
      QUIC_SCAN_SCENARIOS.push({
        name: `qscan-sigalg-${sig.name}`,
        category: 'QSCAN',
        description: `QUIC scan: Signature Algorithm ${sig.name} support`,
        side: 'client',
        actions: (opts) => {
          const hostname = opts.hostname || 'localhost';
          const dcid = crypto.randomBytes(8);
          const scid = crypto.randomBytes(8);

          const extraExtensions = [
            { type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x04]) },
            {
              type: ExtensionType.SIGNATURE_ALGORITHMS,
              data: (() => {
                const b = Buffer.alloc(4);
                b.writeUInt16BE(2, 0);
                b.writeUInt16BE(sig.id, 2);
                return b;
              })(),
            },
            { type: 0x39, data: buildScanTransportParams(scid) },
          ];

          const chBody = hs.buildClientHelloBody({
            hostname,
            version: Version.TLS_1_2,
            cipherSuites: [CipherSuite.TLS_AES_128_GCM_SHA256],
            extraExtensions,
          });

          return [
            { type: 'send', data: buildQuicScanInitial(0x00000001, chBody, { dcid, scid }), label: `QUIC Scan: SigAlg ${sig.name}` },
            { type: 'recv', timeout: 5000 },
          ];
        },
        expected: 'PASSED',
      });
    }
}
generateQuicScanScenarios();

function listQuicScanScenarios() {
  const grouped = {};
  for (const s of QUIC_SCAN_SCENARIOS) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return { categories: QUIC_SCAN_CATEGORIES, scenarios: grouped };
}

function getQuicScanScenario(name) {
  return QUIC_SCAN_SCENARIOS.find(s => s.name === name);
}

module.exports = {
  QUIC_SCAN_SCENARIOS,
  QUIC_SCAN_CATEGORIES,
  listQuicScanScenarios,
  getQuicScanScenario,
};
