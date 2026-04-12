// TLS Compatibility Scan Scenarios — try every combination of version/cipher/curve
const { Version, CipherSuite, NamedGroup, CipherSuiteName, VersionName } = require('./constants');
const hs = require('./handshake');

const SCAN_CATEGORIES = {
  SCAN: 'TLS Compatibility Scanning (Non-fuzzing)',
};

const SCAN_SCENARIOS = [];

// Helper to get group name
function getGroupName(id) {
  for (const [k, v] of Object.entries(NamedGroup)) {
    if (v === id) return k;
  }
  return `0x${id.toString(16)}`;
}

/**
 * Historically accurate version/cipher/curve compatibility matrix.
 *
 * SSL 3.0 (1996):  RSA & DHE key exchange only; CBC + RC4 bulk ciphers;
 *                  MD5/SHA-1 MACs.  No ECDHE, no GCM, no SHA-256 MACs.
 *                  No EC extensions at all (RFC 4492 came in 2006).
 *
 * TLS 1.0 (1999):  Same cipher space as SSL 3.0.  ECDHE was retrofitted
 *                  via RFC 4492 (2006) but only with CBC ciphers (no GCM).
 *                  Curves: secp192r1, secp224r1, secp256r1, secp384r1, secp521r1.
 *
 * TLS 1.1 (2006):  Same cipher space as TLS 1.0.  ECDHE+CBC valid.
 *                  Same curves as TLS 1.0.  No GCM (RFC 5288 = TLS 1.2).
 *
 * TLS 1.2 (2008):  Introduced GCM (AEAD), SHA-256/384 MACs.
 *                  All ECDHE suites valid.  X25519 added later (RFC 7748, 2016).
 *                  Legacy suites (RC4, 3DES, RSA-CBC) still negotiable.
 *
 * TLS 1.3 (2018):  Completely new cipher suite namespace (0x13xx).
 *                  Only AEAD ciphers.  Key exchange via supported_groups.
 *                  X25519, secp256r1, secp384r1, secp521r1.
 */

// Per-version valid cipher suites
const SSL30_CIPHERS = [
  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
  CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
  CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
  CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
];

const TLS10_CIPHERS = [
  ...SSL30_CIPHERS,
  // ECDHE+CBC via RFC 4492 (2006) — retrofitted onto TLS 1.0
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
];

// TLS 1.1 has same suite space as TLS 1.0
const TLS11_CIPHERS = TLS10_CIPHERS;

const TLS12_CIPHERS = [
  // Modern AEAD suites (RFC 5288, 5289)
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
  CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
  CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  // ECDHE+CBC (still valid in 1.2)
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  // RSA+CBC (legacy but negotiable)
  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
  CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
  CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
  CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
];

const TLS13_CIPHERS = [
  CipherSuite.TLS_AES_128_GCM_SHA256,
  CipherSuite.TLS_AES_256_GCM_SHA384,
  CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
];

// Per-version valid named groups (curves)
// SSL 3.0: no EC support at all — Elliptic Curve Cryptography extension (RFC 4492) did not exist
const SSL30_GROUPS = [];

// TLS 1.0/1.1: RFC 4492 curves (secp* only, no X25519)
const TLS10_GROUPS = [
  NamedGroup.SECP256R1,
  NamedGroup.SECP384R1,
  NamedGroup.SECP521R1,
  NamedGroup.SECP192R1,
  NamedGroup.SECP224R1,
];
const TLS11_GROUPS = TLS10_GROUPS;

// TLS 1.2: secp* plus X25519 (RFC 7748, 2016)
const TLS12_GROUPS = [
  NamedGroup.X25519,
  NamedGroup.SECP256R1,
  NamedGroup.SECP384R1,
  NamedGroup.SECP521R1,
  NamedGroup.SECP192R1,
  NamedGroup.SECP224R1,
];

// TLS 1.3: modern curves only (RFC 8446)
const TLS13_GROUPS = [
  NamedGroup.X25519,
  NamedGroup.SECP256R1,
  NamedGroup.SECP384R1,
  NamedGroup.SECP521R1,
  // Post-Quantum / Hybrid Groups
  NamedGroup.MLKEM768,
  NamedGroup.MLKEM1024,
  NamedGroup.X25519_MLKEM768,
  NamedGroup.SECP256R1_MLKEM768,
  NamedGroup.X25519_FRODOKEM_640_SHAKE,
  NamedGroup.X25519_CLASSIC_MCELIECE_348864,
];

// Map version to valid ciphers and groups
const VERSION_CIPHERS = {
  [Version.SSL_3_0]:  SSL30_CIPHERS,
  [Version.TLS_1_0]:  TLS10_CIPHERS,
  [Version.TLS_1_1]:  TLS11_CIPHERS,
  [Version.TLS_1_2]:  TLS12_CIPHERS,
  [Version.TLS_1_3]:  TLS13_CIPHERS,
};

const VERSION_GROUPS = {
  [Version.SSL_3_0]:  SSL30_GROUPS,
  [Version.TLS_1_0]:  TLS10_GROUPS,
  [Version.TLS_1_1]:  TLS11_GROUPS,
  [Version.TLS_1_2]:  TLS12_GROUPS,
  [Version.TLS_1_3]:  TLS13_GROUPS,
};

/**
 * Generate scenarios for every historically valid combination
 */
function generateScanScenarios() {
  const versions = [
    Version.SSL_3_0,
    Version.TLS_1_0,
    Version.TLS_1_1,
    Version.TLS_1_2,
    Version.TLS_1_3,
  ];

  for (const v of versions) {
    const vName = VersionName[v] || `0x${v.toString(16)}`;
    const ciphers = VERSION_CIPHERS[v];
    const validGroups = VERSION_GROUPS[v];

    for (const cs of ciphers) {
      const csName = CipherSuiteName[cs] || `0x${cs.toString(16)}`;

      // Only iterate groups for ECC/TLS1.3 ciphers; RSA/DHE get null (no curve)
      const isEccCipher = csName.includes('ECDHE') || csName.includes('ECDSA') || (cs >> 8) === 0x13;
      const groupsToTest = isEccCipher && validGroups.length > 0 ? validGroups : [null];

      for (const g of groupsToTest) {
        const gName = g ? getGroupName(g) : 'None';
        const name = `scan-${vName.replace(/\./g, '').replace(/\s+/g, '').toLowerCase()}-${csName.toLowerCase().replace(/_/g, '-')}${g ? '-' + gName.toLowerCase() : ''}`;
        
        // SSL 3.0 and TLS 1.0 are deprecated and not supported by most modern implementations
        const isDeprecatedVersion = v === Version.SSL_3_0 || v === Version.TLS_1_0;

        // Client-side scenario
        SCAN_SCENARIOS.push({
          name,
          category: 'SCAN',
          description: `Test connectivity (client): ${vName} + ${csName}${g ? ' + ' + gName : ''}`,
          side: 'client',
          actions: (opts) => {
            const extraExtensions = [];
            const suppressExtensions = [];

            if (v === Version.TLS_1_3) {
              // TLS 1.3: supported_versions must list 0x0304
              extraExtensions.push({ type: 43, data: Buffer.from([0x02, 0x03, 0x04]) });
              // RFC 8446: TLS 1.3 ClientHellos MUST NOT contain ec_point_formats
              suppressExtensions.push(11); // EC_POINT_FORMATS
            } else if (v === Version.TLS_1_2) {
              // TLS 1.2: supported_versions lists only 1.2 to prevent server
              // from upgrading to TLS 1.3; suppress key_share (1.3 concept)
              extraExtensions.push({ type: 43, data: Buffer.from([0x02, 0x03, 0x03]) });
              suppressExtensions.push(51); // KEY_SHARE
            } else {
              // SSL 3.0 / TLS 1.0 / TLS 1.1: no TLS 1.3 extensions
              suppressExtensions.push(43); // SUPPORTED_VERSIONS
              suppressExtensions.push(51); // KEY_SHARE
            }

            // Supported groups: only include if this cipher needs a curve
            if (g) {
              extraExtensions.push({ type: 10, data: Buffer.from([0x00, 0x02, (g >> 8), (g & 0xff)]) });

              if (v === Version.TLS_1_3) {
                // TLS 1.3 requires a key share for the offered group to avoid illegal_parameter.
                // Groups with key sizes > 65535 cannot fit in the key_exchange field (uint16),
                // so we omit key_share and let the server HelloRetryRequest if needed.
                const KEY_SIZES = {
                  [NamedGroup.X25519]: 32, [NamedGroup.SECP256R1]: 65,
                  [NamedGroup.SECP384R1]: 97, [NamedGroup.SECP521R1]: 133,
                  [NamedGroup.MLKEM768]: 1184, [NamedGroup.MLKEM1024]: 1568,
                  [NamedGroup.X25519_MLKEM768]: 1216, [NamedGroup.SECP256R1_MLKEM768]: 1249,
                  [NamedGroup.X25519_FRODOKEM_640_SHAKE]: 9648,
                };
                const keySize = KEY_SIZES[g] || 32;
                if (keySize <= 65535) {
                  extraExtensions.push({
                    type: 51,
                    data: hs.buildPQCKeyShareExtension([{ group: g, keySize }])
                  });
                } else {
                  suppressExtensions.push(51); // KEY_SHARE — too large, rely on HRR
                }
              }
            } else if (!isEccCipher) {
              // Non-EC ciphers don't need supported_groups or ec_point_formats
              suppressExtensions.push(10); // SUPPORTED_GROUPS
              suppressExtensions.push(11); // EC_POINT_FORMATS
            }

            return [
              {
                type: 'send',
                data: hs.buildClientHello({
                  hostname: opts.hostname,
                  version: v === Version.TLS_1_3 ? Version.TLS_1_2 : v,
                  cipherSuites: [cs],
                  extraExtensions,
                  suppressExtensions,
                }),
                label: `Scanning: ${vName} | ${csName} | ${gName}`
              },
              { type: 'recv', timeout: 1000 },
            ];
          },
          // Scan results are informational — no fixed expected value.
          // PASSED means server responded (supports this combo), DROPPED means unsupported.
          expected: 'PASSED',
        });

        // Server-side scenario
        SCAN_SCENARIOS.push({
          name: `${name}-server`,
          category: 'SCAN',
          description: `Test connectivity (server): ${vName} + ${csName}${g ? ' + ' + gName : ''}`,
          side: 'server',
          actions: (opts) => {
            const extraExtensions = [];
            // For TLS 1.3, ServerHello legacy_version must be 0x0303 and supported_versions must be present
            const isTls13 = v === Version.TLS_1_3;
            const KEY_SIZES = {
              [NamedGroup.X25519]: 32, [NamedGroup.SECP256R1]: 65,
              [NamedGroup.SECP384R1]: 97, [NamedGroup.SECP521R1]: 133,
              [NamedGroup.MLKEM768]: 1184, [NamedGroup.MLKEM1024]: 1568,
              [NamedGroup.X25519_MLKEM768]: 1216, [NamedGroup.SECP256R1_MLKEM768]: 1249,
              [NamedGroup.X25519_FRODOKEM_640_SHAKE]: 9648,
            };

            if (isTls13) {
              extraExtensions.push({ type: 43, data: Buffer.from([0x03, 0x04]) });
              // For TLS 1.3, ServerHello MUST contain a KeyShareEntry
              if (g) {
                const keySize = KEY_SIZES[g] || 32;
                const keyData = hs.generateKeyShareData(g, keySize);
                const ksEntry = Buffer.alloc(4 + keyData.length);
                ksEntry.writeUInt16BE(g, 0);
                ksEntry.writeUInt16BE(keyData.length, 2);
                keyData.copy(ksEntry, 4);
                extraExtensions.push({ type: 51, data: ksEntry });
              }
            }

            return [
              { type: 'recv', timeout: 1000 },
              {
                type: 'send',
                data: hs.buildServerHello({
                  version: isTls13 ? Version.TLS_1_2 : v,
                  cipherSuite: cs,
                  extraExtensions
                }),
                label: `Server Response: ${vName} | ${csName}`
              },
            ];
          },
          expected: 'PASSED',
        });
      }
    }
  }
}

generateScanScenarios();

function listScanScenarios() {
  const grouped = {};
  for (const s of SCAN_SCENARIOS) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return { categories: SCAN_CATEGORIES, scenarios: grouped };
}

function getScanScenario(name) {
  return SCAN_SCENARIOS.find(s => s.name === name);
}

module.exports = {
  SCAN_SCENARIOS,
  SCAN_CATEGORIES,
  listScanScenarios,
  getScanScenario,
};
