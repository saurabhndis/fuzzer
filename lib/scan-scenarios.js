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
 * Generate scenarios for every supported combination
 */
function generateScanScenarios() {
  const versions = [
    Version.SSL_3_0,
    Version.TLS_1_0,
    Version.TLS_1_1,
    Version.TLS_1_2,
    Version.TLS_1_3,
  ];

  // Expanded ciphers including legacy ones
  const ciphers = [
    CipherSuite.TLS_AES_128_GCM_SHA256,
    CipherSuite.TLS_AES_256_GCM_SHA384,
    CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
    CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
  ];

  // Expanded groups including older ones
  const groups = [
    NamedGroup.X25519,
    NamedGroup.SECP256R1,
    NamedGroup.SECP384R1,
    NamedGroup.SECP521R1,
    NamedGroup.SECP192R1,
    NamedGroup.SECP224R1,
  ];

  for (const v of versions) {
    const vName = VersionName[v] || `0x${v.toString(16)}`;
    
    for (const cs of ciphers) {
      const csName = CipherSuiteName[cs] || `0x${cs.toString(16)}`;
      
      // Filter: TLS 1.3 ciphers only work with TLS 1.3
      const isH3Cipher = (cs >> 8) === 0x13;
      if (isH3Cipher && v !== Version.TLS_1_3) continue;
      if (!isH3Cipher && v === Version.TLS_1_3) continue;

      // For older versions (SSL3, 1.0, 1.1), ECC might not be supported at all
      // We still test it to see if the server handles the extension correctly.
      
      // To keep the number of scenarios sane (~100 instead of 500+),
      // we only iterate groups for ECC ciphers. For RSA/DHE we just use a default group.
      const isEccCipher = csName.includes('ECDHE') || csName.includes('ECDSA') || isH3Cipher;
      const groupsToTest = isEccCipher ? groups : [null];

      for (const g of groupsToTest) {
        const gName = g ? getGroupName(g) : 'None';
        const name = `scan-${vName.replace(/\./g, '').replace(/\s+/g, '').toLowerCase()}-${csName.toLowerCase().replace(/_/g, '-')}${g ? '-' + gName.toLowerCase() : ''}`;
        
        // Client-side scenario
        SCAN_SCENARIOS.push({
          name,
          category: 'SCAN',
          description: `Test connectivity (client): ${vName} + ${csName}${g ? ' + ' + gName : ''}`,
          side: 'client',
          actions: (opts) => {
            const extraExtensions = [];
            // Supported Versions for 1.3
            if (v === Version.TLS_1_3) {
              extraExtensions.push({ type: 43, data: Buffer.from([0x02, 0x03, 0x04]) });
            }
            // Supported Groups
            if (g) {
              extraExtensions.push({ type: 10, data: Buffer.from([0x00, 0x02, (g >> 8), (g & 0xff)]) });
            }

            return [
              { 
                type: 'send', 
                data: hs.buildClientHello({ 
                  hostname: opts.hostname,
                  version: v,
                  cipherSuites: [cs],
                  extraExtensions
                }), 
                label: `Scanning: ${vName} | ${csName} | ${gName}` 
              },
              { type: 'recv', timeout: 3000 },
            ];
          },
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
            if (isTls13) {
              extraExtensions.push({ type: 43, data: Buffer.from([0x03, 0x04]) });
            }

            return [
              { type: 'recv', timeout: 5000 },
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
