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
    Version.TLS_1_0,
    Version.TLS_1_1,
    Version.TLS_1_2,
    Version.TLS_1_3,
  ];

  // Pick a subset of common/representative cipher suites to avoid 1000s of tests
  const ciphers = [
    CipherSuite.TLS_AES_128_GCM_SHA256,
    CipherSuite.TLS_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
  ];

  const groups = [
    NamedGroup.X25519,
    NamedGroup.SECP256R1,
    NamedGroup.SECP384R1,
  ];

  for (const v of versions) {
    const vName = VersionName[v] || `0x${v.toString(16)}`;
    
    for (const cs of ciphers) {
      const csName = CipherSuiteName[cs] || `0x${cs.toString(16)}`;
      
      // Filter: TLS 1.3 ciphers only work with TLS 1.3
      const isH3Cipher = (cs >> 8) === 0x13;
      if (isH3Cipher && v !== Version.TLS_1_3) continue;
      if (!isH3Cipher && v === Version.TLS_1_3) continue;

      for (const g of groups) {
        const gName = getGroupName(g);
        const name = `scan-${vName.replace(/\s+/g, '').toLowerCase()}-${csName.toLowerCase().replace(/_/g, '-')}-${gName.toLowerCase()}`;
        
        SCAN_SCENARIOS.push({
          name,
          category: 'SCAN',
          description: `Test connectivity: ${vName} + ${csName} + ${gName}`,
          side: 'client',
          actions: (opts) => [
            { 
              type: 'send', 
              data: hs.buildClientHello({ 
                hostname: opts.hostname,
                version: v,
                cipherSuites: [cs],
                // For 1.3, we need specific extensions
                extraExtensions: v === Version.TLS_1_3 ? [
                  { type: 43, data: Buffer.from([0x02, 0x03, 0x04]) }, // supported_versions: TLS 1.3
                  { type: 10, data: Buffer.from([0x00, 0x02, (g >> 8), (g & 0xff)]) }, // supported_groups
                ] : [
                  { type: 10, data: Buffer.from([0x00, 0x02, (g >> 8), (g & 0xff)]) },
                ]
              }), 
              label: `Scanning: ${vName} | ${csName} | ${gName}` 
            },
            { type: 'recv', timeout: 3000 },
          ],
          expected: 'PASSED', // We expect it to pass if supported, or DROPPED if not
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
