// PCAP-Based Test Scenarios — persistent storage and lifecycle management
//
// PCAP tests are generated from captured network traffic via --ingest-pcap.
// They live in fuzzer/pcap-tests/ as JSON files and go through a lifecycle:
//
//   1. PENDING  — freshly ingested, not yet validated by a human
//   2. VERIFIED — user has run the test, reviewed results, and marked it verified
//
// Verified tests appear in the PCAP category alongside built-in scenarios.
// Pending tests are listed with a [pending] tag and can be run but won't be
// included in --scenario all or --category PCAP by default.
//
// File format: <name>.json
//   {
//     "meta": { "status": "pending"|"verified", "createdAt": "...", "verifiedAt": "...",
//               "sourceFile": "...", "streamIndex": 0, "description": "..." },
//     "scenario": { ... serialized scenario ... }
//   }

const fs = require('fs');
const path = require('path');
const { deserializePcapScenario, serializePcapScenario } = require('./pcap-parser');

const PCAP_TESTS_DIR = path.join(__dirname, '..', 'pcap-tests');
const PCAP_CATEGORY = 'PCAP';

/**
 * Ensure the pcap-tests directory exists.
 */
function ensureDir() {
  if (!fs.existsSync(PCAP_TESTS_DIR)) {
    fs.mkdirSync(PCAP_TESTS_DIR, { recursive: true });
  }
}

/**
 * Sanitize a scenario name for use as a filename.
 */
function toFilename(name) {
  return name.replace(/[^a-zA-Z0-9_-]/g, '_');
}

/**
 * Save a PCAP-generated scenario to disk.
 *
 * @param {object} scenario - Scenario from parsePcapToScenario()
 * @param {object} opts - { hostname, sourceFile, streamIndex, name }
 * @returns {{ name: string, filePath: string }} Saved test info
 */
function savePcapTest(scenario, opts = {}) {
  ensureDir();

  const serialized = serializePcapScenario(scenario, { hostname: opts.hostname || 'localhost' });

  // Generate a unique name if not provided
  const baseName = opts.name || scenario.name || `pcap-test-${Date.now()}`;
  const safeName = toFilename(baseName);
  const filePath = path.join(PCAP_TESTS_DIR, `${safeName}.json`);

  // Check for name collision
  if (fs.existsSync(filePath) && !opts.overwrite) {
    // Append timestamp to make unique
    const uniqueName = `${safeName}-${Date.now()}`;
    const uniquePath = path.join(PCAP_TESTS_DIR, `${uniqueName}.json`);
    const data = {
      meta: {
        status: 'pending',
        createdAt: new Date().toISOString(),
        verifiedAt: null,
        sourceFile: opts.sourceFile || null,
        streamIndex: opts.streamIndex || 0,
        description: scenario.description || '',
        explanation: scenario.explanation || '',
      },
      scenario: serialized,
    };
    fs.writeFileSync(uniquePath, JSON.stringify(data, null, 2));
    return { name: uniqueName, filePath: uniquePath };
  }

  const data = {
    meta: {
      status: 'pending',
      createdAt: new Date().toISOString(),
      verifiedAt: null,
      sourceFile: opts.sourceFile || null,
      streamIndex: opts.streamIndex || 0,
      description: scenario.description || '',
      explanation: scenario.explanation || '',
    },
    scenario: serialized,
  };

  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  return { name: safeName, filePath };
}

/**
 * Load a single PCAP test from disk and return the deserialized scenario.
 *
 * @param {string} name - Test name (without .json extension)
 * @returns {object|null} { meta, scenario } or null if not found
 */
function loadPcapTest(name) {
  const safeName = toFilename(name);
  const filePath = path.join(PCAP_TESTS_DIR, `${safeName}.json`);
  if (!fs.existsSync(filePath)) return null;

  try {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const scenario = deserializePcapScenario(raw.scenario);
    // Override category to PCAP
    scenario.category = PCAP_CATEGORY;
    // Tag with metadata
    scenario._pcapMeta = raw.meta;
    return { meta: raw.meta, scenario };
  } catch (err) {
    console.error(`[pcap-scenarios] Failed to load ${name}: ${err.message}`);
    return null;
  }
}

/**
 * Get a PCAP scenario by name (for use by agent/scenario resolution).
 *
 * @param {string} name - Scenario name
 * @returns {object|null} Runnable scenario or null
 */
function getPcapScenario(name) {
  const loaded = loadPcapTest(name);
  return loaded ? loaded.scenario : null;
}

/**
 * List all saved PCAP tests.
 *
 * @param {object} opts - { includesPending: true, verifiedOnly: false }
 * @returns {Array<{ name, meta, scenario }>}
 */
function listPcapTests(opts = {}) {
  ensureDir();
  const files = fs.readdirSync(PCAP_TESTS_DIR).filter(f => f.endsWith('.json'));
  const tests = [];

  for (const file of files) {
    const name = file.replace(/\.json$/, '');
    const loaded = loadPcapTest(name);
    if (!loaded) continue;

    if (opts.verifiedOnly && loaded.meta.status !== 'verified') continue;
    if (!opts.includePending && loaded.meta.status === 'pending' && opts.verifiedOnly) continue;

    tests.push({ name, meta: loaded.meta, scenario: loaded.scenario });
  }

  return tests;
}

/**
 * List PCAP scenarios in the format expected by the scenario registry.
 * Returns only verified tests by default, or all tests if includePending is true.
 *
 * @param {object} opts - { includePending: false }
 * @returns {{ categories: object, scenarios: object }}
 */
function listPcapScenarios(opts = {}) {
  const tests = listPcapTests({ includePending: opts.includePending !== false, verifiedOnly: false });
  const scenarios = tests.map(t => t.scenario);

  return {
    categories: { [PCAP_CATEGORY]: 'PCAP-Based Session Recreation' },
    scenarios: { [PCAP_CATEGORY]: scenarios },
  };
}

/**
 * Get all PCAP client scenarios (for --scenario all or --category PCAP).
 *
 * @param {object} opts - { includePending: false }
 * @returns {Array<object>} Runnable scenario objects
 */
function getPcapClientScenarios(opts = {}) {
  const tests = listPcapTests({ includePending: opts.includePending, verifiedOnly: !opts.includePending });
  return tests.filter(t => t.scenario.side === 'client').map(t => t.scenario);
}

/**
 * Get all PCAP server scenarios.
 */
function getPcapServerScenarios(opts = {}) {
  const tests = listPcapTests({ includePending: opts.includePending, verifiedOnly: !opts.includePending });
  return tests.filter(t => t.scenario.side === 'server').map(t => t.scenario);
}

/**
 * Get PCAP scenarios by category (always returns PCAP category).
 */
function getPcapScenariosByCategory(cat, opts = {}) {
  if (cat.toUpperCase() !== PCAP_CATEGORY) return [];
  const tests = listPcapTests({ includePending: opts.includePending !== false, verifiedOnly: false });
  return tests.map(t => t.scenario);
}

/**
 * Mark a PCAP test as verified.
 *
 * @param {string} name - Test name
 * @returns {boolean} true if successfully verified
 */
function verifyPcapTest(name) {
  const safeName = toFilename(name);
  const filePath = path.join(PCAP_TESTS_DIR, `${safeName}.json`);
  if (!fs.existsSync(filePath)) {
    console.error(`[pcap-scenarios] Test not found: ${name}`);
    return false;
  }

  try {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    raw.meta.status = 'verified';
    raw.meta.verifiedAt = new Date().toISOString();
    fs.writeFileSync(filePath, JSON.stringify(raw, null, 2));
    return true;
  } catch (err) {
    console.error(`[pcap-scenarios] Failed to verify ${name}: ${err.message}`);
    return false;
  }
}

/**
 * Delete a PCAP test.
 *
 * @param {string} name - Test name
 * @returns {boolean} true if successfully deleted
 */
function deletePcapTest(name) {
  const safeName = toFilename(name);
  const filePath = path.join(PCAP_TESTS_DIR, `${safeName}.json`);
  if (!fs.existsSync(filePath)) return false;

  try {
    fs.unlinkSync(filePath);
    return true;
  } catch (err) {
    console.error(`[pcap-scenarios] Failed to delete ${name}: ${err.message}`);
    return false;
  }
}

/**
 * Get info about a specific PCAP test (for display).
 */
function getPcapTestInfo(name) {
  const loaded = loadPcapTest(name);
  if (!loaded) return null;

  const { meta, scenario } = loaded;
  return {
    name,
    status: meta.status,
    createdAt: meta.createdAt,
    verifiedAt: meta.verifiedAt,
    sourceFile: meta.sourceFile,
    streamIndex: meta.streamIndex,
    description: meta.description,
    explanation: meta.explanation,
    protocol: scenario.protocol,
    side: scenario.side,
    expected: scenario.expected,
    natMerged: scenario.pcapParams?.natMerged || false,
    handshakeAnalysis: scenario.pcapParams?.handshakeAnalysis || [],
  };
}

module.exports = {
  PCAP_CATEGORY,
  PCAP_TESTS_DIR,
  savePcapTest,
  loadPcapTest,
  getPcapScenario,
  listPcapTests,
  listPcapScenarios,
  getPcapClientScenarios,
  getPcapServerScenarios,
  getPcapScenariosByCategory,
  verifyPcapTest,
  deletePcapTest,
  getPcapTestInfo,
};
