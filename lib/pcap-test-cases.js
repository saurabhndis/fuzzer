// PCAP Test Cases — committed, self-contained Node.js test scenarios.
//
// Each file under pcap-test-cases/ is a standalone module exporting one
// scenario object (same shape as any other entry in scenarios.js). Users
// generate them by ingesting a PCAP, then read / edit / diff / commit
// them like any other source file.
//
// Replaces the older pcap-tests/<name>.json format. There is no
// pending/verified lifecycle — the file existing in the directory means
// the user has saved it; committing the file means the user has verified it.

const fs = require('fs');
const path = require('path');
const { generateScenarioSource } = require('./pcap-code-gen');

const PCAP_TEST_CASES_DIR = path.join(__dirname, '..', 'pcap-test-cases');
const PCAP_CATEGORY = 'PCAP-CASE';
const PCAP_CATEGORY_LABEL = 'PCAP Test Cases';

function ensureDir() {
  if (!fs.existsSync(PCAP_TEST_CASES_DIR)) {
    fs.mkdirSync(PCAP_TEST_CASES_DIR, { recursive: true });
  }
}

/**
 * Sanitize a name into something filesystem-safe AND a valid module-id-ish
 * identifier. Only [a-zA-Z0-9_-] survive; everything else becomes '-'.
 */
function toFilename(name) {
  const cleaned = String(name).replace(/[^a-zA-Z0-9_-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  if (cleaned.length === 0) return `pcap-test-${Date.now()}`;
  return cleaned;
}

/**
 * Path to the .js file for a given test name.
 */
function filePathFor(name) {
  return path.join(PCAP_TEST_CASES_DIR, `${toFilename(name)}.js`);
}

/**
 * Save a parsed PCAP scenario as a self-contained .js file.
 *
 * @param {object} scenario   Output of parsePcapToScenario() (or a scenario
 *                            object with action closures or arrays).
 * @param {object} opts
 *   @param {string} opts.hostname    — passed into action closures
 *   @param {string} opts.sourceFile  — original .pcap path (recorded in header)
 *   @param {number} opts.streamIndex — original stream index (recorded in header)
 *   @param {string} opts.name        — override the scenario's name
 *   @param {boolean} opts.overwrite  — if true, replace an existing file; else
 *                                     suffix with timestamp to make unique
 *
 * @returns {{ name, filePath }} where `name` is the final on-disk basename.
 */
function saveTestCase(scenario, opts = {}) {
  ensureDir();
  if (opts.name) scenario = { ...scenario, name: opts.name };

  const baseName = scenario.name || `pcap-test-${Date.now()}`;
  let safeName = toFilename(baseName);
  let filePath = path.join(PCAP_TEST_CASES_DIR, `${safeName}.js`);

  if (fs.existsSync(filePath) && !opts.overwrite) {
    safeName = `${safeName}-${Date.now()}`;
    filePath = path.join(PCAP_TEST_CASES_DIR, `${safeName}.js`);
  }

  // The on-disk name must match scenario.name so the loader can find it by
  // name without an extra index. Force-sync them.
  const source = generateScenarioSource({ ...scenario, name: safeName }, {
    hostname: opts.hostname,
    sourceFile: opts.sourceFile,
    streamIndex: opts.streamIndex,
  });

  fs.writeFileSync(filePath, source);
  return { name: safeName, filePath };
}

/**
 * Require a single .js test case file, refreshing module cache so edits
 * picked up on re-list.
 */
function loadTestCase(name) {
  const safeName = toFilename(name);
  const filePath = path.join(PCAP_TEST_CASES_DIR, `${safeName}.js`);
  if (!fs.existsSync(filePath)) return null;

  try {
    // Drop cached copy — users may have edited the file in place and we
    // want subsequent `loadTestCase` calls to reflect that.
    delete require.cache[require.resolve(filePath)];
    const scenario = require(filePath);
    // Force category to PCAP-CASE regardless of what the file claims, so the
    // registry's grouping always lines up.
    scenario.category = PCAP_CATEGORY;
    return scenario;
  } catch (err) {
    console.error(`[pcap-test-cases] Failed to load ${name}: ${err.message}`);
    return null;
  }
}

/**
 * Walk the directory and load every test case file.
 *
 * @returns {Array<{ name, scenario, filePath }>}
 */
function listAllTestCases() {
  ensureDir();
  const files = fs.readdirSync(PCAP_TEST_CASES_DIR).filter(f => f.endsWith('.js'));
  const out = [];
  for (const file of files) {
    const name = file.replace(/\.js$/, '');
    const scenario = loadTestCase(name);
    if (scenario) out.push({ name, scenario, filePath: path.join(PCAP_TEST_CASES_DIR, file) });
  }
  return out;
}

// ─── API surface expected by scenarios.js and cli.js ────────────────────────

function getPcapScenario(name) {
  return loadTestCase(name);
}

/**
 * Return all scenarios grouped by category. We always emit a single category
 * (PCAP-CASE) so the returned `categories` map always contains exactly that
 * key, even when zero tests are saved.
 */
function listPcapScenarios(_opts = {}) {
  const tests = listAllTestCases();
  return {
    categories: { [PCAP_CATEGORY]: PCAP_CATEGORY_LABEL },
    scenarios: { [PCAP_CATEGORY]: tests.map(t => t.scenario) },
  };
}

function getPcapScenariosByCategory(cat, _opts = {}) {
  if (cat.toUpperCase() !== PCAP_CATEGORY) return [];
  return listAllTestCases().map(t => t.scenario);
}

function getPcapClientScenarios(_opts = {}) {
  return listAllTestCases().map(t => t.scenario).filter(s => s.side === 'client');
}

function getPcapServerScenarios(_opts = {}) {
  return listAllTestCases().map(t => t.scenario).filter(s => s.side === 'server');
}

function deletePcapTestCase(name) {
  const safeName = toFilename(name);
  const filePath = path.join(PCAP_TEST_CASES_DIR, `${safeName}.js`);
  if (!fs.existsSync(filePath)) return false;
  try {
    fs.unlinkSync(filePath);
    delete require.cache[require.resolve(filePath)];
    return true;
  } catch (err) {
    console.error(`[pcap-test-cases] Failed to delete ${name}: ${err.message}`);
    return false;
  }
}

/**
 * Compact info-for-display view of a saved test case, for `cli.js pcap-test-cases`.
 */
function getPcapTestCaseInfo(name) {
  const scenario = loadTestCase(name);
  if (!scenario) return null;
  const filePath = filePathFor(name);
  const stats = fs.statSync(filePath);
  return {
    name,
    filePath,
    sizeBytes: stats.size,
    createdAt: stats.birthtime.toISOString(),
    modifiedAt: stats.mtime.toISOString(),
    protocol: scenario.protocol,
    side: scenario.side,
    expected: scenario.expected,
    description: scenario.description,
    explanation: scenario.explanation,
    natMerged: scenario.pcapParams?.natMerged || false,
    reassembly: scenario.pcapParams?.reassembly || null,
  };
}

module.exports = {
  PCAP_CATEGORY,
  PCAP_CATEGORY_LABEL,
  PCAP_TEST_CASES_DIR,
  saveTestCase,
  loadTestCase,
  listAllTestCases,
  deletePcapTestCase,
  getPcapTestCaseInfo,
  // Names matching the old pcap-scenarios.js API so scenarios.js doesn't change much:
  getPcapScenario,
  listPcapScenarios,
  getPcapScenariosByCategory,
  getPcapClientScenarios,
  getPcapServerScenarios,
};
