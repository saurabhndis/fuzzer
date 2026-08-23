// Run history — persisted outcomes of suite executions, one JSON file per
// run under <userData>/run-history/<protocol>/. Each protocol (tls, h2, quic,
// raw-tcp, cert-verify) keeps its own independent history, pruned to the
// newest MAX_RUNS files. The tag lives inside the JSON so retagging never
// renames a file, and filenames embed the timestamp so a plain lexicographic
// sort is a chronological sort.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MAX_RUNS = 10;
const SCHEMA_VERSION = 1;

const KNOWN_PROTOCOLS = ['tls', 'h2', 'quic', 'raw-tcp', 'cert-verify'];

let nextSeq = 0; // per-process save counter; see the filename note in saveRun

function historyDir(userDataPath, protocol) {
  if (!KNOWN_PROTOCOLS.includes(protocol)) {
    throw new Error(`Unknown protocol: ${protocol}`);
  }
  return path.join(userDataPath, 'run-history', protocol);
}

function runFiles(dir) {
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch (_) {
    return [];
  }
  return names.filter((n) => /^run-.*\.json$/.test(n)).sort().reverse();
}

function readRecord(dir, fileName) {
  try {
    const record = JSON.parse(fs.readFileSync(path.join(dir, fileName), 'utf8'));
    if (!record || typeof record !== 'object' || !record.id) return null;
    return record;
  } catch (_) {
    return null;
  }
}

function toMeta(record) {
  const results = Array.isArray(record.results) ? record.results : [];
  const count = (pred) => results.filter(pred).length;
  return {
    id: record.id,
    protocol: record.protocol,
    timestamp: record.timestamp,
    tag: record.tag || '',
    mode: record.mode || null,
    distributed: !!record.distributed,
    aborted: !!record.aborted,
    target: record.target || null,
    scenarioCount: record.scenarioCount || results.length,
    durationMs: record.durationMs || 0,
    grade: record.report ? record.report.grade : null,
    counts: {
      passed: count((r) => r.status === 'PASSED'),
      dropped: count((r) => r.status === 'DROPPED'),
      timeout: count((r) => r.status === 'TIMEOUT'),
      errors: count((r) => r.status === 'ERROR'),
      asExpected: count((r) => r.verdict === 'AS EXPECTED'),
      unexpected: count((r) => r.verdict === 'UNEXPECTED'),
    },
  };
}

// Save a completed run. Stamps id/timestamp/schemaVersion, reports the run
// that was newest before this save (the auto-compare baseline), and prunes
// the directory to MAX_RUNS.
function saveRun(userDataPath, record) {
  const dir = historyDir(userDataPath, record.protocol);
  fs.mkdirSync(dir, { recursive: true });

  const prevFile = runFiles(dir)[0];
  const prevRecord = prevFile ? readRecord(dir, prevFile) : null;

  const timestamp = new Date().toISOString();
  const full = {
    ...record,
    schemaVersion: SCHEMA_VERSION,
    id: crypto.randomUUID(),
    timestamp,
  };
  // Millisecond timestamps can collide on back-to-back saves; the monotonic
  // sequence keeps same-millisecond files ordered and the id suffix keeps
  // them unique. Filenames stay lexicographically chronological.
  const fileName = `run-${timestamp.replace(/[:.]/g, '-')}-${String(nextSeq++).padStart(6, '0')}-${full.id.slice(0, 8)}.json`;
  fs.writeFileSync(path.join(dir, fileName), JSON.stringify(full, null, 2));

  for (const stale of runFiles(dir).slice(MAX_RUNS)) {
    try { fs.unlinkSync(path.join(dir, stale)); } catch (_) {}
  }

  return { saved: toMeta(full), prev: prevRecord ? toMeta(prevRecord) : null };
}

// Newest-first metadata for every readable run of a protocol. Corrupt files
// are skipped rather than surfaced — history must never break the app.
function listRuns(userDataPath, protocol) {
  const dir = historyDir(userDataPath, protocol);
  return runFiles(dir)
    .map((f) => readRecord(dir, f))
    .filter(Boolean)
    .map(toMeta);
}

function findFile(dir, id) {
  for (const f of runFiles(dir)) {
    const record = readRecord(dir, f);
    if (record && record.id === id) return { file: f, record };
  }
  return null;
}

function loadRun(userDataPath, protocol, id) {
  const found = findFile(historyDir(userDataPath, protocol), id);
  return found ? found.record : null;
}

// Runs are written as soon as they finish so nothing is lost to a dismissed
// dialog and the auto-comparison always has a baseline; this removes one the
// user explicitly chose not to keep.
function deleteRun(userDataPath, protocol, id) {
  const dir = historyDir(userDataPath, protocol);
  const found = findFile(dir, id);
  if (!found) return false;
  try {
    fs.unlinkSync(path.join(dir, found.file));
    return true;
  } catch (_) {
    return false;
  }
}

function setTag(userDataPath, protocol, id, tag) {
  const dir = historyDir(userDataPath, protocol);
  const found = findFile(dir, id);
  if (!found) return false;
  found.record.tag = String(tag == null ? '' : tag);
  fs.writeFileSync(path.join(dir, found.file), JSON.stringify(found.record, null, 2));
  return true;
}

module.exports = { saveRun, listRuns, loadRun, setTag, deleteRun, MAX_RUNS, SCHEMA_VERSION, KNOWN_PROTOCOLS };
