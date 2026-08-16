// Tests for lib/run-history.js and lib/run-compare.js.
// Run: node test-run-history.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { saveRun, listRuns, loadRun, setTag, deleteRun, MAX_RUNS } = require('./lib/run-history');
const { compareRuns } = require('./lib/run-compare');

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
  } catch (err) {
    failures++;
    console.error(`  FAIL  ${name}`);
    console.error(`        ${err.message}`);
  }
}

function makeResult(overrides = {}) {
  return {
    scenario: 'tls-hello-basic',
    category: 'A',
    severity: 'high',
    status: 'PASSED',
    expected: 'PASSED',
    verdict: 'AS EXPECTED',
    hostDown: false,
    finding: { grade: 'PASS', severity: 'high', reason: null },
    ...overrides,
  };
}

function makeRecord(overrides = {}) {
  return {
    protocol: 'tls',
    tag: '',
    mode: 'client',
    distributed: false,
    aborted: false,
    target: { host: '127.0.0.1', port: 4433 },
    durationMs: 1000,
    scenarioCount: 1,
    report: { grade: 'A', label: 'ok', stats: { pass: 1, fail: 0, warn: 0, info: 0 } },
    results: [makeResult()],
    ...overrides,
  };
}

const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'run-history-test-'));

// --- run-history ---

test('saveRun returns saved meta and null prev on first save', () => {
  const { saved, prev } = saveRun(userData, makeRecord());
  assert.ok(saved.id, 'saved.id missing');
  assert.ok(saved.timestamp, 'saved.timestamp missing');
  assert.strictEqual(saved.grade, 'A');
  assert.strictEqual(saved.counts.passed, 1);
  assert.strictEqual(prev, null);
});

test('saveRun reports the previous newest run as prev', () => {
  const { saved, prev } = saveRun(userData, makeRecord({ report: { grade: 'B', stats: {} } }));
  assert.ok(prev, 'prev missing');
  assert.strictEqual(prev.grade, 'A');
  assert.strictEqual(saved.grade, 'B');
});

test(`retention prunes to ${MAX_RUNS} newest runs`, () => {
  for (let i = 0; i < 12; i++) saveRun(userData, makeRecord({ durationMs: i }));
  const dir = path.join(userData, 'run-history', 'tls');
  const files = fs.readdirSync(dir).filter((f) => /^run-.*\.json$/.test(f));
  assert.strictEqual(files.length, MAX_RUNS, `expected ${MAX_RUNS} files, got ${files.length}`);
  const metas = listRuns(userData, 'tls');
  assert.strictEqual(metas.length, MAX_RUNS);
  assert.strictEqual(metas[0].durationMs, 11, 'newest run should be first');
});

test('listRuns is newest-first and per-protocol', () => {
  saveRun(userData, makeRecord({ protocol: 'h2' }));
  assert.strictEqual(listRuns(userData, 'h2').length, 1);
  assert.strictEqual(listRuns(userData, 'quic').length, 0);
  const tls = listRuns(userData, 'tls');
  for (let i = 1; i < tls.length; i++) {
    assert.ok(tls[i - 1].timestamp >= tls[i].timestamp, 'not sorted newest-first');
  }
});

test('loadRun round-trips the full record', () => {
  const { saved } = saveRun(userData, makeRecord({ tag: 'baseline' }));
  const record = loadRun(userData, 'tls', saved.id);
  assert.ok(record, 'record not found');
  assert.strictEqual(record.tag, 'baseline');
  assert.strictEqual(record.results.length, 1);
  assert.strictEqual(loadRun(userData, 'tls', 'no-such-id'), null);
});

test('setTag persists a tag without renaming the file', () => {
  const { saved } = saveRun(userData, makeRecord());
  const dir = path.join(userData, 'run-history', 'tls');
  const before = fs.readdirSync(dir).sort();
  assert.strictEqual(setTag(userData, 'tls', saved.id, 'after refactor'), true);
  assert.deepStrictEqual(fs.readdirSync(dir).sort(), before);
  assert.strictEqual(loadRun(userData, 'tls', saved.id).tag, 'after refactor');
  const meta = listRuns(userData, 'tls').find((m) => m.id === saved.id);
  assert.strictEqual(meta.tag, 'after refactor');
  assert.strictEqual(setTag(userData, 'tls', 'no-such-id', 'x'), false);
});

test('deleteRun removes only the named run', () => {
  const { saved } = saveRun(userData, makeRecord({ tag: 'to-discard' }));
  const before = listRuns(userData, 'tls').length;
  assert.strictEqual(deleteRun(userData, 'tls', saved.id), true);
  const after = listRuns(userData, 'tls');
  assert.strictEqual(after.length, before - 1);
  assert.strictEqual(after.find((m) => m.id === saved.id), undefined);
  assert.strictEqual(loadRun(userData, 'tls', saved.id), null);
  assert.strictEqual(deleteRun(userData, 'tls', saved.id), false, 'deleting twice should report false');
});

test('corrupt history files are skipped', () => {
  const dir = path.join(userData, 'run-history', 'tls');
  const before = listRuns(userData, 'tls').length;
  fs.writeFileSync(path.join(dir, 'run-9999-corrupt.json'), '{ not json');
  assert.strictEqual(listRuns(userData, 'tls').length, before, 'corrupt file should be skipped');
  fs.unlinkSync(path.join(dir, 'run-9999-corrupt.json'));
});

test('unknown protocol throws', () => {
  assert.throws(() => listRuns(userData, 'ftp'), /Unknown protocol/);
});

// --- run-compare ---

function record(results, grade) {
  return { report: grade ? { grade } : null, results };
}

test('compareRuns classifies every movement kind', () => {
  const prev = record([
    makeResult({ scenario: 's-match' }),
    makeResult({ scenario: 's-regressed' }),
    makeResult({ scenario: 's-improved', status: 'ERROR', verdict: 'UNEXPECTED', finding: { grade: 'FAIL' } }),
    makeResult({ scenario: 's-status', status: 'DROPPED', expected: 'DROPPED' }),
    makeResult({ scenario: 's-removed' }),
  ], 'B');
  const curr = record([
    makeResult({ scenario: 's-match' }),
    makeResult({ scenario: 's-regressed', status: 'TIMEOUT', verdict: 'UNEXPECTED', finding: { grade: 'FAIL' } }),
    makeResult({ scenario: 's-improved' }),
    makeResult({ scenario: 's-status', status: 'TIMEOUT', expected: 'DROPPED' }),
    makeResult({ scenario: 's-new' }),
  ], 'A');

  const { rows, summary } = compareRuns(prev, curr);
  const byName = Object.fromEntries(rows.map((r) => [r.scenario, r.classification]));
  assert.strictEqual(byName['s-match'], 'match');
  assert.strictEqual(byName['s-regressed'], 'regressed');
  assert.strictEqual(byName['s-improved'], 'improved');
  assert.strictEqual(byName['s-status'], 'status-changed');
  assert.strictEqual(byName['s-new'], 'new');
  assert.strictEqual(byName['s-removed'], 'removed');
  assert.deepStrictEqual(summary.counts, { match: 1, regressed: 1, improved: 1, statusChanged: 1, new: 1, removed: 1 });
  assert.strictEqual(summary.common, 4);
  assert.strictEqual(summary.prevGrade, 'B');
  assert.strictEqual(summary.currGrade, 'A');
  assert.ok(summary.headline.includes('Grade B → A'), `headline: ${summary.headline}`);
  assert.strictEqual(rows[0].classification, 'regressed', 'regressed rows should sort first');
});

test('verdict flip without grade change classifies as regressed/improved', () => {
  const asExpected = makeResult({ scenario: 's', verdict: 'AS EXPECTED', finding: { grade: 'WARN' } });
  const unexpected = makeResult({ scenario: 's', verdict: 'UNEXPECTED', finding: { grade: 'WARN' } });
  assert.strictEqual(compareRuns(record([asExpected]), record([unexpected])).rows[0].classification, 'regressed');
  assert.strictEqual(compareRuns(record([unexpected]), record([asExpected])).rows[0].classification, 'improved');
});

test('duplicate scenario entries dedupe to the worst occurrence', () => {
  const prev = record([makeResult({ scenario: 's' })]);
  const curr = record([
    makeResult({ scenario: 's' }),
    makeResult({ scenario: 's', status: 'ERROR', verdict: 'UNEXPECTED', finding: { grade: 'FAIL' } }),
  ]);
  const { rows } = compareRuns(prev, curr);
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].classification, 'regressed');
  assert.strictEqual(rows[0].curr.grade, 'FAIL');
});

test('a scenario that stopped running is a regression, whatever it reported before', () => {
  const errored = makeResult({ scenario: 's', status: 'ERROR', verdict: 'N/A', finding: { grade: 'ERROR' } });
  // From PASS the rank comparison would catch it; from WARN/FAIL it would not,
  // since FAIL outranks ERROR. Losing coverage is never an improvement.
  for (const before of ['PASS', 'INFO', 'WARN', 'FAIL']) {
    const prev = record([makeResult({ scenario: 's', finding: { grade: before } })]);
    const { rows } = compareRuns(prev, record([errored]));
    assert.strictEqual(rows[0].classification, 'regressed', `${before} -> ERROR should be regressed`);
  }
});

test('a scenario that started running again is judged on its new result', () => {
  const errored = makeResult({ scenario: 's', status: 'ERROR', verdict: 'N/A', finding: { grade: 'ERROR' } });
  const expectations = { PASS: 'improved', INFO: 'improved', WARN: 'regressed', FAIL: 'regressed' };
  for (const [after, want] of Object.entries(expectations)) {
    const curr = record([makeResult({ scenario: 's', finding: { grade: after } })]);
    const { rows } = compareRuns(record([errored]), curr);
    assert.strictEqual(rows[0].classification, want, `ERROR -> ${after} should be ${want}`);
  }
});

test('identical runs yield all match and a no-changes headline', () => {
  const a = record([makeResult({ scenario: 's1' }), makeResult({ scenario: 's2' })], 'A');
  const { summary } = compareRuns(a, a);
  assert.strictEqual(summary.counts.match, 2);
  assert.ok(summary.headline.includes('no changes'), summary.headline);
});

fs.rmSync(userData, { recursive: true, force: true });

if (failures) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log('\nAll run-history tests passed');
