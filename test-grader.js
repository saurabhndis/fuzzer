// Tests for lib/grader.js — in particular that a run whose scenarios never
// executed is reported as inconclusive rather than as a clean pass.
// Run: node test-grader.js

const assert = require('assert');
const { gradeResult, computeOverallGrade } = require('./lib/grader');

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
  } catch (err) {
    failures++;
    console.error(`  FAIL  ${name}\n        ${err.message}`);
  }
}

const META = { category: 'A', expected: 'DROPPED' };

// A graded result as the engines build it: run gradeResult, attach the finding.
function graded(overrides = {}, meta = META) {
  const result = {
    scenario: 'scenario-' + (overrides.scenario || Math.abs(hash(JSON.stringify(overrides)))),
    category: meta.category,
    status: 'DROPPED',
    expected: meta.expected,
    hostDown: false,
    response: 'Alert(fatal, HANDSHAKE_FAILURE)',
    ...overrides,
  };
  result.finding = gradeResult(result, meta);
  return result;
}
function hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }

const repeat = (n, fn) => Array.from({ length: n }, (_, i) => fn(i));

// ── gradeResult ──────────────────────────────────────────────────────

test('ERROR is graded ERROR, not INFO', () => {
  const f = gradeResult({ status: 'ERROR', expected: 'DROPPED' }, META);
  assert.strictEqual(f.grade, 'ERROR');
});

test('ABORTED is graded ERROR', () => {
  const f = gradeResult({ status: 'ABORTED', expected: 'DROPPED' }, META);
  assert.strictEqual(f.grade, 'ERROR');
});

test('a scenario with no expected value is still INFO, not ERROR', () => {
  const f = gradeResult({ status: 'DROPPED', expected: null }, { category: 'A', expected: null });
  assert.strictEqual(f.grade, 'INFO', 'INFO means "ran, nothing to assert" and must stay distinct');
});

test('hostDown still outranks the error path', () => {
  const f = gradeResult({ status: 'ERROR', expected: 'DROPPED', hostDown: true }, META);
  assert.strictEqual(f.grade, 'FAIL');
  assert.strictEqual(f.severity, 'critical');
});

// ── computeOverallGrade: the reported bug ────────────────────────────

test('a run where every scenario errored is Inconclusive, not A', () => {
  const results = repeat(5, (i) => graded({ scenario: `e${i}`, status: 'ERROR', response: 'ERROR' }));
  const report = computeOverallGrade(results);
  assert.strictEqual(report.grade, 'I', `expected I, got ${report.grade} (${report.label})`);
  assert.strictEqual(report.stats.error, 5);
  assert.strictEqual(report.stats.pass, 0);
  assert.ok(/inconclusive/i.test(report.label), report.label);
  assert.ok(!/all tests passed/i.test(report.label), 'must not claim tests passed');
});

test('an empty run is Inconclusive, not A', () => {
  const report = computeOverallGrade([]);
  assert.strictEqual(report.grade, 'I');
  assert.ok(/no scenarios ran/i.test(report.label), report.label);
});

test('a majority-errored run is Inconclusive', () => {
  const results = [
    ...repeat(6, (i) => graded({ scenario: `e${i}`, status: 'ERROR' })),
    ...repeat(4, (i) => graded({ scenario: `p${i}` })),
  ];
  const report = computeOverallGrade(results);
  assert.strictEqual(report.grade, 'I', report.label);
  assert.ok(report.label.includes('6 of 10'), report.label);
});

test('a minority of errors still grades normally', () => {
  const results = [
    ...repeat(2, (i) => graded({ scenario: `e${i}`, status: 'ERROR' })),
    ...repeat(8, (i) => graded({ scenario: `p${i}` })),
  ];
  const report = computeOverallGrade(results);
  assert.strictEqual(report.grade, 'A', report.label);
  assert.strictEqual(report.stats.error, 2);
  assert.ok(/did not run/i.test(report.label), `A-grade label should disclose skipped tests: ${report.label}`);
});

test('a fully clean run is still A with the original label', () => {
  const results = repeat(5, (i) => graded({ scenario: `p${i}` }));
  const report = computeOverallGrade(results);
  assert.strictEqual(report.grade, 'A');
  assert.strictEqual(report.stats.error, 0);
  assert.strictEqual(report.label, 'All tests passed — robust TLS implementation');
});

// ── precedence: real findings must not be masked by errors ───────────

test('a crashed target is F, never Inconclusive', () => {
  // A crash makes every later scenario error out — the crash is the finding.
  const results = [
    graded({ scenario: 'crash', status: 'ERROR', hostDown: true }),
    ...repeat(9, (i) => graded({ scenario: `e${i}`, status: 'ERROR' })),
  ];
  const report = computeOverallGrade(results);
  assert.strictEqual(report.grade, 'F', report.label);
  assert.ok(/crash/i.test(report.label), report.label);
});

test('a critical failure is F even when most scenarios errored', () => {
  const results = [
    graded({ scenario: 'vuln', status: 'PASSED', expected: 'DROPPED', response: 'raw bytes' },
      { category: 'A', expected: 'DROPPED' }),
    ...repeat(9, (i) => graded({ scenario: `e${i}`, status: 'ERROR' })),
  ];
  const critical = results[0].finding.severity === 'critical';
  const report = computeOverallGrade(results);
  assert.strictEqual(report.grade, critical ? 'F' : 'I',
    `grade ${report.grade} for severity ${results[0].finding.severity}`);
});

test('errored scenarios never enter the security findings list', () => {
  const results = repeat(4, (i) => graded({ scenario: `e${i}`, status: 'ERROR' }));
  const report = computeOverallGrade(results);
  assert.deepStrictEqual(report.findings, [],
    'a connection failure is not a vulnerability and must not be reported as one');
});

test('warn ratio is measured against scenarios that actually ran', () => {
  // 3 warns out of 4 executed (75%) — errors must not dilute this below 30%.
  const results = [
    ...repeat(3, (i) => graded({ scenario: `w${i}`, status: 'DROPPED', expected: 'PASSED' },
      { category: 'A', expected: 'PASSED' })),
    graded({ scenario: 'p0' }),
    ...repeat(3, (i) => graded({ scenario: `e${i}`, status: 'ERROR' })),
  ];
  const report = computeOverallGrade(results);
  assert.strictEqual(report.stats.warn, 3);
  assert.strictEqual(report.grade, 'B', `expected B from a warn-heavy run, got ${report.grade}`);
});

if (failures) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log('\nAll grader tests passed');
