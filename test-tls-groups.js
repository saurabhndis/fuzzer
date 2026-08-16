// Tests for lib/tls-groups.js — the named groups handed to Node's TLS stack
// must be ones that stack actually accepts, not whatever the `openssl` CLI
// on PATH happens to list. Run: node test-tls-groups.js
// Run it under Electron too, where the two disagree:
//   ELECTRON_RUN_AS_NODE=1 ./node_modules/electron/dist/Electron.app/Contents/MacOS/Electron test-tls-groups.js

const tls = require('tls');
const assert = require('assert');
const { getNodeTlsGroups, hasPqcSupport, CLASSICAL_GROUPS, PQC_GROUPS } = require('./lib/tls-groups');

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

const runtime = process.versions.electron ? `Electron ${process.versions.electron}` : `Node ${process.version}`;
console.log(`Runtime: ${runtime}`);
console.log(`Groups:  ${getNodeTlsGroups() || '(none)'}`);

test('the group list is accepted by this runtime as one ecdhCurve value', () => {
  const groups = getNodeTlsGroups();
  if (!groups) return; // a stack that rejects even classical curves is legal here
  tls.createSecureContext({ ecdhCurve: groups }); // throws if any name is rejected
});

test('every returned group is individually accepted', () => {
  for (const g of getNodeTlsGroups().split(':').filter(Boolean)) {
    tls.createSecureContext({ ecdhCurve: g });
  }
});

test('no group outside the known candidate set is returned', () => {
  const known = new Set([...CLASSICAL_GROUPS, ...PQC_GROUPS]);
  for (const g of getNodeTlsGroups().split(':').filter(Boolean)) {
    assert.ok(known.has(g), `unexpected group: ${g}`);
  }
});

test('classical curves come before PQC groups', () => {
  const list = getNodeTlsGroups().split(':').filter(Boolean);
  const lastClassical = Math.max(...list.map((g, i) => (CLASSICAL_GROUPS.includes(g) ? i : -1)));
  const firstPqc = Math.min(...list.map((g, i) => (PQC_GROUPS.includes(g) ? i : Infinity)));
  assert.ok(lastClassical < firstPqc, `order wrong: ${list.join(':')}`);
});

test('X25519 is available (every supported TLS stack has it)', () => {
  assert.ok(getNodeTlsGroups().split(':').includes('X25519'));
});

test('result is cached — repeated calls return the identical string', () => {
  assert.strictEqual(getNodeTlsGroups(), getNodeTlsGroups());
});

test('hasPqcSupport agrees with the returned list', () => {
  const listed = getNodeTlsGroups().split(':').some((g) => PQC_GROUPS.includes(g));
  assert.strictEqual(hasPqcSupport(), listed);
});

test('the well-behaved TLS server starts with these groups', () => {
  // The regression this module exists for: the server threw
  // "Failed to set ECDH curve" under Electron because the list came from
  // the openssl CLI rather than the runtime.
  const groups = getNodeTlsGroups();
  tls.createSecureContext({ ...(groups && { ecdhCurve: groups }) });
});

if (failures) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log('\nAll tls-groups tests passed');
