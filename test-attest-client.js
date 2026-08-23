// Client-side attestation tests: PR-token verification, the pure run
// comparison, and account/mode config. The server itself lives in a separate
// private repo; these tests need no network — a throwaway Ed25519 server
// certificate stands in for the operator's, built from lib/x509.js.
// Run: node test-attest-client.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');

// Isolate the client store BEFORE anything resolves ~/.wirestrike.
process.env.WIRESTRIKE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-attest-cli-'));

const A = require('./lib/attestation');
const T = require('./lib/attestation-token');
const X = require('./lib/x509');
const { compareRuns } = require('./lib/attestation-commands');
const R = require('./lib/attestation-remote');

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

// A minimal self-signed Ed25519 certificate, standing in for the operator's
// server cert. RFC 8410 requires the AlgorithmIdentifier parameters absent,
// so we build the algo id by hand rather than via buildAlgorithmIdentifier.
function makeServerCert() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const OID_ED25519 = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);
  const algo = X.derSequence([OID_ED25519]);
  const name = X.derSequence([X.buildRDN(X.OID.COMMON_NAME, 'Test Attestation CA')]);
  const spki = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  const tbs = X.derSequence([
    X.derExplicit(0, X.derInteger(2)),
    X.derInteger(crypto.randomBytes(8)),
    algo, name,
    X.derSequence([X.derUTCTime('250101000000Z'), X.derUTCTime('350101000000Z')]),
    name, spki,
  ]);
  const sig = crypto.sign(null, tbs, privateKey);
  const der = X.derSequence([tbs, algo, X.derBitString(sig)]);
  const certPem = `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END CERTIFICATE-----\n`;
  return { certPem, privateKeyPem: privateKey };
}

const T0 = 1755300000000;
const server = makeServerCert();

function makePayload(over = {}) {
  return {
    v: 1, serial: 3, username: 'alice', email: 'alice@paloaltonetworks.com',
    keyId: 'k'.repeat(16), receiptHash: 'a'.repeat(64), runId: 'run-1', repoId: 'repo01',
    prNumber: 42, grade: 'A', protocol: 'tls', coveragePermille: 1000,
    finishedAt: T0 + 60000, issuedAt: Date.now(), ...over,
  };
}

// ── Token verification ────────────────────────────────────────────────

test('token round-trips and verifies against the stand-in server cert', () => {
  const token = T.signToken(makePayload(), { privateKeyPem: server.privateKeyPem });
  const res = T.verifyToken(`See PR notes:\n${token}\n`, { serverCertPem: server.certPem });
  assert.ok(res.ok, JSON.stringify(res.errors));
  assert.strictEqual(res.payload.username, 'alice');
  assert.strictEqual(res.payload.prNumber, 42);
});

test('a token signed by another key does not verify', () => {
  const other = makeServerCert();
  const token = T.signToken(makePayload(), { privateKeyPem: other.privateKeyPem });
  assert.ok(!T.verifyToken(token, { serverCertPem: server.certPem }).ok);
});

test('decodeToken takes the last token in edited text', () => {
  const stale = T.signToken(makePayload({ prNumber: 1 }), { privateKeyPem: server.privateKeyPem });
  const fresh = T.signToken(makePayload({ prNumber: 2 }), { privateKeyPem: server.privateKeyPem });
  const decoded = T.decodeToken(`old: ${stale}\nnew: ${fresh}`);
  assert.strictEqual(decoded.payload.prNumber, 2);
});

test('malformed input yields a clean malformed error, not a throw', () => {
  const res = T.verifyToken('no token here', { serverCertPem: server.certPem });
  assert.ok(!res.ok);
  assert.strictEqual(res.errors[0].code, 'malformed');
});

// ── compareRuns ───────────────────────────────────────────────────────

function detail(serial, prNumber, over = {}) {
  return {
    serial, prNumber,
    envelope: {
      receipt: {
        repo: { headSha: over.headSha || 'deadbeef', branch: 'main', dirty: false },
        run: {
          protocol: over.protocol || 'tls', mode: 'client', grade: over.grade || 'A',
          coveragePermille: over.coverage || 1000, executedScenarios: 10, requestedScenarios: 10,
          scenarioSetDigest: over.scenarioSetDigest || 'set-x', resultsDigest: over.resultsDigest || 'res-x',
          stats: over.stats || { pass: 10, fail: 0, warn: 0, error: 0 }, finishedAt: T0,
        },
        target: { host: 'fw.internal', port: 443 },
      },
    },
  };
}

test('compareRuns marks identical runs as all-same', () => {
  const rows = compareRuns(detail(1, 10), detail(2, 10));
  assert.ok(rows.every((r) => r.same), 'all rows same');
  assert.ok(rows.find((r) => r.label === 'grade'));
});

test('compareRuns flags the fields that differ', () => {
  const a = detail(1, 10, { grade: 'A', resultsDigest: 'res-a' });
  const b = detail(2, 11, { grade: 'C', resultsDigest: 'res-b' });
  const rows = compareRuns(a, b);
  const byLabel = Object.fromEntries(rows.map((r) => [r.label, r]));
  assert.ok(!byLabel['grade'].same, 'grade differs');
  assert.ok(!byLabel['results digest'].same, 'results digest differs');
  assert.ok(!byLabel['PR'].same, 'PR differs');
  assert.ok(byLabel['protocol'].same, 'protocol same');
  assert.ok(byLabel['branch'].same, 'branch same');
});

test('compareRuns renders same test set but different results', () => {
  // Same scenarios, different outcome — the point of comparing two runs.
  const a = detail(1, 10, { scenarioSetDigest: 'S', resultsDigest: 'R1', stats: { pass: 9, fail: 1, warn: 0, error: 0 } });
  const b = detail(2, 10, { scenarioSetDigest: 'S', resultsDigest: 'R2', stats: { pass: 10, fail: 0, warn: 0, error: 0 } });
  const rows = compareRuns(a, b);
  const byLabel = Object.fromEntries(rows.map((r) => [r.label, r]));
  assert.ok(byLabel['scenario set'].same, 'same scenario set');
  assert.ok(!byLabel['results digest'].same, 'different results');
  assert.ok(!byLabel['pass/fail/warn/err'].same, 'different stats');
});

// ── Account / mode config ─────────────────────────────────────────────

test('a fresh install is anonymous', () => {
  assert.ok(!R.isSignedIn());
  assert.strictEqual(R.loadConfig().mode, 'anonymous');
});

test('saveConfig + logout flip the mode; key/cert paths are under the store', () => {
  R.saveConfig({ mode: 'account', serverUrl: 'https://s:9443', username: 'alice', email: 'alice@paloaltonetworks.com', keyId: 'k' });
  assert.ok(R.isSignedIn());
  assert.strictEqual(R.accountStatus().username, 'alice');
  R.logout();
  assert.ok(!R.isSignedIn());
  assert.strictEqual(R.loadConfig().mode, 'anonymous');
  // logout keeps the identity fields around for a later --login.
  assert.strictEqual(R.loadConfig().username, 'alice');
  assert.ok(R.clientCertPath().startsWith(process.env.WIRESTRIKE_HOME));
});

test('WIRESTRIKE_ATTEST_URL overrides the configured server URL', () => {
  R.saveConfig({ mode: 'account', serverUrl: 'https://configured:9443' });
  process.env.WIRESTRIKE_ATTEST_URL = 'https://env-override:9443';
  assert.strictEqual(R.serverUrl(), 'https://env-override:9443');
  assert.strictEqual(R.serverUrl('https://explicit:9443'), 'https://explicit:9443');
  delete process.env.WIRESTRIKE_ATTEST_URL;
});

// ── run-reporter (needs a live server; skipped if the private repo isn't
//    checked out beside the fuzzer) ─────────────────────────────────────

const SERVER_REPO = path.join(__dirname, '..', 'wirestrike-attest-server');
const haveServer = fs.existsSync(path.join(SERVER_REPO, 'lib', 'attest-server.js'));

async function asyncTest(name, fn) {
  try { await fn(); console.log(`  PASS  ${name}`); }
  catch (err) { failures++; console.error(`  FAIL  ${name}\n        ${err.message}`); }
}

async function runReporterTests() {
  if (!haveServer) {
    console.log('  SKIP  run-reporter live tests (wirestrike-attest-server not checked out beside fuzzer)');
    return;
  }
  const os2 = require('os');
  const P = require(path.join(SERVER_REPO, 'lib', 'attest-pki'));
  const { startAttestServer } = require(path.join(SERVER_REPO, 'lib', 'attest-server'));
  const S = require('./lib/attestation-store');
  const reporter = require('./lib/run-reporter');

  const srvHome = fs.mkdtempSync(path.join(os2.tmpdir(), 'ws-rep-srv-'));
  P.initServerIdentity(srvHome, { host: 'localhost' });
  const handle = await startAttestServer({ dataDir: srvHome, port: 0, host: '127.0.0.1' });
  const url = `https://127.0.0.1:${handle.port}`;

  await asyncTest('reporter is a no-op when anonymous', async () => {
    R.logout();
    const h = reporter.startReporting({ runId: 'x', protocol: 'tls' });
    h.stop();
    assert.strictEqual(handle.db.listActiveRuns().length, 0);
  });

  await asyncTest('signed-in run start/finish appears then clears on the server', async () => {
    // Enroll this client against the live test server.
    if (!S.keyStatus().exists) S.generateKeyPair();
    await R.enroll({ server: url, username: 'reporter', email: 'reporter@paloaltonetworks.com', serverCertPath: P.serverCertPath(srvHome) });
    const runId = 'live-report-1';
    const h = reporter.startReporting({ runId, protocol: 'tls', targetHost: 'fw', targetPort: 443, mode: 'client', requestedScenarios: 5 });
    // start is fire-and-forget; give the mTLS round-trip a moment.
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(handle.db.listActiveRuns().find((x) => x.runId === runId), 'active run recorded');
    h.stop();
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(!handle.db.listActiveRuns().find((x) => x.runId === runId), 'finish cleared it');
  });

  await handle.close();
}

(async () => {
  await runReporterTests();
  if (failures) {
    console.error(`\n${failures} test(s) failed`);
    process.exit(1);
  }
  console.log('\nAll attestation-client tests passed');
})();
