// Tests for lib/attestation.js — the signed, chained run receipt.
// Run: node test-attestation.js

const fs = require('fs');
const crypto = require('crypto');
const assert = require('assert');
const A = require('./lib/attestation');

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

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const KEY_ID = A.keyIdFromPublicKey(publicKey);
const REGISTRY = new Map([[KEY_ID, { keyId: KEY_ID, publicKeyPem: publicKey, email: 'dev@example.com' }]]);

const T0 = 1755300000000;

function makeReceipt(over = {}) {
  return A.buildReceipt({
    receiptId: over.receiptId || 'r-0001',
    tool: { name: 'wirestrike', version: '1.0.0', commit: 'abc1234', node: 'v25', platform: 'darwin', arch: 'arm64' },
    repo: { available: true, repoId: 'repo01', headSha: 'deadbeef', branch: 'main', dirty: false, dirtyFileCount: 0 },
    run: {
      runId: 'run-1', startedAt: T0, finishedAt: T0 + 60000, durationMs: 60000,
      protocol: 'tls', mode: 'client', distributed: false, aborted: false, abortReason: null,
      requestedScenarios: 10, executedScenarios: 10, coveragePermille: 1000,
      scenarioSetDigest: 'aaa', resultsDigest: 'bbb', grade: 'A',
      stats: { pass: 10, fail: 0, warn: 0, info: 0, error: 0 },
      ...over.run,
    },
    target: { host: 'fw.internal', port: 443, addressClass: 'private', localServer: false, ...over.target },
    evidence: over.evidence,
    chain: over.chain || { keyId: KEY_ID, chainSeq: 0, prevReceiptHash: null },
    signer: { email: 'dev@example.com', name: 'Dev' },
  });
}
const sign = (r) => A.signReceipt(r, { privateKeyPem: privateKey, keyId: KEY_ID });

// ── canonicalization ────────────────────────────────────────────────

test('canonical form is key-order independent', () => {
  assert.strictEqual(A.canonicalize({ b: 1, a: { d: 2, c: 3 } }), A.canonicalize({ a: { c: 3, d: 2 }, b: 1 }));
});

test('canonical form preserves array order', () => {
  assert.strictEqual(A.canonicalize([3, 1, 2]), '[3,1,2]');
  assert.notStrictEqual(A.canonicalize([1, 2]), A.canonicalize([2, 1]));
});

test('canonicalize rejects values a cross-language verifier cannot reproduce', () => {
  assert.throws(() => A.canonicalize({ x: 1.5 }), /non-integer/);
  assert.throws(() => A.canonicalize({ x: NaN }), /non-finite/);
  assert.throws(() => A.canonicalize({ x: Infinity }), /non-finite/);
  assert.throws(() => A.canonicalize({ x: Number.MAX_SAFE_INTEGER + 2 }), /unsafe/);
  assert.throws(() => A.canonicalize(undefined), /undefined/);
});

test('canonicalize keeps null but drops undefined keys', () => {
  assert.strictEqual(A.canonicalize({ a: null, b: undefined }), '{"a":null}');
});

test('canonical form round-trips through JSON unchanged', () => {
  const r = makeReceipt();
  assert.strictEqual(A.canonicalize(JSON.parse(A.canonicalize(r))), A.canonicalize(r));
});

test('signing preimage is domain-separated', () => {
  assert.ok(A.preimage({ a: 1 }).toString('utf8').startsWith(A.DOMAIN + '\n'));
});

// ── build / sign / verify ───────────────────────────────────────────

test('buildReceipt is byte-stable across identical calls', () => {
  assert.strictEqual(A.canonicalize(makeReceipt()), A.canonicalize(makeReceipt()));
});

test('a freshly signed receipt verifies', () => {
  const res = A.verifyEnvelope(sign(makeReceipt()), { registry: REGISTRY, now: T0 + 61000 });
  assert.ok(res.ok, JSON.stringify(res.errors));
  assert.ok(res.signatureValid);
  assert.ok(res.keyKnown);
});

test('editing any field breaks the hash', () => {
  const env = sign(makeReceipt());
  env.receipt.run.grade = 'F';
  const res = A.verifyEnvelope(env, { registry: REGISTRY, now: T0 + 61000 });
  assert.ok(!res.ok);
  assert.ok(res.errors.some((e) => e.code === 'hash-mismatch'), JSON.stringify(res.errors));
});

test('re-hashing an edited receipt without the key breaks the signature', () => {
  // The two-layer property: you cannot edit without breaking the hash, and
  // cannot repair the hash without the private key.
  const env = sign(makeReceipt());
  env.receipt.run.grade = 'F';
  env.receiptHash = A.receiptHashOf(env.receipt);
  const res = A.verifyEnvelope(env, { registry: REGISTRY, now: T0 + 61000 });
  assert.ok(!res.ok);
  assert.ok(res.errors.some((e) => e.code === 'signature-invalid'), JSON.stringify(res.errors));
});

test('reordering keys does not break verification', () => {
  const env = sign(makeReceipt());
  const reordered = JSON.parse(A.canonicalize(env));
  assert.ok(A.verifyEnvelope(reordered, { registry: REGISTRY, now: T0 + 61000 }).ok);
});

test('a signer cannot assert friendlier signals than the body implies', () => {
  const receipt = makeReceipt({ run: { grade: 'I' } });
  receipt.signals.inconclusive = false;      // lie about it
  const res = A.verifyEnvelope(sign(receipt), { registry: REGISTRY, now: T0 + 61000 });
  assert.ok(res.errors.some((e) => e.code === 'signals-mismatch'), JSON.stringify(res.errors));
});

test('an unregistered key is reported distinctly from a forgery', () => {
  const res = A.verifyEnvelope(sign(makeReceipt()), { registry: new Map(), now: T0 + 61000 });
  assert.ok(!res.ok);
  assert.ok(res.errors.some((e) => e.code === 'key-unknown'));
  assert.strictEqual(res.keyKnown, false);
});

test('a revoked key invalidates only runs finishing after revocation', () => {
  const revoked = new Map([[KEY_ID, {
    keyId: KEY_ID, publicKeyPem: publicKey, revokedAt: new Date(T0 + 30000).toISOString(),
  }]]);
  const after = A.verifyEnvelope(sign(makeReceipt()), { registry: revoked, now: T0 + 90000 });
  assert.ok(after.errors.some((e) => e.code === 'key-revoked'), 'run after revocation should fail');
  const before = A.verifyEnvelope(
    sign(makeReceipt({ run: { finishedAt: T0 + 10000 } })), { registry: revoked, now: T0 + 90000 });
  assert.ok(!before.errors.some((e) => e.code === 'key-revoked'), 'run before revocation should stand');
});

test('impossible clocks are rejected', () => {
  const back = A.verifyEnvelope(sign(makeReceipt({ run: { finishedAt: T0 - 1000 } })), { registry: REGISTRY, now: T0 });
  assert.ok(back.errors.some((e) => e.code === 'clock-invalid'));
  const future = A.verifyEnvelope(sign(makeReceipt()), { registry: REGISTRY, now: T0 - 5 * 86400000 });
  assert.ok(future.errors.some((e) => e.code === 'clock-invalid'));
});

// ── warnings: authentic but weak evidence ───────────────────────────

test('weak evidence produces warnings, not errors', () => {
  const receipt = makeReceipt({
    run: { grade: 'I', aborted: true, abortReason: 'sigint', coveragePermille: 120 },
    target: { host: 'localhost', addressClass: 'loopback', localServer: true },
  });
  const res = A.verifyEnvelope(sign(receipt), { registry: REGISTRY, now: T0 + 61000 });
  assert.ok(res.ok, `should still verify: ${JSON.stringify(res.errors)}`);
  const codes = res.warnings.map((w) => w.code);
  for (const c of ['inconclusive', 'aborted', 'trivial-target', 'low-coverage', 'no-evidence', 'chain-genesis']) {
    assert.ok(codes.includes(c), `missing warning ${c} in ${codes.join(',')}`);
  }
});

test('an unbindable keylog warns but never fails — h2 and distributed do this legitimately', () => {
  const receipt = makeReceipt({
    evidence: {
      pcap: { sha256: 'a', bytes: 100, packets: 5, firstPacketAtMs: T0 + 10, lastPacketAtMs: T0 + 900 },
      keylog: { sha256: 'b', bytes: 50, lines: 478, clientRandoms: 478 },
      binding: { method: 'client-random-in-pcap', randoms: 478, matched: 0, status: 'unavailable' },
    },
  });
  const res = A.verifyEnvelope(sign(receipt), { registry: REGISTRY, now: T0 + 61000 });
  assert.ok(res.ok, JSON.stringify(res.errors));
  assert.ok(res.warnings.some((w) => w.code === 'binding-unavailable'));
});

test('a pcap from outside the run window is flagged', () => {
  const receipt = makeReceipt({
    evidence: {
      pcap: { sha256: 'a', bytes: 100, packets: 5, firstPacketAtMs: T0 - 86400000, lastPacketAtMs: T0 - 86000000 },
      keylog: null, binding: null,
    },
  });
  const res = A.verifyEnvelope(sign(receipt), { registry: REGISTRY, now: T0 + 61000 });
  assert.ok(res.warnings.some((w) => w.code === 'pcap-window'), JSON.stringify(res.warnings));
});

// ── chaining ────────────────────────────────────────────────────────

function chainOf(n) {
  const out = [];
  let prev = null;
  for (let i = 0; i < n; i++) {
    const { chainSeq, prevReceiptHash } = A.chainNext(prev);
    const env = sign(makeReceipt({
      receiptId: `r-${i}`,
      run: { finishedAt: T0 + 60000 + i * 1000 },
      chain: { keyId: KEY_ID, chainSeq, prevReceiptHash },
    }));
    out.push(env);
    prev = env;
  }
  return out;
}

test('a well-formed chain verifies', () => {
  const res = A.verifyChain(chainOf(3));
  assert.ok(res.ok, JSON.stringify(res.breaks));
});

test('rewriting a past entry breaks the chain', () => {
  const chain = chainOf(3);
  chain[1] = sign(makeReceipt({ receiptId: 'forged', chain: { keyId: KEY_ID, chainSeq: 1, prevReceiptHash: 'nope' } }));
  const res = A.verifyChain(chain);
  assert.ok(!res.ok);
  assert.strictEqual(res.breaks[0].index, 1);
});

test('backdating an entry is detected', () => {
  const chain = chainOf(2);
  const { chainSeq, prevReceiptHash } = A.chainNext(chain[0]);
  chain[1] = sign(makeReceipt({ run: { finishedAt: T0 - 999999 }, chain: { keyId: KEY_ID, chainSeq, prevReceiptHash } }));
  assert.ok(A.verifyChain(chain).breaks.some((b) => /backdated/.test(b.reason)));
});

test('the genesis entry has no predecessor', () => {
  assert.deepStrictEqual(A.chainNext(null), { chainSeq: 0, prevReceiptHash: null });
});

// ── block encoding ──────────────────────────────────────────────────

test('a block round-trips', () => {
  const env = sign(makeReceipt());
  const decoded = A.decodeBlock(A.encodeBlock(env));
  assert.strictEqual(decoded.receiptHash, env.receiptHash);
});

test('a block survives being pasted into surrounding markdown', () => {
  const env = sign(makeReceipt());
  const block = A.encodeBlock(env, { human: '**WireStrike run attestation**\n\n| Grade | A |' });
  const buried = `Some PR description.\n\n<details><summary>evidence</summary>\n\n${block}\n\n</details>\n\nThanks!`;
  assert.strictEqual(A.decodeBlock(buried).receiptHash, env.receiptHash);
});

test('a quoted reply still yields the block', () => {
  const env = sign(makeReceipt());
  const quoted = A.encodeBlock(env).split('\n').map((l) => `> ${l}`).join('\n');
  assert.strictEqual(A.decodeBlock(quoted).receiptHash, env.receiptHash);
});

test('when a comment accumulates blocks, the last one wins', () => {
  const first = sign(makeReceipt({ receiptId: 'old' }));
  const second = sign(makeReceipt({ receiptId: 'new' }));
  const both = `${A.encodeBlock(first)}\n\nedited:\n\n${A.encodeBlock(second)}`;
  assert.strictEqual(A.decodeBlock(both).receipt.receiptId, 'new');
});

test('an oversized receipt switches to the gzip prefix and still round-trips', () => {
  const big = makeReceipt();
  big.repo.dirtyFiles = Array.from({ length: 100 }, (_, i) => ({
    path: `lib/some/deeply/nested/path/file-${i}.js`, status: 'M', sha256: 'c'.repeat(64),
  }));
  big.signals = A.deriveSignals(big);
  const env = sign(big);
  const block = A.encodeBlock(env);
  assert.ok(block.startsWith(A.BLOCK_PREFIX_GZ + ':'), 'expected gzip prefix for a large receipt');
  assert.strictEqual(A.decodeBlock(block).receiptHash, env.receiptHash);
  assert.ok(A.verifyEnvelope(A.decodeBlock(block), { registry: REGISTRY, now: T0 + 61000 }).ok);
});

test('garbage decodes to null rather than throwing', () => {
  assert.strictEqual(A.decodeBlock('no block here'), null);
  assert.strictEqual(A.decodeBlock('wsr1:!!!!not-base64!!!!'), null);
  assert.strictEqual(A.decodeBlock(null), null);
});

// ── registry ────────────────────────────────────────────────────────

test('a registry file parses into a usable key', () => {
  const spki = publicKey.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const entry = A.parseRegistryFile(
    `# WireStrike attestation key\nkeyId    ${KEY_ID}\nalg      ed25519\nemail    dev@example.com\npub      ${spki}\n`);
  assert.strictEqual(entry.keyId, KEY_ID);
  assert.strictEqual(entry.email, 'dev@example.com');
  assert.strictEqual(A.keyIdFromPublicKey(entry.publicKeyPem), KEY_ID);
});

// ── portability guard ───────────────────────────────────────────────

test('the core depends only on Node builtins so CI can vendor it alone', () => {
  const src = fs.readFileSync(require.resolve('./lib/attestation'), 'utf8');
  const requires = [...src.matchAll(/require\((['"])([^'"]+)\1\)/g)].map((m) => m[2]);
  const allowed = new Set(['crypto', 'zlib']);
  const unexpected = requires.filter((r) => !allowed.has(r));
  assert.deepStrictEqual(unexpected, [], `unexpected requires: ${unexpected.join(', ')}`);
});

// ── store: keys, ledger, run records (temp WIRESTRIKE_HOME) ─────────

const os = require('os');
const path = require('path');
process.env.WIRESTRIKE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'wirestrike-attest-'));
const S = require('./lib/attestation-store');

test('a key is generated once and refuses silent replacement', () => {
  assert.strictEqual(S.keyStatus().exists, false);
  const gen = S.generateKeyPair();
  assert.ok(gen.keyId && gen.publicKeyPem);
  assert.strictEqual(S.keyStatus().keyId, gen.keyId);
  assert.throws(() => S.generateKeyPair(), /already exists/);
  assert.ok(S.generateKeyPair({ force: true }).keyId);
});

test('the private key is not world-readable', () => {
  const mode = fs.statSync(S.privateKeyPath()).mode & 0o777;
  assert.strictEqual(mode, 0o600, `expected 0600, got ${mode.toString(8)}`);
});

test('the registry file round-trips through the parser', () => {
  const st = S.keyStatus();
  const file = S.registryFileFor({ keyId: st.keyId, publicKeyPem: st.publicKeyPem, email: 'a@b.com', name: 'A B' });
  assert.ok(file.relPath.includes(st.keyId));
  const parsed = A.parseRegistryFile(file.content);
  assert.strictEqual(parsed.keyId, st.keyId);
  assert.strictEqual(A.keyIdFromPublicKey(parsed.publicKeyPem), st.keyId);
});

test('a registry rejects a key whose declared keyId does not match its bytes', () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'wirestrike-repo-'));
  const dir = path.join(repo, '.wirestrike', 'keys');
  fs.mkdirSync(dir, { recursive: true });
  const st = S.keyStatus();
  const good = S.registryFileFor({ keyId: st.keyId, publicKeyPem: st.publicKeyPem, email: 'a@b.com' });
  fs.writeFileSync(path.join(dir, 'good.pub'), good.content);
  fs.writeFileSync(path.join(dir, 'bad.pub'), good.content.replace(st.keyId, 'x'.repeat(16)));
  const reg = S.loadRegistry(repo);
  assert.strictEqual(reg.byKeyId.size, 1);
  assert.strictEqual(reg.errors.length, 1);
  assert.match(reg.errors[0].error, /does not match/);
});

test('the ledger appends and reads back in order', () => {
  const repoId = 'repo-ledger';
  let prev = null;
  for (let i = 0; i < 3; i++) {
    const { chainSeq, prevReceiptHash } = A.chainNext(prev);
    const env = sign(makeReceipt({ receiptId: `led-${i}`, run: { finishedAt: T0 + i * 1000 },
      chain: { keyId: KEY_ID, chainSeq, prevReceiptHash } }));
    S.appendToLedger(repoId, env);
    prev = env;
  }
  const { envelopes, errors } = S.readLedger(repoId);
  assert.strictEqual(envelopes.length, 3);
  assert.deepStrictEqual(errors, []);
  assert.ok(A.verifyChain(envelopes).ok);
  assert.strictEqual(S.tailLedger(repoId).receipt.receiptId, 'led-2');
});

test('a corrupt ledger line is reported, not thrown', () => {
  const repoId = 'repo-corrupt';
  S.appendToLedger(repoId, sign(makeReceipt()));
  fs.appendFileSync(S.ledgerPath(repoId), '{ not json\n');
  const { envelopes, errors } = S.readLedger(repoId);
  assert.strictEqual(envelopes.length, 1);
  assert.strictEqual(errors.length, 1);
});

test('run records save, load and prune to the cap', () => {
  const repoId = 'repo-runs';
  for (let i = 0; i < S.MAX_RUN_RECORDS + 5; i++) {
    S.saveRunRecord(repoId, { runId: `run-${String(i).padStart(3, '0')}`, protocol: 'tls' });
  }
  const kept = fs.readdirSync(S.runsDir(repoId)).filter((n) => n.endsWith('.json'));
  assert.strictEqual(kept.length, S.MAX_RUN_RECORDS);
  assert.ok(S.latestRunRecord(repoId));
  assert.strictEqual(S.loadRunRecord(repoId, 'run-054').protocol, 'tls');
});

test('a hostile repoId cannot escape the store directory', () => {
  assert.throws(() => S.ledgerPath('../../etc/passwd'), /Unsafe identifier/);
  assert.throws(() => S.saveRunRecord('ok', { runId: '../escape' }), /Unsafe identifier/);
});

// ── evidence: git, pcap, keylog, digests ────────────────────────────

const E = require('./lib/attestation-evidence');

test('repo info reports this repository', () => {
  const r = E.collectRepoInfo(process.cwd());
  assert.strictEqual(r.available, true);
  assert.match(r.headSha, /^[0-9a-f]{40}$/);
  assert.match(r.repoId, /^[0-9a-f]{16}$/);
  assert.strictEqual(typeof r.dirty, 'boolean');
});

test('repo info degrades gracefully outside a git repo', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wirestrike-nogit-'));
  assert.deepStrictEqual(E.collectRepoInfo(tmp), { available: false });
});

test('tool info carries a version and a code digest', () => {
  const t = E.collectToolInfo(process.cwd());
  assert.strictEqual(t.name, 'wirestrike');
  assert.ok(t.version, 'version should come from package.json');
  assert.match(t.codeDigest, /^[0-9a-f]{64}$/);
  assert.strictEqual(t.codeDigest, E.collectToolInfo(process.cwd()).codeDigest, 'digest must be stable');
});

test('keylog binds to its pcap for a raw-socket TLS run', () => {
  // Empirical fixture: this run really did capture the ClientHello.
  if (!fs.existsSync('dist-tls-avsb.pcap')) return;
  const k = E.inspectKeylog('dist-tls-avsb.keylog');
  const b = E.bindKeylogToPcap(k, 'dist-tls-avsb.pcap');
  assert.strictEqual(b.status, 'verified');
  assert.strictEqual(b.matched, b.randoms);
  assert.strictEqual(b.randoms, 159);
});

test('an h2 run cannot bind, and that is not a failure', () => {
  // The h2 path never writes the ClientHello into the pcap. If this ever
  // starts binding the capture path changed — worth knowing either way.
  if (!fs.existsSync('dist-h2-wb.pcap')) return;
  const k = E.inspectKeylog('dist-h2-wb.keylog');
  const b = E.bindKeylogToPcap(k, 'dist-h2-wb.pcap');
  assert.strictEqual(b.status, 'unavailable');
  assert.strictEqual(b.matched, 0);
});

test('pcap inspection reports packets and a monotonic window', () => {
  if (!fs.existsSync('dist-tls-avsb.pcap')) return;
  const p = E.inspectPcap('dist-tls-avsb.pcap');
  assert.ok(p.packets > 0);
  assert.ok(p.lastPacketAtMs >= p.firstPacketAtMs);
  assert.match(p.sha256, /^[0-9a-f]{64}$/);
  assert.strictEqual(E.inspectPcap('/nonexistent.pcap'), null);
});

test('results digest ignores ordering but not multiplicity', () => {
  const a = [{ scenario: 'x', status: 'PASSED', verdict: 'AS EXPECTED', finding: { grade: 'PASS' } },
             { scenario: 'y', status: 'DROPPED', verdict: 'AS EXPECTED', finding: { grade: 'PASS' } }];
  assert.strictEqual(E.resultsDigest(a), E.resultsDigest([a[1], a[0]]));
  assert.notStrictEqual(E.resultsDigest(a), E.resultsDigest([...a, a[0]]));
});

test('scenario set digest changes when a scenario body changes', () => {
  const s1 = [{ name: 'a', category: 'A', side: 'client', actions: () => 1 }];
  const s2 = [{ name: 'a', category: 'A', side: 'client', actions: () => 2 }];
  assert.notStrictEqual(E.scenarioSetDigest(s1).digest, E.scenarioSetDigest(s2).digest);
  assert.strictEqual(E.scenarioSetDigest(s1).digest, E.scenarioSetDigest(s1).digest);
});

test('address classes distinguish a trivial target from a real one', async () => {
  assert.strictEqual(E.classifyAddressSync('localhost'), 'loopback');
  assert.strictEqual(E.classifyAddressSync('127.0.0.1'), 'loopback');
  assert.strictEqual(E.classifyAddressSync('10.0.0.5'), 'private');
  assert.strictEqual(E.classifyAddressSync('8.8.8.8'), 'public');
});

if (failures) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log('\nAll attestation tests passed');
