// On-disk side of attestation: the developer's signing key, the append-only
// receipt ledger, and durable run records.
//
// Deliberately separate from lib/run-history.js. That store lives under
// Electron's userData, is capped at 10 runs and is meant to be pruned — fine
// for a UI history, useless as evidence. This one is durable, never pruned,
// and reachable from the CLI with no Electron involved.
//
// Nothing here is secret except the private key. The ledger never leaves the
// machine; only what the developer chooses to paste is disclosed.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { keyIdFromPublicKey, parseRegistryFile } = require('./attestation');

const MAX_RUN_RECORDS = 50;
const LOCK_STALE_MS = 5000;

function homeDir() {
  if (process.env.WIRESTRIKE_HOME) return process.env.WIRESTRIKE_HOME;
  const home = os.homedir();
  if (!home) throw new Error('Cannot locate a home directory; set WIRESTRIKE_HOME');
  return path.join(home, '.wirestrike');
}

const keysDir = () => path.join(homeDir(), 'keys');
const privateKeyPath = () => path.join(keysDir(), 'ed25519.key');
const publicKeyPath = () => path.join(keysDir(), 'ed25519.pub');
const ledgerPath = (repoId) => path.join(homeDir(), 'attestations', `${safeId(repoId)}.ndjson`);
const runsDir = (repoId) => path.join(homeDir(), 'runs', safeId(repoId));

// Ledger and run paths are built from a repoId; never let it escape the dir.
function safeId(id) {
  const s = String(id || 'unknown');
  if (!/^[A-Za-z0-9_.-]+$/.test(s)) throw new Error(`Unsafe identifier: ${s}`);
  return s;
}

// ── Keys ────────────────────────────────────────────────────────────

function keyStatus() {
  try {
    const publicKeyPem = fs.readFileSync(publicKeyPath(), 'utf8');
    return { exists: true, keyId: keyIdFromPublicKey(publicKeyPem), publicKeyPem, path: privateKeyPath() };
  } catch (_) {
    return { exists: false, keyId: null, publicKeyPem: null, path: privateKeyPath() };
  }
}

// Never called implicitly during a run: a key created silently mid-run would
// defeat the point, which is that signing is a deliberate, registered act.
function generateKeyPair({ force = false } = {}) {
  if (!force && keyStatus().exists) {
    throw new Error('An attestation key already exists; pass --force to replace it (old receipts stay verifiable)');
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.mkdirSync(keysDir(), { recursive: true, mode: 0o700 });
  fs.writeFileSync(privateKeyPath(), privateKey, { mode: 0o600 });
  fs.writeFileSync(publicKeyPath(), publicKey, { mode: 0o644 });
  return { keyId: keyIdFromPublicKey(publicKey), publicKeyPem: publicKey, privateKeyPath: privateKeyPath() };
}

function loadPrivateKey() {
  const st = keyStatus();
  if (!st.exists) {
    throw new Error('No attestation key found — run `node cli.js attest --init-key` first');
  }
  return { privateKeyPem: fs.readFileSync(privateKeyPath(), 'utf8'), keyId: st.keyId };
}

// The registry content the developer commits. The trust anchor is the
// reviewed commit that adds this file, exactly like authorized_keys.
function registryFileFor({ keyId, publicKeyPem, email, name }) {
  const spki = publicKeyPem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const slug = String(email || 'unknown').replace(/[^A-Za-z0-9]+/g, '-').toLowerCase();
  return {
    relPath: path.join('.wirestrike', 'keys', `${slug}.${keyId}.pub`),
    content: [
      '# WireStrike attestation key',
      `keyId    ${keyId}`,
      'alg      ed25519',
      `email    ${email || ''}`,
      `name     ${name || ''}`,
      `addedAt  ${new Date().toISOString()}`,
      `pub      ${spki}`,
      '',
    ].join('\n'),
  };
}

// Reads every .pub committed to the repo. Corrupt entries are collected
// rather than thrown so one bad file cannot block all verification.
function loadRegistry(repoRoot) {
  const byKeyId = new Map();
  const byEmail = new Map();
  const errors = [];
  const dir = path.join(repoRoot, '.wirestrike', 'keys');
  let names = [];
  try {
    names = fs.readdirSync(dir);
  } catch (_) {
    return { byKeyId, byEmail, errors };
  }
  for (const name of names) {
    if (!name.endsWith('.pub')) continue;
    try {
      const entry = parseRegistryFile(fs.readFileSync(path.join(dir, name), 'utf8'));
      if (!entry.keyId || !entry.publicKeyPem) {
        errors.push({ file: name, error: 'missing keyId or pub' });
        continue;
      }
      if (keyIdFromPublicKey(entry.publicKeyPem) !== entry.keyId) {
        errors.push({ file: name, error: 'keyId does not match the public key it declares' });
        continue;
      }
      byKeyId.set(entry.keyId, entry);
      if (entry.email) byEmail.set(entry.email.toLowerCase(), entry);
    } catch (err) {
      errors.push({ file: name, error: err.message });
    }
  }
  return { byKeyId, byEmail, errors };
}

// ── Ledger ──────────────────────────────────────────────────────────

// Advisory lock so two concurrent CLI runs cannot fork the chain.
function withLock(target, fn) {
  const lock = `${target}.lock`;
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const deadline = Date.now() + LOCK_STALE_MS;
  let fd = null;
  for (;;) {
    try {
      fd = fs.openSync(lock, 'wx');
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      let age = Infinity;
      try { age = Date.now() - fs.statSync(lock).mtimeMs; } catch (_) {}
      if (age > LOCK_STALE_MS) { try { fs.unlinkSync(lock); } catch (_) {} continue; }
      if (Date.now() > deadline) throw new Error('Another run is writing the attestation ledger; try again');
    }
  }
  try {
    return fn();
  } finally {
    try { fs.closeSync(fd); } catch (_) {}
    try { fs.unlinkSync(lock); } catch (_) {}
  }
}

function readLedger(repoId) {
  const out = [];
  const errors = [];
  let text = '';
  try {
    text = fs.readFileSync(ledgerPath(repoId), 'utf8');
  } catch (_) {
    return { envelopes: out, errors };
  }
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      out.push(JSON.parse(line));
    } catch (err) {
      errors.push({ index: i, error: err.message });
    }
  }
  return { envelopes: out, errors };
}

function tailLedger(repoId) {
  const { envelopes } = readLedger(repoId);
  return envelopes.length ? envelopes[envelopes.length - 1] : null;
}

function appendToLedger(repoId, envelope) {
  const target = ledgerPath(repoId);
  return withLock(target, () => {
    fs.appendFileSync(target, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
    return { path: target };
  });
}

// ── Durable run records ─────────────────────────────────────────────
// Closes the "a plain CLI run emits nothing durable" gap without touching the
// working tree — so nothing lands in the repo or trips .gitignore.

function saveRunRecord(repoId, record) {
  const dir = runsDir(repoId);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${safeId(record.runId)}.json`);
  fs.writeFileSync(file, JSON.stringify(record, null, 2), { mode: 0o600 });

  const keep = fs.readdirSync(dir)
    .filter((n) => n.endsWith('.json'))
    .map((n) => ({ n, t: fs.statSync(path.join(dir, n)).mtimeMs }))
    .sort((a, b) => b.t - a.t)
    .slice(MAX_RUN_RECORDS);
  for (const stale of keep) {
    try { fs.unlinkSync(path.join(dir, stale.n)); } catch (_) {}
  }
  return file;
}

function loadRunRecord(repoId, runId) {
  try {
    return JSON.parse(fs.readFileSync(path.join(runsDir(repoId), `${safeId(runId)}.json`), 'utf8'));
  } catch (_) {
    return null;
  }
}

function latestRunRecord(repoId) {
  const dir = runsDir(repoId);
  let names = [];
  try { names = fs.readdirSync(dir).filter((n) => n.endsWith('.json')); } catch (_) { return null; }
  if (!names.length) return null;
  const newest = names
    .map((n) => ({ n, t: fs.statSync(path.join(dir, n)).mtimeMs }))
    .sort((a, b) => b.t - a.t)[0];
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, newest.n), 'utf8'));
  } catch (_) {
    return null;
  }
}

module.exports = {
  homeDir, keysDir, privateKeyPath, publicKeyPath, ledgerPath, runsDir,
  keyStatus, generateKeyPair, loadPrivateKey, registryFileFor, loadRegistry,
  readLedger, tailLedger, appendToLedger,
  saveRunRecord, loadRunRecord, latestRunRecord,
  MAX_RUN_RECORDS,
};
