// Client side of the central attestation service: account state (anonymous
// vs signed-in), enrollment, mTLS requests, run submission, token fetch.
//
// The mTLS identity is the same Ed25519 key that signs run receipts
// (~/.wirestrike/keys/ed25519.key) — enrollment wraps it in a 2-year client
// certificate issued by the operator's server. "Logout" only flips the mode
// back to anonymous; the key and certificate stay on disk for `--login`.

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const A = require('./attestation');
const S = require('./attestation-store');

const ENROLL_DOMAIN = 'wirestrike-enroll-v1';
const REQUEST_TIMEOUT_MS = 15000;

const configPath = () => path.join(S.homeDir(), 'remote.json');
const clientCertPath = () => path.join(S.homeDir(), 'keys', 'client-cert.pem');
const pinnedServerCertPath = () => path.join(S.homeDir(), 'server', 'server.pem');

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(configPath(), 'utf8'));
  } catch (_) {
    return { mode: 'anonymous' };
  }
}

function saveConfig(config) {
  fs.mkdirSync(S.homeDir(), { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath(), `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

function isSignedIn() {
  return loadConfig().mode === 'account';
}

function serverUrl(explicit) {
  return explicit || process.env.WIRESTRIKE_ATTEST_URL || loadConfig().serverUrl || null;
}

// All traffic pins the operator's self-signed server certificate — there is
// no public CA in this PKI, so an unpinned request would be unverifiable.
function request(method, urlPath, body, { base, mtls = false } = {}) {
  const target = serverUrl(base);
  if (!target) throw new Error('No attestation server configured — pass --server or set WIRESTRIKE_ATTEST_URL');
  let pinned;
  try {
    pinned = fs.readFileSync(pinnedServerCertPath(), 'utf8');
  } catch (_) {
    throw new Error('No pinned server certificate — run `node cli.js account --create` (or --login) with --server-cert first');
  }
  const url = new URL(urlPath, target);
  const options = {
    method,
    hostname: url.hostname,
    port: url.port || 443,
    path: url.pathname + url.search,
    ca: [pinned],
    timeout: REQUEST_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json' },
  };
  if (mtls) {
    options.cert = fs.readFileSync(clientCertPath(), 'utf8');
    options.key = fs.readFileSync(S.privateKeyPath(), 'utf8');
  }
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) {}
        resolve({ statusCode: res.statusCode, body: parsed });
      });
    });
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    if (body !== undefined) req.write(JSON.stringify(body));
    req.end();
  });
}

// Create the account: prove possession of the local attestation key, receive
// the 2-year client certificate, pin the server certificate, sign in.
async function enroll({ server, username, email, serverCertPath }) {
  const { privateKeyPem } = S.loadPrivateKey();
  const { publicKeyPem } = S.keyStatus();

  // Bootstrap trust: an explicit --server-cert wins; otherwise the copy the
  // repo commits at .wirestrike/server/server.pem. Never trust-on-first-use.
  let anchor = null;
  const repoCopy = path.join(process.cwd(), '.wirestrike', 'server', 'server.pem');
  const source = serverCertPath || (fs.existsSync(repoCopy) ? repoCopy : null);
  if (source) anchor = fs.readFileSync(source, 'utf8');
  if (!anchor) {
    throw new Error('Cannot establish trust in the server: pass --server-cert <path>, or run from a repo checkout that commits .wirestrike/server/server.pem');
  }
  fs.mkdirSync(path.dirname(pinnedServerCertPath()), { recursive: true, mode: 0o700 });
  fs.writeFileSync(pinnedServerCertPath(), anchor, { mode: 0o644 });

  const requestedAt = Date.now();
  const unsigned = { username, email, publicKeyPem, requestedAt };
  const preimage = Buffer.from(`${ENROLL_DOMAIN}\n${A.canonicalize(unsigned)}`, 'utf8');
  const signature = crypto.sign(null, preimage, privateKeyPem).toString('base64');

  const { statusCode, body } = await request('POST', '/enroll', { v: 1, ...unsigned, signature }, { base: server });
  if (statusCode !== 200 || !body?.ok) {
    throw new Error(`Enrollment failed (${statusCode}): ${body?.message || body?.error || 'unknown error'}`);
  }
  fs.writeFileSync(clientCertPath(), body.certPem, { mode: 0o644 });
  fs.writeFileSync(pinnedServerCertPath(), body.serverCertPem, { mode: 0o644 });
  saveConfig({
    mode: 'account', serverUrl: serverUrl(server),
    username: body.username, email: body.email, keyId: body.keyId,
  });
  return body;
}

// "Login" is an mTLS round-trip: the server recognizing our client
// certificate is the credential check. No password exists anywhere.
async function login({ server } = {}) {
  const { statusCode, body } = await request('GET', '/whoami', undefined, { base: server, mtls: true });
  if (statusCode !== 200 || !body?.ok) {
    throw new Error(`Login failed (${statusCode}): ${body?.error || 'unknown error'}`);
  }
  const config = loadConfig();
  saveConfig({
    ...config, mode: 'account', serverUrl: serverUrl(server) || config.serverUrl,
    username: body.username, email: body.email, keyId: body.keyId,
  });
  return body;
}

function logout() {
  const config = loadConfig();
  saveConfig({ ...config, mode: 'anonymous' });
}

function accountStatus() {
  const config = loadConfig();
  const status = { ...config, enrolled: fs.existsSync(clientCertPath()) };
  if (status.enrolled) {
    try {
      const cert = new crypto.X509Certificate(fs.readFileSync(clientCertPath(), 'utf8'));
      status.certSubject = cert.subject.replace(/\n/g, ', ');
      status.certExpiresAt = Date.parse(cert.validTo);
    } catch (_) {}
  }
  return status;
}

async function submitRun({ envelope, prNumber = null, server } = {}) {
  const { statusCode, body } = await request('POST', '/runs', {
    v: 1, envelope, prNumber: Number.isInteger(prNumber) ? prNumber : null, submittedAt: Date.now(),
  }, { base: server, mtls: true });
  if (statusCode !== 200 || !body?.ok) {
    throw new Error(`Submission failed (${statusCode}): ${body?.error || 'unknown error'}`);
  }
  return body;
}

async function listRuns({ server } = {}) {
  const { statusCode, body } = await request('GET', '/runs', undefined, { base: server, mtls: true });
  if (statusCode !== 200 || !body?.ok) {
    throw new Error(`Could not list runs (${statusCode}): ${body?.error || 'unknown error'}`);
  }
  return body;
}

async function getRun(serial, { server } = {}) {
  const { statusCode, body } = await request('GET', `/runs/${serial}`, undefined, { base: server, mtls: true });
  if (statusCode === 404) throw new Error(`No run #${serial} in your history`);
  if (statusCode !== 200 || !body?.ok) {
    throw new Error(`Could not fetch run #${serial} (${statusCode}): ${body?.error || 'unknown error'}`);
  }
  return body;
}

// Live-run reporting. Best-effort: any failure resolves to {ok:false} rather
// than throwing, so a run is never disrupted by the attestation server being
// slow or down. Only meaningful when signed in.
async function reportRun(kind, body) {
  try {
    if (!isSignedIn()) return { ok: false };
    const { statusCode, body: res } = await request('POST', `/runs/${kind}`, { v: 1, ...body }, { mtls: true });
    return { ok: statusCode === 200 && !!res?.ok };
  } catch (_) {
    return { ok: false };
  }
}
const reportRunStart = (meta) => reportRun('start', meta);
const reportRunHeartbeat = (runId) => reportRun('heartbeat', { runId });
const reportRunFinish = (runId) => reportRun('finish', { runId });

async function fetchToken(serial, { server } = {}) {
  const { statusCode, body } = await request('GET', `/token/${serial}`, undefined, { base: server });
  if (statusCode !== 200 || !body?.ok) {
    throw new Error(`Token lookup failed (${statusCode}): ${body?.error || 'unknown error'}`);
  }
  return body;
}

module.exports = {
  ENROLL_DOMAIN,
  configPath, clientCertPath, pinnedServerCertPath,
  loadConfig, saveConfig, isSignedIn, serverUrl,
  enroll, login, logout, accountStatus, submitRun, fetchToken, listRuns, getRun,
  reportRunStart, reportRunHeartbeat, reportRunFinish,
};
