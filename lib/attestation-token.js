// The PR token: the attestation server's signed statement that it verified a
// user's run receipt. `wst1:<payload>.<sig>` — one paste-able line, both
// halves base64url so the dot is unambiguous.
//
// What a token asserts: "at issuedAt the server verified an envelope
// correctly signed by <username>'s enrolled key, whose receipt hashes to
// receiptHash, claiming PR prNumber". It does not assert the run happened —
// see the threat model atop lib/attestation.js.
//
// Like lib/attestation.js this module must stay vendorable by a CI validator:
// Node builtins plus ./attestation only. test-attest-server.js asserts that.

const crypto = require('crypto');
const { canonicalize, receiptHashOf } = require('./attestation');

const TOKEN_DOMAIN = 'wirestrike-token-v1';
const TOKEN_PREFIX = 'wst1';

// The signature covers the transmitted payload bytes, not a re-canonicalized
// form: a verifier in any language checks exactly what it received.
function signToken(payload, { privateKeyPem }) {
  const payloadB64 = Buffer.from(canonicalize(payload), 'utf8').toString('base64url');
  const preimage = Buffer.from(`${TOKEN_DOMAIN}\n${payloadB64}`, 'utf8');
  const signature = crypto.sign(null, preimage, privateKeyPem).toString('base64url');
  return `${TOKEN_PREFIX}:${payloadB64}.${signature}`;
}

// Extract a token from arbitrary pasted text (a PR description, a file, a
// bare token). Last match wins, same as decodeBlock: an edited paste with a
// stale token above the real one should resolve to the newest.
function decodeToken(text) {
  const re = /wst1:([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)/g;
  let match = null;
  for (const m of String(text).matchAll(re)) match = m;
  if (!match) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;
  return { payload, payloadB64: match[1], signature: match[2] };
}

// Verify a token against the server certificate (the trust anchor a repo
// commits at .wirestrike/server/server.pem). Pass the envelope decoded from
// the same pasted text to also enforce token↔receipt binding.
function verifyToken(text, { serverCertPem, now = Date.now(), envelope = null }) {
  const errors = [];
  const warnings = [];
  const decoded = decodeToken(text);
  if (!decoded) {
    return { ok: false, payload: null, errors: [{ code: 'malformed', message: 'No wst1: token found in input' }], warnings };
  }
  const { payload, payloadB64, signature } = decoded;

  let cert;
  try {
    cert = new crypto.X509Certificate(serverCertPem);
  } catch (err) {
    return { ok: false, payload, errors: [{ code: 'server-cert', message: `Unreadable server certificate: ${err.message}` }], warnings };
  }

  const preimage = Buffer.from(`${TOKEN_DOMAIN}\n${payloadB64}`, 'utf8');
  let sigOk = false;
  try {
    sigOk = crypto.verify(null, preimage, cert.publicKey, Buffer.from(signature, 'base64url'));
  } catch (_) {}
  if (!sigOk) errors.push({ code: 'signature-invalid', message: 'Token signature does not verify against the server certificate' });

  if (payload.v !== 1) errors.push({ code: 'schema', message: `Unsupported token version ${payload.v}` });
  if (!Number.isInteger(payload.issuedAt)) {
    errors.push({ code: 'schema', message: 'Token has no integer issuedAt' });
  } else {
    if (payload.issuedAt > now + 86400000) errors.push({ code: 'clock-invalid', message: 'Token issuedAt is more than a day in the future' });
    const from = Date.parse(cert.validFrom);
    const to = Date.parse(cert.validTo);
    if (payload.issuedAt < from || payload.issuedAt > to) {
      warnings.push({ code: 'cert-window', message: 'Token issuedAt falls outside the server certificate validity window' });
    }
  }

  if (envelope) {
    if (receiptHashOf(envelope.receipt) !== payload.receiptHash) {
      errors.push({ code: 'receipt-mismatch', message: 'Token was issued for a different receipt than the wsr1 block alongside it' });
    }
  }

  return { ok: errors.length === 0, payload, errors, warnings };
}

module.exports = { TOKEN_DOMAIN, TOKEN_PREFIX, signToken, decodeToken, verifyToken };
