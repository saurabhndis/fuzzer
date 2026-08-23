// Run attestation — the signed, chained receipt that says "this run happened,
// against this code". Pure core: build, sign, verify, encode, chain.
//
// WHAT THIS PROVES, AND WHAT IT DOES NOT
//
// A receipt cannot prove a run happened: the tool executes on a machine the
// developer controls, so every byte here is producible by hand with their own
// key. Nor can it prove the target was meaningful. What changed with the
// central attestation service (a separate, operator-run server) is who
// vouches, and how attribution works:
//   * Identity — enrollment binds a work-email account to a key: the
//     operator's server issues a 2-year X.509 certificate (CN=username,
//     emailAddress in the subject) over the enrollee's Ed25519 key — the same
//     key that signs these receipts.
//   * Authenticated submission — runs reach the server over mTLS with that
//     certificate, and the server only accepts envelopes signed by the
//     authenticated user's own key. Binding a PR number to a run is therefore
//     authorized by the key holder, never by a third party.
//   * The token — a wst1: token is the operator's server attesting "at
//     issuedAt I verified an envelope correctly signed by this user's
//     enrolled key, hashing to receiptHash, claiming PR N". Its trust anchor
//     is the reviewed commit that adds .wirestrike/server/server.pem.
//   * Custody — the server keeps an independent copy of each user's last 100
//     runs, so a rewritten local ledger disagrees with the server's record.
//   * Disclosure — trivial targets, aborted runs and inconclusive grades are
//     recorded in the receipt and passed through into token warnings, so the
//     cheap cheats stay visible to a reviewer.
//
// Still outside the model: proof of execution, proof the target mattered, and
// a dishonest operator — the server key can mint any token. The local chain,
// ledger and .wirestrike/keys/ registry keep working unchanged for anonymous
// and offline use.
//
// This file must require nothing but Node builtins (`crypto`, `zlib`): a CI
// validator vendors it on its own, with no git, no pcap parsing, no filesystem
// and no third-party packages. test-attestation.js asserts that.

const crypto = require('crypto');
const zlib = require('zlib');

const SCHEMA_VERSION = 1;
const DOMAIN = 'wirestrike-attestation-v1';
const BLOCK_PREFIX = 'wsr1';
const BLOCK_PREFIX_GZ = 'wsr1z';
// Above this many bytes of canonical JSON the block is gzipped. Both prefixes
// are part of v1 so a verifier written today keeps working when receipts grow.
const GZIP_THRESHOLD = 2048;

// ── Canonical JSON ──────────────────────────────────────────────────
// The hashing contract. Sorted keys, no whitespace, integers only. Floats are
// rejected rather than serialized: their text form varies between languages,
// and a verifier in Go or Python has to reproduce these bytes exactly.
function canonicalize(value) {
  if (value === undefined) {
    throw new TypeError('canonicalize: undefined is not representable (omit the key instead)');
  }
  if (value === null) return 'null';

  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`canonicalize: non-finite number ${value}`);
    if (!Number.isInteger(value)) throw new TypeError(`canonicalize: non-integer number ${value} (use permille/ms)`);
    if (!Number.isSafeInteger(value)) throw new TypeError(`canonicalize: unsafe integer ${value}`);
    return String(value);
  }
  if (t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (t === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalize: unsupported type ${t}`);
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

// Domain-separated so this key can never be tricked into signing something
// that merely resembles a receipt.
function preimage(receipt) {
  return Buffer.from(`${DOMAIN}\n${canonicalize(receipt)}`, 'utf8');
}

function receiptHashOf(receipt) {
  return sha256Hex(preimage(receipt));
}

// Short, stable, filename-safe identifier for a public key. Embedded in the
// registry filename so key rotation never collides.
function keyIdFromPublicKey(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('base64url').slice(0, 16);
}

// ── Build ───────────────────────────────────────────────────────────
// Pure: every input is supplied by the caller (lib/attestation-evidence.js
// does the collecting). Field order here is irrelevant — canonicalize sorts —
// but the shape is the frozen v1 schema.
function buildReceipt(input) {
  const {
    receiptId, tool, repo, run, target, evidence, chain, signer,
  } = input;

  if (!receiptId) throw new Error('buildReceipt: receiptId is required');
  if (!tool || !run) throw new Error('buildReceipt: tool and run are required');

  const receipt = {
    schemaVersion: SCHEMA_VERSION,
    receiptId,
    tool,
    repo: repo || { available: false },
    run,
    target: target || null,
    evidence: evidence || { pcap: null, keylog: null, binding: null },
    signer: signer || null,
    chain: chain || { keyId: null, chainSeq: 0, prevReceiptHash: null },
  };
  receipt.signals = deriveSignals(receipt);
  return receipt;
}

// Derived, never trusted: a verifier recomputes these from the receipt body
// and compares. Anything a signer could assert about itself belongs here, not
// in the free-form fields.
function deriveSignals(receipt) {
  const run = receipt.run || {};
  const target = receipt.target || {};
  const repo = receipt.repo || {};
  const ev = receipt.evidence || {};

  const pcap = ev.pcap;
  let pcapWithinRunWindow = null;
  let pcapSpanMs = null;
  if (pcap && Number.isInteger(pcap.firstPacketAtMs) && Number.isInteger(pcap.lastPacketAtMs)) {
    pcapSpanMs = pcap.lastPacketAtMs - pcap.firstPacketAtMs;
    if (Number.isInteger(run.startedAt) && Number.isInteger(run.finishedAt)) {
      const SLACK_MS = 5000;
      pcapWithinRunWindow =
        pcap.firstPacketAtMs >= run.startedAt - SLACK_MS &&
        pcap.lastPacketAtMs <= run.finishedAt + SLACK_MS;
    }
  }

  return {
    inconclusive: run.grade === 'I',
    aborted: !!run.aborted,
    // A run against loopback or the tool's own bundled server is legitimate,
    // but it says nothing about a real target — surface it rather than judge.
    trivialTarget: target.addressClass === 'loopback' || !!target.localServer,
    cleanTree: repo.available ? !repo.dirty : null,
    hasEvidence: !!(ev.pcap || ev.keylog),
    bindingStatus: ev.binding ? ev.binding.status : null,
    pcapWithinRunWindow,
    pcapSpanMs,
    chainContinuous: !!(receipt.chain && receipt.chain.prevReceiptHash),
  };
}

// ── Sign ────────────────────────────────────────────────────────────
function signReceipt(receipt, { privateKeyPem, keyId }) {
  const hash = receiptHashOf(receipt);
  const signature = crypto.sign(null, preimage(receipt), privateKeyPem).toString('base64');
  return {
    v: SCHEMA_VERSION,
    alg: 'ed25519',
    keyId: keyId || (receipt.chain && receipt.chain.keyId) || null,
    receipt,
    receiptHash: hash,
    signature,
  };
}

// ── Verify ──────────────────────────────────────────────────────────
// errors   = cryptographic or structural: the receipt is not what it claims.
// warnings = judgement calls: the receipt is authentic but weak evidence.
// Splitting them lets CI set policy over warnings without a format change.
function verifyEnvelope(envelope, opts = {}) {
  const { registry = null, now = Date.now(), maxAgeMs = null } = opts;
  const errors = [];
  const warnings = [];
  const add = (list, code, message) => list.push({ code, message });

  if (!envelope || typeof envelope !== 'object') {
    add(errors, 'malformed', 'Not an attestation envelope');
    return { ok: false, receipt: null, keyId: null, signer: null, signatureValid: false, signatureChecked: false, keyKnown: false, errors, warnings };
  }
  if (envelope.v !== SCHEMA_VERSION) add(errors, 'schema', `Unsupported envelope version ${envelope.v}`);
  if (envelope.alg !== 'ed25519') add(errors, 'schema', `Unsupported algorithm ${envelope.alg}`);

  const receipt = envelope.receipt;
  if (!receipt || typeof receipt !== 'object') {
    add(errors, 'malformed', 'Envelope carries no receipt');
    return { ok: false, receipt: null, keyId: envelope.keyId || null, signer: null, signatureValid: false, signatureChecked: false, keyKnown: false, errors, warnings };
  }

  // Recompute rather than trust: catches any edit to the receipt body.
  let computedHash = null;
  try {
    computedHash = receiptHashOf(receipt);
  } catch (err) {
    add(errors, 'canonicalization', `Receipt is not canonicalizable: ${err.message}`);
  }
  if (computedHash && computedHash !== envelope.receiptHash) {
    add(errors, 'hash-mismatch', 'Receipt hash does not match its contents — the receipt was edited');
  }

  // Signals are derived, so a signer cannot assert a friendlier value.
  try {
    const expected = canonicalize(deriveSignals(receipt));
    if (receipt.signals && canonicalize(receipt.signals) !== expected) {
      add(errors, 'signals-mismatch', 'Derived signals do not match the receipt body');
    }
  } catch (_) { /* canonicalization error already reported */ }

  const entry = registry && envelope.keyId ? registry.get(envelope.keyId) : null;
  const keyKnown = !!entry;
  let signatureValid = false;
  // "could not check" is not the same claim as "checked and it failed" —
  // reporting an unregistered key as INVALID would misdescribe the evidence.
  let signatureChecked = false;
  if (computedHash) {
    const publicKeyPem = entry ? entry.publicKeyPem : opts.publicKeyPem;
    if (publicKeyPem) {
      try {
        signatureValid = crypto.verify(
          null, preimage(receipt), publicKeyPem, Buffer.from(envelope.signature || '', 'base64'),
        );
        signatureChecked = true;
      } catch (err) {
        add(errors, 'signature-invalid', `Signature could not be checked: ${err.message}`);
      }
      if (signatureChecked && !signatureValid) {
        add(errors, 'signature-invalid', 'Signature does not verify against the registered key');
      }
    } else if (registry) {
      // Report "wrong key" distinctly from "forged bytes" — a developer whose
      // key is not yet merged is a different situation from a tampered block.
      add(errors, 'key-unknown', `Signing key ${envelope.keyId} is not registered in this repo`);
    }
  }

  if (entry && entry.revokedAt) {
    const finishedAt = receipt.run && receipt.run.finishedAt;
    const revokedMs = Date.parse(entry.revokedAt);
    if (Number.isFinite(revokedMs) && Number.isInteger(finishedAt) && finishedAt >= revokedMs) {
      add(errors, 'key-revoked', `Key ${envelope.keyId} was revoked before this run finished`);
    }
  }

  const run = receipt.run || {};
  if (Number.isInteger(run.startedAt) && Number.isInteger(run.finishedAt) && run.finishedAt < run.startedAt) {
    add(errors, 'clock-invalid', 'Run finished before it started');
  }
  if (Number.isInteger(run.finishedAt) && run.finishedAt - now > 24 * 3600 * 1000) {
    add(errors, 'clock-invalid', 'Run finished more than a day in the future');
  }
  if (maxAgeMs && Number.isInteger(run.finishedAt) && now - run.finishedAt > maxAgeMs) {
    add(warnings, 'stale', `Run finished ${Math.round((now - run.finishedAt) / 86400000)} days ago`);
  }

  const s = receipt.signals || {};
  if (s.inconclusive) add(warnings, 'inconclusive', 'Grade I — too little of the run executed to support any claim');
  if (s.aborted) add(warnings, 'aborted', `Run was aborted${run.abortReason ? ` (${run.abortReason})` : ''}`);
  if (s.trivialTarget) add(warnings, 'trivial-target', 'Target was loopback or the tool\'s own server');
  if (s.cleanTree === false) add(warnings, 'dirty-tree', `Working tree had ${receipt.repo.dirtyFileCount || 0} uncommitted file(s)`);
  if (!s.hasEvidence) add(warnings, 'no-evidence', 'No PCAP or keylog was captured (run without --pcap)');
  // Expected on HTTP/2 and distributed captures, where the ClientHello never
  // reaches this pcap. Never an error.
  if (s.bindingStatus === 'unavailable') add(warnings, 'binding-unavailable', 'Keylog could not be bound to the PCAP (normal for h2/distributed)');
  if (s.pcapWithinRunWindow === false) add(warnings, 'pcap-window', 'PCAP timestamps fall outside the run window');
  if (!s.chainContinuous) add(warnings, 'chain-genesis', 'First receipt in this chain — no predecessor to link to');
  if (Number.isInteger(run.coveragePermille) && run.coveragePermille < 900) {
    add(warnings, 'low-coverage', `Only ${(run.coveragePermille / 10).toFixed(1)}% of requested scenarios executed`);
  }
  if (receipt.repo && receipt.repo.available === false) add(warnings, 'no-repo', 'Run was not inside a git repository');

  return {
    ok: errors.length === 0,
    receipt,
    keyId: envelope.keyId || null,
    signer: receipt.signer || null,
    signatureValid,
    signatureChecked,
    keyKnown,
    errors,
    warnings,
  };
}

// ── Chain ───────────────────────────────────────────────────────────
function chainNext(prevEnvelope) {
  if (!prevEnvelope) return { chainSeq: 0, prevReceiptHash: null };
  const prevSeq = prevEnvelope.receipt && prevEnvelope.receipt.chain
    ? prevEnvelope.receipt.chain.chainSeq : -1;
  return { chainSeq: (Number.isInteger(prevSeq) ? prevSeq : -1) + 1, prevReceiptHash: prevEnvelope.receiptHash };
}

// Walks a ledger and reports every break. Inserting or rewriting a past run
// cannot keep both the hash links and the sequence intact.
function verifyChain(envelopes) {
  const breaks = [];
  for (let i = 0; i < envelopes.length; i++) {
    const env = envelopes[i];
    const chain = (env.receipt && env.receipt.chain) || {};
    const prev = i > 0 ? envelopes[i - 1] : null;

    if (i === 0) {
      if (chain.prevReceiptHash) breaks.push({ index: i, reason: 'first entry claims a predecessor' });
    } else {
      if (chain.prevReceiptHash !== prev.receiptHash) {
        breaks.push({ index: i, reason: 'prevReceiptHash does not match the preceding entry' });
      }
      const prevSeq = (prev.receipt && prev.receipt.chain && prev.receipt.chain.chainSeq);
      if (Number.isInteger(prevSeq) && chain.chainSeq !== prevSeq + 1) {
        breaks.push({ index: i, reason: `chainSeq jumped from ${prevSeq} to ${chain.chainSeq}` });
      }
      const prevFinished = prev.receipt && prev.receipt.run && prev.receipt.run.finishedAt;
      const finished = env.receipt && env.receipt.run && env.receipt.run.finishedAt;
      if (Number.isInteger(prevFinished) && Number.isInteger(finished) && finished < prevFinished) {
        breaks.push({ index: i, reason: 'run finished before the preceding entry — backdated' });
      }
    }
  }
  return { ok: breaks.length === 0, breaks };
}

// ── Block encoding ──────────────────────────────────────────────────
function encodeBlock(envelope, { human = null } = {}) {
  const json = canonicalize(envelope);
  let payload;
  if (Buffer.byteLength(json, 'utf8') > GZIP_THRESHOLD) {
    payload = `${BLOCK_PREFIX_GZ}:${zlib.gzipSync(Buffer.from(json, 'utf8')).toString('base64url')}`;
  } else {
    payload = `${BLOCK_PREFIX}:${Buffer.from(json, 'utf8').toString('base64url')}`;
  }
  if (!human) return payload;
  return `${human}\n\n\`\`\`text\n${payload}\n\`\`\`\n<!-- /wirestrike-attestation -->`;
}

// Tolerates the block being quoted, indented, or buried in a longer comment.
// Takes the LAST match: edited PR comments accumulate old blocks above new.
function decodeBlock(text) {
  if (typeof text !== 'string') return null;
  const re = /(wsr1z?):([A-Za-z0-9_-]+={0,2})/g;
  let match = null, last = null;
  while ((match = re.exec(text)) !== null) last = match;
  if (!last) return null;
  try {
    const raw = Buffer.from(last[2], 'base64url');
    const json = last[1] === BLOCK_PREFIX_GZ ? zlib.gunzipSync(raw).toString('utf8') : raw.toString('utf8');
    return JSON.parse(json);
  } catch (_) {
    return null;
  }
}

// ── Key registry (.wirestrike/keys/*.pub) ───────────────────────────
function parseRegistryFile(text) {
  const out = { keyId: null, alg: null, email: null, name: null, addedAt: null, revokedAt: null, publicKeyPem: null };
  for (const line of String(text).split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const sp = t.indexOf(' ');
    if (sp < 0) continue;
    const key = t.slice(0, sp).trim();
    const val = t.slice(sp + 1).trim();
    if (key === 'pub') {
      out.publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${val}\n-----END PUBLIC KEY-----\n`;
    } else if (key in out) {
      out[key] = val;
    }
  }
  return out;
}

module.exports = {
  canonicalize,
  sha256Hex,
  preimage,
  receiptHashOf,
  keyIdFromPublicKey,
  buildReceipt,
  deriveSignals,
  signReceipt,
  verifyEnvelope,
  chainNext,
  verifyChain,
  encodeBlock,
  decodeBlock,
  parseRegistryFile,
  SCHEMA_VERSION,
  DOMAIN,
  BLOCK_PREFIX,
  BLOCK_PREFIX_GZ,
  GZIP_THRESHOLD,
};
