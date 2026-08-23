// Evidence collection for run attestation: everything that touches git, the
// filesystem, or the network lives here so lib/attestation.js can stay pure
// enough for a CI validator to vendor on its own.

const fs = require('fs');
const os = require('os');
const path = require('path');
const dns = require('dns');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { canonicalize, sha256Hex } = require('./attestation');
const { scenarioFingerprint } = require('./run-manifest');

// A single untracked file should never stall a run; hash at most this much.
const MAX_HASH_BYTES = 64 * 1024 * 1024;
const MAX_DIRTY_FILES = 100;
const MAX_PCAP_RECORDS = 2000000;

function git(args, cwd) {
  try {
    return execFileSync('git', args, {
      cwd, encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'],
    }).replace(/\n$/, '');
  } catch (_) {
    return null;
  }
}

// ── Tool ────────────────────────────────────────────────────────────

// Hash of the tool's own code, so a receipt records which build produced it.
// A modified tool yields a different codeDigest even at the same commit.
function toolCodeDigest(toolRoot) {
  const files = [];
  const walk = (dir, rel) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const abs = path.join(dir, e.name);
      const relPath = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(abs, relPath);
      else if (e.name.endsWith('.js')) files.push([relPath, hashFile(abs).sha256]);
    }
  };
  walk(path.join(toolRoot, 'lib'), 'lib');
  const cli = path.join(toolRoot, 'cli.js');
  if (fs.existsSync(cli)) files.push(['cli.js', hashFile(cli).sha256]);
  files.sort((a, b) => a[0].localeCompare(b[0]));
  return sha256Hex(canonicalize(files));
}

function collectToolInfo(toolRoot) {
  let version = null;
  try {
    version = JSON.parse(fs.readFileSync(path.join(toolRoot, 'package.json'), 'utf8')).version || null;
  } catch (_) {}
  return {
    name: 'wirestrike',
    version,
    commit: git(['rev-parse', 'HEAD'], toolRoot),
    codeDigest: toolCodeDigest(toolRoot),
    node: process.version,
    // OS family only — no hostname, no release string, nothing identifying.
    platform: process.platform,
    arch: process.arch,
  };
}

// ── Repo under test ─────────────────────────────────────────────────

function collectRepoInfo(cwd, { baseRef = null, maxDirtyFiles = MAX_DIRTY_FILES } = {}) {
  const headSha = git(['rev-parse', 'HEAD'], cwd);
  if (!headSha) return { available: false };

  // Root commit is stable across clones and remotes — a better repo identity
  // than the remote URL, which differs per fork and may embed credentials.
  const roots = git(['rev-list', '--max-parents=0', 'HEAD'], cwd);
  const rootCommit = roots ? roots.split('\n').pop().trim() : null;

  const branchRaw = git(['rev-parse', '--abbrev-ref', 'HEAD'], cwd);
  const detached = branchRaw === 'HEAD';
  const porcelain = git(['status', '--porcelain=v1'], cwd) || '';
  const entries = porcelain.split('\n').map((l) => l.trim()).filter(Boolean);

  const dirtyFiles = [];
  for (const line of entries.slice().sort()) {
    const status = line.slice(0, 2).trim();
    const rel = line.slice(2).trim().replace(/^"|"$/g, '');
    const abs = path.join(cwd, rel);
    let sha256 = null;
    try {
      if (fs.statSync(abs).isFile()) sha256 = hashFile(abs).sha256;
    } catch (_) {}
    dirtyFiles.push({ path: rel, status, sha256 });
  }

  // Digest covers ALL dirty files even when the listed array is truncated.
  const diff = git(['diff', 'HEAD'], cwd) || '';
  const dirtyDigest = entries.length
    ? sha256Hex(`${entries.sort().join('\n')}\n\0\0\n${diff}\n\0\0\n${canonicalize(dirtyFiles)}`)
    : null;

  return {
    available: true,
    repoId: rootCommit ? rootCommit.slice(0, 16) : 'unknown',
    headSha,
    tree: git(['rev-parse', 'HEAD^{tree}'], cwd),
    branch: detached ? null : branchRaw,
    detached,
    baseRef: baseRef || null,
    mergeBase: baseRef ? git(['merge-base', 'HEAD', baseRef], cwd) : null,
    dirty: entries.length > 0,
    dirtyDigest,
    dirtyFileCount: entries.length,
    dirtyFiles: dirtyFiles.slice(0, maxDirtyFiles),
    dirtyFilesTruncated: dirtyFiles.length > maxDirtyFiles,
  };
}

// ── Files ───────────────────────────────────────────────────────────

function hashFile(p) {
  try {
    const stat = fs.statSync(p);
    const h = crypto.createHash('sha256');
    const fd = fs.openSync(p, 'r');
    const buf = Buffer.alloc(1024 * 1024);
    let read = 0;
    try {
      for (;;) {
        const n = fs.readSync(fd, buf, 0, buf.length, null);
        if (n <= 0) break;
        h.update(buf.subarray(0, n));
        read += n;
        if (read >= MAX_HASH_BYTES) break;
      }
    } finally {
      fs.closeSync(fd);
    }
    return { sha256: h.digest('hex'), bytes: stat.size, hashedBytes: read };
  } catch (_) {
    return { sha256: null, bytes: 0, hashedBytes: 0 };
  }
}

// Classic libpcap: 24-byte global header, then 16-byte record headers.
// Hashing and walking happen in one pass over the same buffer.
function inspectPcap(p) {
  let buf;
  try { buf = fs.readFileSync(p); } catch (_) { return null; }
  if (buf.length < 24) return null;

  const magic = buf.readUInt32LE(0);
  const le = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  const be = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  if (!le && !be) return null;
  const u32 = (off) => (le ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  const nanos = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;

  let off = 24;
  let packets = 0;
  let first = null;
  let last = null;
  let truncated = false;
  while (off + 16 <= buf.length) {
    const tsSec = u32(off);
    const tsSub = u32(off + 4);
    const inclLen = u32(off + 8);
    const ms = tsSec * 1000 + Math.floor(tsSub / (nanos ? 1e6 : 1e3));
    if (first === null) first = ms;
    last = ms;
    packets++;
    off += 16 + inclLen;
    if (packets >= MAX_PCAP_RECORDS) { truncated = true; break; }
  }

  return {
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
    bytes: buf.length,
    packets,
    packetsTruncated: truncated,
    linkType: u32(20),
    firstPacketAtMs: first,
    lastPacketAtMs: last,
  };
}

// NSS key log. Field 2 is the client random on every label, TLS 1.2 and 1.3
// alike, which is what makes the pcap binding below possible.
function inspectKeylog(p) {
  let text;
  try { text = fs.readFileSync(p, 'utf8'); } catch (_) { return null; }
  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
  const labels = new Set();
  const randoms = new Set();
  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    labels.add(parts[0]);
    if (/^[0-9a-f]{64}$/i.test(parts[1])) randoms.add(parts[1].toLowerCase());
  }
  const { sha256, bytes } = hashFile(p);
  return {
    sha256, bytes, lines: lines.length,
    labels: [...labels].sort(),
    clientRandoms: [...randoms],
  };
}

// Does each client random from the keylog actually appear in the capture?
// Only the raw-socket paths write the ClientHello into the pcap, so h2 and
// distributed runs legitimately score zero — 'unavailable' is not a failure.
// Measured on this repo: dist-tls-avsb 159/159, dist-h2-wb 0/478.
function bindKeylogToPcap(keylogInfo, pcapPath) {
  if (!keylogInfo || !keylogInfo.clientRandoms || keylogInfo.clientRandoms.length === 0) return null;
  let buf;
  try { buf = fs.readFileSync(pcapPath); } catch (_) { return null; }

  let matched = 0;
  for (const r of keylogInfo.clientRandoms) {
    if (buf.includes(Buffer.from(r, 'hex'))) matched++;
  }
  const randoms = keylogInfo.clientRandoms.length;
  const status = matched === randoms ? 'verified' : matched > 0 ? 'partial' : 'unavailable';
  return { method: 'client-random-in-pcap', randoms, matched, status };
}

// ── Digests over the run itself ─────────────────────────────────────

function scenarioSetDigest(scenarios) {
  const pairs = (scenarios || [])
    .map((s) => [s.name, scenarioFingerprint(s)])
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  return { count: pairs.length, digest: sha256Hex(canonicalize(pairs)) };
}

// Deliberately excludes `response` and `description`: they carry
// target-specific strings that would make the digest unstable across two
// otherwise identical runs. Mirrors the whitelist used for run history.
function resultsDigest(results) {
  const rows = (results || []).map((r, i) => [
    r.scenario || '', r.status || '', r.verdict || '',
    r.finding ? r.finding.grade || '' : '', r.finding ? r.finding.severity || '' : '', i,
  ]);
  rows.sort((a, b) => (a[0] === b[0] ? a[5] - b[5] : String(a[0]).localeCompare(String(b[0]))));
  return sha256Hex(canonicalize(rows.map((r) => r.slice(0, 5))));
}

// ── Target ──────────────────────────────────────────────────────────

function isPrivateV4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n))) return false;
  return p[0] === 10
    || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
    || (p[0] === 192 && p[1] === 168)
    || (p[0] === 169 && p[1] === 254);
}

// Recorded instead of the address itself: a reviewer needs to know the target
// was loopback, not what the internal IP was.
function classifyAddressSync(host) {
  const h = String(host || '').toLowerCase();
  if (!h) return 'unresolved';
  if (h === 'localhost' || h === '::1' || /^127\./.test(h)) return 'loopback';
  if (/^[0-9.]+$/.test(h)) return isPrivateV4(h) ? 'private' : 'public';
  if (/^f[cd][0-9a-f]{2}:/.test(h)) return 'private';
  return 'unknown';
}

async function classifyAddress(host) {
  const direct = classifyAddressSync(host);
  if (direct !== 'unknown') return direct;
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve('unresolved'), 500);
    dns.lookup(host, (err, address) => {
      clearTimeout(timer);
      if (err || !address) return resolve('unresolved');
      resolve(classifyAddressSync(address));
    });
  });
}

// Peer certificate fingerprint and negotiated parameters, captured on the
// first successful handshake — evidence about *which* endpoint was tested.
function collectDutIdentity(client) {
  const d = client && client._dutIdentity;
  if (!d) return null;
  return {
    certSha256: d.certSha256 || null,
    tlsVersion: d.tlsVersion || null,
    cipher: d.cipher || null,
    alpn: d.alpn || null,
  };
}

module.exports = {
  git, collectToolInfo, toolCodeDigest, collectRepoInfo,
  hashFile, inspectPcap, inspectKeylog, bindKeylogToPcap,
  scenarioSetDigest, resultsDigest,
  classifyAddress, classifyAddressSync, collectDutIdentity,
  MAX_DIRTY_FILES, MAX_HASH_BYTES,
};
