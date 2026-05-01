// Run manifest — a checked-in record of what was run, where, against what,
// and from which code. Written once per run by the controller. A failure in a
// downstream report can be rewound to the exact git SHA, scenario versions,
// agent versions and target configuration that produced it.
//
// Design goals:
//   * Reproducible — contains git SHA, dirty flag, seed, and a content
//     fingerprint for every scenario. If the manifest matches, the run
//     is byte-for-byte reproducible.
//   * Stable across runs — fingerprints are derived from scenario bodies
//     (actions function source), not from object identity, so re-running
//     the same code yields the same fingerprint.
//   * Offline-safe — gitInfo degrades to nulls if git isn't available.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

function gitInfo() {
  const run = (cmd) => {
    try {
      return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch (_) { return null; }
  };
  const sha = run('git rev-parse HEAD');
  if (!sha) return { sha: null, dirty: null, branch: null };
  const dirty = run('git status --porcelain');
  const branch = run('git rev-parse --abbrev-ref HEAD');
  return { sha, branch, dirty: dirty ? dirty.length > 0 : null };
}

// Deterministic 16-hex fingerprint of a scenario's observable behavior:
// name, description, side, and the stringified action-producing functions.
// Two scenarios that produce the same bytes on the wire yield the same
// fingerprint; edits to the actions function change the fingerprint.
function scenarioFingerprint(scenario) {
  if (!scenario || !scenario.name) return null;
  const h = crypto.createHash('sha256');
  const parts = [
    scenario.name || '',
    scenario.description || '',
    scenario.side || '',
    scenario.category || '',
    typeof scenario.clientActions === 'function' ? scenario.clientActions.toString() : String(scenario.clientActions || ''),
    typeof scenario.serverActions === 'function' ? scenario.serverActions.toString() : String(scenario.serverActions || ''),
    typeof scenario.actions === 'function' ? scenario.actions.toString() : String(scenario.actions || ''),
  ];
  h.update(parts.join('\x00'));
  return h.digest('hex').slice(0, 16);
}

// Write a manifest to disk. `data` fields:
//   runId        — string (caller-supplied, otherwise a UUID is generated)
//   seed         — optional RNG seed
//   config       — single config object; kept for back-compat. In distributed
//                  mode this is the client config (or server, if no client).
//                  Use `configByRole` to recover the full picture.
//   configByRole — { client?, server? } — per-role configs. Distributed runs
//                  legitimately differ on bindAddress/host/port/traceDir, so
//                  collapsing them loses information needed to replay.
//   agents       — [{ role, host, port, version, platform, nodeVersion, ... }]
//   scenarios    — [{ name, category, fingerprint, role }]
//   dut          — { host, port, banner?, fingerprint? }
function writeManifest(outPath, data = {}) {
  // Bump the schema only when a downstream consumer needs to know that the
  // per-role split exists. v1 readers will still see `config` populated.
  const manifest = {
    schemaVersion: 2,
    runId: data.runId || crypto.randomUUID(),
    startedAt: data.startedAt || new Date().toISOString(),
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    git: gitInfo(),
    seed: data.seed === undefined ? null : data.seed,
    config: data.config || null,
    configByRole: data.configByRole || null,
    agents: data.agents || [],
    scenarios: data.scenarios || [],
    dut: data.dut || null,
  };
  try { fs.mkdirSync(path.dirname(outPath), { recursive: true }); } catch (_) {}
  fs.writeFileSync(outPath, JSON.stringify(manifest, null, 2));
  return manifest;
}

module.exports = { gitInfo, scenarioFingerprint, writeManifest };
