#!/usr/bin/env node
// Compare per-scenario TLS verdicts between the Node well-behaved counterpart
// and an OpenSSL counterpart, in distributed mode.
//
//   client-side (Core + SCAN): the fuzzer (client agent) runs each scenario
//     against (a) the Node WellBehavedServer.startTLS() and (b) an OpenSSL echo
//     server (socat OPENSSL-LISTEN → Node HTTP echo backend). Same fuzzing
//     client, only the well-behaved SERVER changes.
//
//   server-side (SRV): the fuzzer (server agent) runs each fuzzed server
//     scenario; the connecting well-behaved CLIENT is (a) Node WellBehavedClient
//     and (b) `openssl s_client`. Same fuzzing server, only the peer changes.
//
// The per-scenario verdict/status is produced by UnifiedClient/UnifiedServer
// unchanged — we only swap the counterpart — so any difference is attributable
// to Node-vs-OpenSSL. Writes tls-openssl-vs-node.json and tls-openssl-vs-node.md.
//
// Every scenario is driven individually via /run-scenario with a wall-clock cap
// so a pathological scenario (e.g. alert floods that keep a socket busy past the
// idle timeout) is recorded as STALLED and skipped instead of blocking the run.
//
// Usage:
//   node run-tls-openssl-compare.js [--side client|server|both]
//                                   [--category A,F,SCAN] [--limit N] [--cap MS]

const http = require('http');
const fs = require('fs');
const path = require('path');
const { startAgent } = require('./lib/agent');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { WellBehavedClient } = require('./lib/well-behaved-client');
const { getClientScenarios, getServerScenarios } = require('./lib/scenarios');
const { startOpenSSLEchoServer, startOpenSSLClient } = require('./lib/openssl-peer');

// In-process agents mean a stray socket 'error' would otherwise be fatal to the
// whole run. Swallow them — each scenario's verdict is captured per /run-scenario.
process.on('uncaughtException', (e) => { console.error('[guard] uncaughtException:', (e && e.message) || e); });
process.on('unhandledRejection', (e) => { console.error('[guard] unhandledRejection:', (e && (e.message || e)) || e); });

// The agent's /run path is strictly sequential (workers are hardcoded to 1), so
// we parallelize at the process level: SHARDS independent in-process agents +
// target servers run concurrently, each driving a slice of the scenarios.
const SHARDS = 5;
const CLIENT_AGENT_BASE = 9300; // client agents: 9300..9300+SHARDS-1
const SERVER_AGENT_BASE = 9400; // server agents: 9400..9400+SHARDS-1
const SERVER_BIND_BASE = 4460;  // fuzzed-server bind ports: 4460,4462,... (gap of 2/shard)

const CLIENT_CATEGORIES = ['A', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'X', 'SCAN'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A scenario exercises post-quantum key exchange when its name references a PQC
// group/KEM. The OpenSSL peer must opt in to PQC groups (`-groups`) for these, or
// it never offers them and the comparison can't exercise real PQC negotiation.
const isPqcScenario = (name) => /pqc|mlkem|kyber|frodo|mceliece|sntrup|bikel/i.test(name || '');

function parseArgs(argv) {
  const out = { side: 'both', category: null, limit: 0, cap: 10000 };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--side' && argv[i + 1]) out.side = argv[++i];
    else if (argv[i] === '--category' && argv[i + 1]) out.category = argv[++i].split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
    else if (argv[i] === '--limit' && argv[i + 1]) out.limit = parseInt(argv[++i], 10) || 0;
    else if (argv[i] === '--cap' && argv[i + 1]) out.cap = parseInt(argv[++i], 10) || 15000;
  }
  return out;
}
const ARGS = parseArgs(process.argv);

// Scenario metadata (category + expected) for STALLED/missing rows.
const META = new Map();
for (const s of getClientScenarios()) META.set(s.name, { category: s.category, expected: s.expected });
for (const s of getServerScenarios()) if (!META.has(s.name)) META.set(s.name, { category: s.category, expected: s.expected });
const metaOf = (name) => META.get(name) || { category: '?', expected: null };

// ── HTTP helpers ────────────────────────────────────────────────────────────
function httpPost(port, p, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ hostname: 'localhost', port, path: p, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      let buf = '';
      res.on('data', (d) => (buf += d));
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}
function httpGet(port, p) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: 'localhost', port, path: p }, (res) => {
      let buf = '';
      res.on('data', (d) => (buf += d));
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    }).on('error', reject);
  });
}
async function waitForReady(port, timeout = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try { const r = await httpGet(port, '/ready'); if (r && r.ready) return true; } catch (_) {}
    await sleep(50);
  }
  return false; // proceed anyway; the run-scenario promise still resolves
}
// Reject after `ms`, but keep the underlying promise's rejection from leaking.
function withCap(promise, ms) {
  promise.catch(() => {});
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`capped after ${ms}ms`)), ms);
    promise.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

// ── Agent configuration ─────────────────────────────────────────────────────
function configureAgent(role, agentPort, names, targetPort) {
  // Same timeout both passes so the Node-vs-OpenSSL comparison is fair; 2.5s is
  // enough for a real handshake while keeping DROPPED-expected scenarios (which
  // wait out the timeout) from dominating runtime.
  const config = role === 'server'
    ? { bindAddress: '0.0.0.0', hostname: 'localhost', port: targetPort, protocol: 'tls', workers: 1, timeout: 2500, delay: 5, baseline: false }
    : { host: 'localhost', port: targetPort, protocol: 'tls', workers: 1, timeout: 2500, delay: 5, baseline: false };
  return httpPost(agentPort, '/configure', { config, scenarios: names });
}

function splitInto(arr, k) {
  const shards = Array.from({ length: k }, () => []);
  arr.forEach((x, i) => shards[i % k].push(x));
  return shards.filter((s) => s.length > 0);
}

// ── Per-scenario driver (one fuzzed scenario + its counterpart peer) ─────────
async function driveOne({ role, agentPort, name, idx, peerKind, targetPort }) {
  const runPromise = httpPost(agentPort, '/run-scenario', { pairId: `cmp-${idx}`, scenarioName: name });
  if (role !== 'server') return runPromise; // client agent connects to the target itself

  await waitForReady(agentPort);
  let peer;
  if (peerKind === 'node') {
    peer = new WellBehavedClient({ host: 'localhost', port: targetPort });
    peer.connectTLS().catch(() => {});
  } else {
    peer = startOpenSSLClient({ port: targetPort, pqc: isPqcScenario(name) });
  }
  try {
    const resp = await runPromise;
    // Attach a translated reason from the OpenSSL peer's stderr so the report can
    // explain *why* the handshake was dropped instead of leaving the raw stack.
    if (peerKind === 'openssl' && peer.reason && resp && resp.result) {
      await sleep(60); // let s_client flush its diagnostics before we read them
      const reason = peer.reason();
      if (reason && !resp.result.peerReason) resp.result.peerReason = reason;
    }
    return resp;
  } finally { try { peer.stop(); } catch (_) {} }
}

// Drive every scenario one-at-a-time with a wall-clock cap; recover from a stall
// by stopping + re-arming the agent and moving on.
async function steppedPass({ role, agentPort, names, peerKind, targetPort, label }) {
  const results = [];
  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    let resp;
    try {
      resp = await withCap(driveOne({ role, agentPort, name, idx: i, peerKind, targetPort }), ARGS.cap);
    } catch (capErr) {
      const m = metaOf(name);
      results.push({ scenario: name, category: m.category, expected: m.expected, status: 'STALLED', verdict: 'N/A', response: capErr.message });
      try { await httpPost(agentPort, '/stop', {}); } catch (_) {}
      await sleep(300);
      try { await configureAgent(role, agentPort, names, targetPort); } catch (_) {}
      console.log(`    [${label}] STALLED on ${name} — recovered, continuing`);
      continue;
    }
    const m = metaOf(name);
    const r = resp && resp.result ? resp.result : { scenario: name, status: 'NO_RESULT', expected: m.expected, verdict: 'N/A', response: '' };
    if (!r.scenario) r.scenario = name;
    if (!r.category) r.category = m.category;
    results.push(r);
    if ((i + 1) % 25 === 0 || i + 1 === names.length) console.log(`    [${label}] ${i + 1}/${names.length}`);
  }
  return results;
}

// ── Client-side comparison (sharded) ────────────────────────────────────────
async function runOneClientShard(shardNames, peerKind, idx) {
  const agentPort = CLIENT_AGENT_BASE + idx;
  const agent = startAgent('client', { controlPort: agentPort });
  await sleep(800);
  let target = null;
  let targetPort = null;
  try {
    if (peerKind === 'node') {
      target = new WellBehavedServer({ hostname: 'localhost', port: 0, logger: null });
      await target.startTLS();
      targetPort = target.actualPort;
    } else {
      target = await startOpenSSLEchoServer({});
      targetPort = target.port;
    }
    await configureAgent('client', agentPort, shardNames, targetPort);
    return await steppedPass({ role: 'client', agentPort, names: shardNames, peerKind, targetPort, label: `c${idx}-${peerKind}` });
  } finally {
    try { await httpPost(agentPort, '/stop', {}); } catch (_) {}
    try { if (target) target.stop(); } catch (_) {}
    try { agent.close(); } catch (_) {}
  }
}

async function runClientPass(shards, peerKind) {
  const arrays = await Promise.all(shards.map((s, i) => runOneClientShard(s, peerKind, i)));
  return arrays.flat();
}

async function runClientSide(names) {
  console.log(`\n=== CLIENT-SIDE: ${names.length} scenarios across ${Math.min(SHARDS, names.length)} shards ===`);
  const shards = splitInto(names, SHARDS);
  console.log('  [node] WellBehavedServer (Node TLS) pass…');
  const nodeResults = await runClientPass(shards, 'node');
  await sleep(400);
  console.log('  [openssl] socat/OpenSSL echo server pass…');
  const opensslResults = await runClientPass(shards, 'openssl');
  return { nodeResults, opensslResults };
}

// ── Server-side comparison (sharded) ────────────────────────────────────────
async function runOneServerShard(shardNames, peerKind, idx) {
  const agentPort = SERVER_AGENT_BASE + idx;
  const bindPort = SERVER_BIND_BASE + idx * 2;
  const agent = startAgent('server', { controlPort: agentPort });
  await sleep(800);
  try {
    await configureAgent('server', agentPort, shardNames, bindPort);
    return await steppedPass({ role: 'server', agentPort, names: shardNames, peerKind, targetPort: bindPort, label: `s${idx}-${peerKind}` });
  } finally {
    try { await httpPost(agentPort, '/stop', {}); } catch (_) {}
    try { agent.close(); } catch (_) {}
  }
}

async function runServerPass(shards, peerKind) {
  const arrays = await Promise.all(shards.map((s, i) => runOneServerShard(s, peerKind, i)));
  return arrays.flat();
}

async function runServerSide(names) {
  console.log(`\n=== SERVER-SIDE: ${names.length} scenarios across ${Math.min(SHARDS, names.length)} shards ===`);
  const shards = splitInto(names, SHARDS);
  console.log('  [node] Node WellBehavedClient peer pass…');
  const nodeResults = await runServerPass(shards, 'node');
  await sleep(800);
  console.log('  [openssl] openssl s_client peer pass…');
  const opensslResults = await runServerPass(shards, 'openssl');
  return { nodeResults, opensslResults };
}

// ── Diff + report ───────────────────────────────────────────────────────────
function indexByName(results) {
  const m = new Map();
  for (const r of results) m.set(r.scenario, r);
  return m;
}

function buildRows(side, nodeResults, opensslResults) {
  const nm = indexByName(nodeResults);
  const om = indexByName(opensslResults);
  const names = new Set([...nm.keys(), ...om.keys()]);
  const rows = [];
  for (const name of names) {
    const n = nm.get(name);
    const o = om.get(name);
    const m = metaOf(name);
    const row = {
      side,
      scenario: name,
      category: (n && n.category) || (o && o.category) || m.category,
      expected: (n && n.expected) || (o && o.expected) || m.expected || null,
      nodeStatus: n ? n.status : 'MISSING',
      nodeVerdict: n ? n.verdict : 'MISSING',
      opensslStatus: o ? o.status : 'MISSING',
      opensslVerdict: o ? o.verdict : 'MISSING',
      opensslReason: (o && o.peerReason) || '',
    };
    if (row.nodeVerdict !== row.opensslVerdict) row.classification = 'verdict-diverged';
    else if (row.nodeStatus !== row.opensslStatus) row.classification = 'status-diverged';
    else row.classification = 'match';
    rows.push(row);
  }
  rows.sort((a, b) => (a.category + a.scenario).localeCompare(b.category + b.scenario));
  return rows;
}

function summarize(rows) {
  const counts = { match: 0, 'status-diverged': 0, 'verdict-diverged': 0 };
  const byCat = {};
  for (const r of rows) {
    counts[r.classification] = (counts[r.classification] || 0) + 1;
    if (!byCat[r.category]) byCat[r.category] = { total: 0, match: 0, statusDiverged: 0, verdictDiverged: 0 };
    byCat[r.category].total++;
    if (r.classification === 'match') byCat[r.category].match++;
    else if (r.classification === 'status-diverged') byCat[r.category].statusDiverged++;
    else byCat[r.category].verdictDiverged++;
  }
  return { counts, byCat };
}

function writeReport(allRows) {
  const { counts, byCat } = summarize(allRows);
  const total = allRows.length;
  const diverged = allRows.filter((r) => r.classification !== 'match');

  const json = {
    timestamp: new Date().toISOString(),
    total,
    verdictMatch: counts.match,
    statusDiverged: counts['status-diverged'],
    verdictDiverged: counts['verdict-diverged'],
    byCategory: byCat,
    rows: allRows,
  };
  fs.writeFileSync(path.resolve('tls-openssl-vs-node.json'), JSON.stringify(json, null, 2));

  let md = `# TLS verdicts: Node well-behaved counterpart vs OpenSSL counterpart\n\n`;
  md += `Generated: ${json.timestamp}\n\n`;
  md += `- **Total scenarios compared:** ${total}\n`;
  md += `- **Verdict matches (same verdict AND status):** ${counts.match} (${total ? ((counts.match / total) * 100).toFixed(1) : 0}%)\n`;
  md += `- **Status-diverged (same verdict, different status):** ${counts['status-diverged']}\n`;
  md += `- **Verdict-diverged:** ${counts['verdict-diverged']}\n\n`;

  md += `## Per-category match rate\n\n`;
  md += `| Category | Total | Match | Status-diverged | Verdict-diverged |\n|---|---|---|---|---|\n`;
  for (const cat of Object.keys(byCat).sort()) {
    const c = byCat[cat];
    md += `| ${cat} | ${c.total} | ${c.match} | ${c.statusDiverged} | ${c.verdictDiverged} |\n`;
  }

  md += `\n## Diverged scenarios (${diverged.length})\n\n`;
  if (diverged.length === 0) {
    md += `_None — every in-scope scenario produced the same verdict and status against both counterparts._\n`;
  } else {
    md += `| Scenario | Cat | Expected | Node status / verdict | OpenSSL status / verdict | OpenSSL peer reason | Class |\n|---|---|---|---|---|---|---|\n`;
    for (const r of diverged) {
      md += `| ${r.scenario} | ${r.category} | ${r.expected || ''} | ${r.nodeStatus} / ${r.nodeVerdict} | ${r.opensslStatus} / ${r.opensslVerdict} | ${r.opensslReason || ''} | ${r.classification} |\n`;
    }
  }
  fs.writeFileSync(path.resolve('tls-openssl-vs-node.md'), md);

  return { counts, total, diverged };
}

// ── Main ────────────────────────────────────────────────────────────────────
async function main() {
  const cats = ARGS.category || CLIENT_CATEGORIES;
  const allClient = getClientScenarios();
  let clientNames = allClient.filter((s) => cats.includes(s.category)).map((s) => s.name);
  let serverNames = getServerScenarios().map((s) => s.name);
  if (ARGS.limit > 0) {
    clientNames = clientNames.slice(0, ARGS.limit);
    serverNames = serverNames.slice(0, ARGS.limit);
  }

  console.log('TLS Node-vs-OpenSSL counterpart verdict comparison');
  console.log(`  side=${ARGS.side}  categories=${cats.join(',')}  limit=${ARGS.limit || 'none'}  cap=${ARGS.cap}ms`);

  const allRows = [];
  if (ARGS.side === 'client' || ARGS.side === 'both') {
    const { nodeResults, opensslResults } = await runClientSide(clientNames);
    allRows.push(...buildRows('client', nodeResults, opensslResults));
  }
  if (ARGS.side === 'server' || ARGS.side === 'both') {
    const { nodeResults, opensslResults } = await runServerSide(serverNames);
    allRows.push(...buildRows('server', nodeResults, opensslResults));
  }

  const { counts, total, diverged } = writeReport(allRows);
  console.log('\n════════════════════ SUMMARY ════════════════════');
  console.log(`  Total compared : ${total}`);
  console.log(`  Verdict match  : ${counts.match} (${total ? ((counts.match / total) * 100).toFixed(1) : 0}%)`);
  console.log(`  Status-diverged: ${counts['status-diverged']}`);
  console.log(`  Verdict-diverged: ${counts['verdict-diverged']}`);
  console.log(`  Report: tls-openssl-vs-node.md / .json`);
  if (diverged.length) {
    console.log(`\n  First diverged scenarios:`);
    for (const r of diverged.slice(0, 15)) {
      const why = r.opensslReason ? ` — ${r.opensslReason}` : '';
      console.log(`    [${r.category}] ${r.scenario}: node=${r.nodeStatus}/${r.nodeVerdict} openssl=${r.opensslStatus}/${r.opensslVerdict} (${r.classification})${why}`);
    }
  }
}

main()
  .then(() => { setTimeout(() => process.exit(0), 500); })
  .catch((err) => { console.error('Comparison failed:', err); process.exit(1); });
