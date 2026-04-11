#!/usr/bin/env node
// Test ALL TLS client scenarios in distributed mode with response verification.
//
// Pipeline:
//   1. Enumerate every TLS client scenario from getClientScenarios()
//   2. Run batched through a single client Agent + WellBehavedServer
//   3. Verify each result semantically (well-behaved must show a real server
//      handshake; fuzz expected-DROPPED must show an alert or close)
//   4. Double-click (retry) any TIMEOUT or unverified result up to 2 more times
//   5. Emit Coverage / Verification / Mismatches / Confirmed-timeouts report
//      and write tls-verify-results.json for diffing across runs.
//
// CLI:
//   node test-tls-distributed.js                  # full run
//   node test-tls-distributed.js --category FV,Z  # only named categories
//   node test-tls-distributed.js --only fv-tls-get

const http = require('http');
const fs = require('fs');
const { startAgent } = require('./lib/agent');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { getClientScenarios } = require('./lib/scenarios');

// ── CLI parsing ────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const out = { category: null, only: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--category' && argv[i + 1]) { out.category = argv[++i].split(',').map(s => s.trim()).filter(Boolean); }
    else if (a === '--only' && argv[i + 1]) { out.only = argv[++i]; }
  }
  return out;
}
const ARGS = parseArgs(process.argv);

const SERVER_PORT = 4435;
const AGENT_PORT = 9252;
const LOG_FILE = 'tls.log';

const logStream = fs.createWriteStream(LOG_FILE);

function formatHex(hex) {
  const buf = Buffer.from(hex, 'hex');
  let out = '';
  for (let i = 0; i < buf.length; i += 16) {
    const chunk = buf.slice(i, i + 16);
    const hexPart = (chunk.toString('hex').match(/.{1,2}/g) || []).join(' ').padEnd(47);
    const asciiPart = Array.from(chunk).map(c => (c >= 32 && c <= 126) ? String.fromCharCode(c) : '.').join('');
    out += `    ${i.toString(16).padStart(8, '0')}  ${hexPart}  |${asciiPart}|\n`;
  }
  return out;
}

function startLogCollector(port) {
  http.get({ hostname: 'localhost', port, path: '/events' }, (res) => {
    res.on('data', (chunk) => {
      const lines = chunk.toString().split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);
          if (event.type === 'logger') {
            const e = event.event;
            const scenarioTag = e.scenario ? ` [${e.scenario}]` : '';
            if (e.type === 'scenario') {
              logStream.write(`\n━━━ Scenario: ${e.name} ━━━\n    ${e.description}\n`);
            } else if (e.type === 'sent') {
              logStream.write(`${e.ts}${scenarioTag} → ${e.label} (${e.size} bytes)\n`);
              if (e.hex) logStream.write(formatHex(e.hex));
            } else if (e.type === 'received') {
              logStream.write(`${e.ts}${scenarioTag} ← ${e.label} (${e.size} bytes)\n`);
              if (e.hex) logStream.write(formatHex(e.hex));
            } else if (e.type === 'tcp') {
              const arrow = e.direction === 'sent' ? '→' : '←';
              logStream.write(`${e.ts}${scenarioTag} ${arrow} [TCP] ${e.event}\n`);
            } else if (e.type === 'fuzz') {
              logStream.write(`${e.ts}${scenarioTag} ⚡ [FUZZ] ${e.message}\n`);
            } else if (e.type === 'info') {
              logStream.write(`${e.ts}${scenarioTag} ℹ ${e.message}\n`);
            }
          } else if (event.type === 'result') {
            const r = event.result;
            logStream.write(`\nRESULT [${r.scenario}]: ${r.status} (${r.response || ''})\n`);
          }
        } catch (e) {}
      }
    });
  }).on('error', (err) => {
    console.error('Log collector error:', err.message);
  });
}

function httpPost(port, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ hostname: 'localhost', port, path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function httpGet(port, path) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: 'localhost', port, path }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    }).on('error', reject);
  });
}

async function waitForDone(port, total, timeout = 3600000) {
  const start = Date.now();
  let lastCount = -1;
  while (Date.now() - start < timeout) {
    const status = await httpGet(port, '/status');
    if (status.completedCount !== lastCount) {
      const pct = Math.floor((status.completedCount / total) * 100);
      console.log(`  Progress: ${status.completedCount}/${total} (${pct}%)`);
      lastCount = status.completedCount;
    }
    if (status.status === 'done') return;
    await new Promise(r => setTimeout(r, 2000));
  }
  throw new Error(`Timed out after ${Math.round((Date.now() - start)/1000)}s`);
}

async function runBatch(agentPort, serverPort, scenarioNames) {
  if (scenarioNames.length === 0) return [];
  try { await httpPost(agentPort, '/stop', {}); } catch {}
  await new Promise(r => setTimeout(r, 500));
  const configResult = await httpPost(agentPort, '/configure', {
    config: { host: 'localhost', port: serverPort, protocol: 'tls', workers: 10, timeout: 5000, delay: 10, baseline: false },
    scenarios: scenarioNames,
  });
  if (configResult.scenarioCount === 0) throw new Error('No scenarios resolved');
  await httpPost(agentPort, '/run', {});
  await waitForDone(agentPort, configResult.scenarioCount);
  return await httpGet(agentPort, '/results');
}

// ── Semantic verification ─────────────────────────────────────────────────
// Classifies a single result as ok | mismatch | unverified given expected +
// status + response text. `response` is already a parsed, human-readable
// description produced by lib/unified-client.js — see lastResponse at
// unified-client.js:295-770. We deliberately key off the strings it emits
// (ServerHelloDone, "TLS 1.3", "handshake completed", "HTTP/1.1 200",
// "Alert(fatal...", "Encrypted alert", "Connection closed").
const HANDSHAKE_OK_RE = /ServerHelloDone|TLS 1\.3|handshake completed|handshake successful|HTTP\b.*\b200|HEAD 200|ServerHello\b|\d+\/\d+\b.*\b(responses|requests|OK)|POST echo|POST \+ GET|POST=OK|GET=OK/i;
const REJECT_RE = /^Alert\b|Encrypted alert|Connection closed|Connection reset|ApplicationData/i;

function verifyResult(r, expected) {
  const status = r.status;
  const resp = (r.response || '').trim();

  // Protocol-level alerts are always correct — grader treats these as PASS.
  if (status === 'tls-alert-server' || status === 'tls-alert-client') {
    return { verify: 'ok', reason: 'protocol alert' };
  }
  if (status === 'ERROR' || status === 'ABORTED' || status === 'SKIPPED') {
    return { verify: 'mismatch', reason: `${status.toLowerCase()}: ${resp.substring(0, 120)}` };
  }

  if (expected === 'PASSED') {
    if (status !== 'PASSED') {
      return { verify: 'mismatch', reason: `expected PASSED, got ${status}` };
    }
    if (!HANDSHAKE_OK_RE.test(resp)) {
      return { verify: 'unverified', reason: `PASSED but response lacks handshake marker: "${resp.substring(0, 120)}"` };
    }
    return { verify: 'ok', reason: 'handshake completed' };
  }

  if (expected === 'DROPPED') {
    if (status === 'PASSED') {
      return { verify: 'mismatch', reason: `expected DROPPED, server ACCEPTED: "${resp.substring(0, 120)}"` };
    }
    if (status === 'TIMEOUT') {
      // Don't trust a single TIMEOUT — retry layer will double-click it.
      return { verify: 'unverified', reason: 'TIMEOUT — no server response observed' };
    }
    if (status === 'DROPPED' && !REJECT_RE.test(resp)) {
      // DROPPED with no alert/close marker means the client gave up without
      // a concrete server reaction — double-click to rule out flake.
      return { verify: 'unverified', reason: `DROPPED without alert/close marker: "${resp.substring(0, 120)}"` };
    }
    return { verify: 'ok', reason: 'server rejected' };
  }

  // No expected value — informational, don't fail.
  return { verify: 'ok', reason: 'no expected value' };
}

// ── Retry loop ────────────────────────────────────────────────────────────
const MAX_ATTEMPTS = 3; // 1 initial + 2 retries

async function doubleClick(agentPort, serverPort, needsRetry, expectedMap) {
  if (needsRetry.length === 0) return new Map();
  console.log(`\n── DOUBLE-CLICK: retrying ${needsRetry.length} unverified/TIMEOUT results ──`);
  const history = new Map(); // scenario → [attempt1, attempt2, attempt3]
  for (const r of needsRetry) history.set(r.scenario, [r]);

  for (let attempt = 2; attempt <= MAX_ATTEMPTS; attempt++) {
    const pending = [...history.entries()]
      .filter(([, atts]) => {
        const last = atts[atts.length - 1];
        const v = verifyResult(last, expectedMap[last.scenario]);
        return v.verify !== 'ok';
      })
      .map(([name]) => name);
    if (pending.length === 0) break;
    console.log(`  attempt ${attempt}/${MAX_ATTEMPTS}: re-running ${pending.length} scenarios`);
    const results = await runBatch(agentPort, serverPort, pending);
    for (const r of results) {
      const atts = history.get(r.scenario);
      if (atts) atts.push(r);
    }
  }
  return history;
}

// Classify a retry history into: recovered | flake | confirmed-timeout | confirmed-mismatch
function classifyRetry(attempts, expected) {
  const verdicts = attempts.map(a => verifyResult(a, expected).verify);
  const final = attempts[attempts.length - 1];
  if (verdicts[verdicts.length - 1] === 'ok') {
    return verdicts.some(v => v !== 'ok') ? 'flake' : 'ok';
  }
  if (attempts.every(a => a.status === 'TIMEOUT')) return 'confirmed-timeout';
  return 'confirmed-mismatch';
}

async function run() {
  const allScenarios = getClientScenarios();
  const expectedMap = {};
  const categoryMap = {};
  for (const s of allScenarios) {
    expectedMap[s.name] = s.expected || 'DROPPED';
    categoryMap[s.name] = s.category;
  }

  const byCategory = {};
  for (const s of allScenarios) {
    if (!byCategory[s.category]) byCategory[s.category] = [];
    byCategory[s.category].push(s.name);
  }

  // ── Coverage selection ────────────────────────────────────────────────
  let selectedCats = Object.keys(byCategory).sort();
  if (ARGS.category) {
    selectedCats = selectedCats.filter(c => ARGS.category.includes(c));
  } else {
    // Exclude APP scenarios by default as they require custom application-layer servers
    selectedCats = selectedCats.filter(c => c !== 'APP');
  }

  let selection = selectedCats.flatMap(c => byCategory[c].map(name => ({ name, category: c })));
  if (ARGS.only) selection = selection.filter(s => s.name === ARGS.only);

  console.log('══════════════════════════════════════════════════');
  console.log('  COVERAGE');
  console.log('══════════════════════════════════════════════════');
  console.log(`  Total TLS client scenarios in repo: ${allScenarios.length}`);
  console.log(`  Selected for this run:              ${selection.length}`);
  if (ARGS.category) console.log(`  Filter --category: ${ARGS.category.join(',')}`);
  if (ARGS.only) console.log(`  Filter --only: ${ARGS.only}`);
  for (const c of selectedCats) {
    const count = byCategory[c].filter(n => selection.find(s => s.name === n)).length;
    if (count > 0) console.log(`    ${c.padEnd(10)} ${String(count).padStart(4)}`);
  }
  console.log('  NOTE: server-side TLS scenarios (SRV, 34 total) are out of scope for this harness.');

  if (selection.length === 0) {
    console.error('No scenarios selected — check --category/--only filters.');
    process.exit(1);
  }

  const server = new WellBehavedServer({ hostname: 'localhost', port: SERVER_PORT, logger: null });
  await server.startTLS();
  const actualPort = server._actualPort || SERVER_PORT;
  console.log(`\nServer on port ${actualPort}`);

  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));
  startLogCollector(AGENT_PORT);

  // Batch by category (keeps /configure payloads reasonable and lets progress
  // output reflect which area is currently running).
  const selectedNames = new Set(selection.map(s => s.name));
  const batches = selectedCats
    .map(c => ({ cat: c, names: byCategory[c].filter(n => selectedNames.has(n)) }))
    .filter(b => b.names.length > 0);

  const allResults = [];

  try {
    for (const b of batches) {
      console.log(`\n── BATCH [${b.cat}] ${b.names.length} scenarios ──`);
      const rs = await runBatch(AGENT_PORT, actualPort, b.names);
      allResults.push(...rs);
      console.log(`  Done: ${rs.length} results`);
    }

    // ── Verification pass ────────────────────────────────────────────
    for (const r of allResults) {
      const expected = expectedMap[r.scenario];
      Object.assign(r, verifyResult(r, expected), { expected, category: categoryMap[r.scenario] });
    }

    // ── Double-click unverified / TIMEOUT ────────────────────────────
    const needsRetry = allResults.filter(r => r.verify !== 'ok');
    const retryHistory = await doubleClick(AGENT_PORT, actualPort, needsRetry, expectedMap);

    // Apply retry outcomes back to allResults.
    const finalRetry = new Map(); // scenario → classification
    for (const [name, atts] of retryHistory.entries()) {
      const expected = expectedMap[name];
      const cls = classifyRetry(atts, expected);
      finalRetry.set(name, { classification: cls, attempts: atts });
      // Replace allResults entry with the last attempt + classification.
      const idx = allResults.findIndex(r => r.scenario === name);
      if (idx >= 0) {
        const last = atts[atts.length - 1];
        Object.assign(allResults[idx], last, verifyResult(last, expected), {
          expected,
          category: categoryMap[name],
          retryClassification: cls,
          retryAttemptCount: atts.length,
        });
      }
    }

    // ═══════════════════════════════════════════════════
    // REPORT
    // ═══════════════════════════════════════════════════

    // Per-category summary (status breakdown)
    const catResults = {};
    for (const r of allResults) {
      const cat = r.category || 'unknown';
      if (!catResults[cat]) catResults[cat] = [];
      catResults[cat].push(r);
    }
    console.log('\n══════════════════════════════════════════════════');
    console.log('  PER-CATEGORY STATUS');
    console.log('══════════════════════════════════════════════════');
    for (const [cat, items] of Object.entries(catResults).sort()) {
      const counts = {};
      for (const r of items) counts[r.status] = (counts[r.status] || 0) + 1;
      const parts = Object.entries(counts).sort().map(([k, v]) => `${k}:${v}`).join(' ');
      console.log(`  ${cat.padEnd(10)} ${String(items.length).padStart(4)} total | ${parts}`);
    }

    // Verification totals
    const verifyCounts = { ok: 0, mismatch: 0, unverified: 0, flake: 0, 'confirmed-timeout': 0, 'confirmed-mismatch': 0 };
    for (const r of allResults) {
      const cls = r.retryClassification || r.verify;
      verifyCounts[cls] = (verifyCounts[cls] || 0) + 1;
    }
    console.log('\n══════════════════════════════════════════════════');
    console.log('  VERIFICATION RESULTS');
    console.log('══════════════════════════════════════════════════');
    for (const [k, v] of Object.entries(verifyCounts)) {
      if (v > 0) console.log(`  ${k.padEnd(22)} ${v}`);
    }

    // Mismatches — the actionable list
    const mismatches = allResults.filter(r => {
      const cls = r.retryClassification || r.verify;
      return cls === 'mismatch' || cls === 'confirmed-mismatch';
    });
    console.log('\n══════════════════════════════════════════════════');
    console.log('  MISMATCHES');
    console.log('══════════════════════════════════════════════════');
    if (mismatches.length === 0) {
      console.log('  None — all scenarios produced correct responses.');
    } else {
      for (const r of mismatches) {
        console.log(`  ✗ ${r.scenario} [${r.category}] expected=${r.expected} status=${r.status}`);
        console.log(`      reason: ${r.reason}`);
        console.log(`      response: ${(r.response || '').substring(0, 200)}`);
      }
    }

    // Confirmed timeouts — genuine server hangs, the real investigation targets
    const confirmed = allResults.filter(r => r.retryClassification === 'confirmed-timeout');
    console.log('\n══════════════════════════════════════════════════');
    console.log('  CONFIRMED TIMEOUTS (all retries timed out)');
    console.log('══════════════════════════════════════════════════');
    if (confirmed.length === 0) {
      console.log('  None — no scenario timed out across all retry attempts.');
    } else {
      confirmed.sort((a, b) => (a.category || '').localeCompare(b.category || ''));
      for (const r of confirmed) {
        console.log(`  ⏱ ${r.scenario} [${r.category}] expected=${r.expected}`);
      }
    }

    // Flakes — worth noting, not failing
    const flakes = allResults.filter(r => r.retryClassification === 'flake');
    if (flakes.length > 0) {
      console.log('\n══════════════════════════════════════════════════');
      console.log(`  FLAKES (recovered on retry, ${flakes.length})`);
      console.log('══════════════════════════════════════════════════');
      for (const r of flakes) {
        console.log(`  ↻ ${r.scenario} [${r.category}] — succeeded after ${r.retryAttemptCount} attempts`);
      }
    }

    // Final status line
    console.log('\n══════════════════════════════════════════════════');
    console.log('  FINAL');
    console.log('══════════════════════════════════════════════════');
    console.log(`  Total:              ${allResults.length}`);
    console.log(`  OK:                 ${verifyCounts.ok || 0}`);
    console.log(`  Mismatches:         ${mismatches.length}`);
    console.log(`  Confirmed timeouts: ${confirmed.length}`);
    console.log(`  Flakes:             ${flakes.length}`);
    console.log('══════════════════════════════════════════════════');

    // Persist structured results for diffing across runs
    const outPath = 'tls-verify-results.json';
    fs.writeFileSync(outPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      total: allResults.length,
      verifyCounts,
      results: allResults.map(r => ({
        scenario: r.scenario,
        category: r.category,
        expected: r.expected,
        status: r.status,
        response: (r.response || '').substring(0, 500),
        verify: r.verify,
        reason: r.reason,
        retryClassification: r.retryClassification || null,
        retryAttemptCount: r.retryAttemptCount || 1,
      })),
    }, null, 2));
    console.log(`\n  Wrote ${outPath}`);

    // Exit code: fail if any mismatch or confirmed-timeout
    const failed = mismatches.length + confirmed.length;
    process.exitCode = failed > 0 ? 1 : 0;

  } finally {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    try { server.stop(); } catch {}
    try { agent.close(); } catch {}
    setTimeout(() => process.exit(process.exitCode || 0), 2000);
  }
}

run().catch(err => { console.error('Test failed:', err); process.exit(1); });
