#!/usr/bin/env node
// Run the TLS AV (FW — firewall / EICAR / malware) and Sandbox (SB) client
// scenarios in distributed mode and capture every packet to a single merged
// PCAP for manual Wireshark verification.
//
// Mirrors run-quic-fw-sb-distributed.js: a client Agent drives the fuzzer
// against an in-process well-behaved TLS echo server. Setting `pcapFile` in the
// agent config makes lib/unified-client.js write a merged PCAP plus a companion
// NSS keylog (.keylog) next to it so Wireshark can decrypt the TLS records.
//
// Usage:
//   node run-tls-fw-sb-distributed.js [--pcap <file>] [--only FW|SB]

const http = require('http');
const path = require('path');
const { startAgent } = require('./lib/agent');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { getClientScenarios } = require('./lib/scenarios');

const SERVER_PORT = 4438;
const AGENT_PORT = 9258;

function parseArgs(argv) {
  const out = { pcap: null, only: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--pcap' && argv[i + 1]) out.pcap = argv[++i];
    else if (argv[i] === '--only' && argv[i + 1]) out.only = argv[++i].toUpperCase();
  }
  return out;
}
const ARGS = parseArgs(process.argv);
const PCAP_FILE = path.resolve(ARGS.pcap || 'dist-tls-avsb.pcap');

function httpPost(port, p, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ hostname: 'localhost', port, path: p, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
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
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    }).on('error', reject);
  });
}

async function waitForDone(port, total, timeout = 1800000) {
  const start = Date.now();
  let lastPct = -1;
  while (Date.now() - start < timeout) {
    const status = await httpGet(port, '/status');
    const pct = Math.floor((status.completedCount / total) * 100);
    if (pct !== lastPct && (pct % 10 === 0 || status.status === 'done')) {
      console.log(`  Progress: ${status.completedCount}/${total} (${pct}%)`);
      lastPct = pct;
    }
    if (status.status === 'done') return;
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`Timed out after ${Math.round((Date.now() - start) / 1000)}s`);
}

async function run() {
  const all = getClientScenarios();
  let cats = ['FW', 'SB'];
  if (ARGS.only) cats = cats.filter(c => c === ARGS.only);

  const names = all.filter(s => cats.includes(s.category)).map(s => s.name);
  const fwCount = all.filter(s => s.category === 'FW').length;
  const sbCount = all.filter(s => s.category === 'SB').length;
  console.log(`TLS AV/Sandbox distributed run`);
  console.log(`  Categories: ${cats.join(', ')}  (FW/AV=${fwCount}, SB=${sbCount})`);
  console.log(`  Scenarios:  ${names.length}`);
  console.log(`  PCAP:       ${PCAP_FILE}`);

  const server = new WellBehavedServer({ hostname: 'localhost', port: SERVER_PORT, logger: null });
  await server.startTLS();
  const actualPort = server.actualPort || SERVER_PORT;
  console.log(`  Echo server: TLS on port ${actualPort}\n`);

  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  let results = [];
  try {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    await new Promise(r => setTimeout(r, 300));

    const cfg = await httpPost(AGENT_PORT, '/configure', {
      config: {
        host: 'localhost',
        port: actualPort,
        protocol: 'tls',
        workers: 1,            // sequential → clean, ordered streams in the merged PCAP
        timeout: 5000,
        delay: 10,
        baseline: false,
        pcapFile: PCAP_FILE,   // enables merged PCAP + companion .keylog
        mergePcap: true,
      },
      scenarios: names,
    });
    if (!cfg.scenarioCount) throw new Error('No scenarios resolved');

    await httpPost(AGENT_PORT, '/run', {});
    await waitForDone(AGENT_PORT, cfg.scenarioCount);
    results = await httpGet(AGENT_PORT, '/results');

    const byStatus = {};
    for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    console.log('\n══ RESULTS ══');
    console.log(`  Total: ${results.length}`);
    for (const [st, n] of Object.entries(byStatus)) console.log(`    ${st}: ${n}`);
  } finally {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    await new Promise(r => setTimeout(r, 500)); // let PCAP flush/close
    try { server.stop(); } catch {}
    try { agent.close(); } catch {}
  }

  return results.length;
}

run()
  .then(() => { setTimeout(() => process.exit(0), 500); })
  .catch(err => { console.error('Run failed:', err); process.exit(1); });
