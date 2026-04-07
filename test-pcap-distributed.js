#!/usr/bin/env node
// Run a PCAP-ingested scenario in distributed mode.
//
// This script:
//   1. Reads a PCAP file and generates a TLS session recreation scenario
//   2. Serializes the scenario (client + server actions) into JSON
//   3. Pushes the serialized scenario to both client and server agents
//   4. Runs the test using stepped orchestration (server starts first, then client)
//   5. Collects and displays results from both sides
//
// Usage:
//   node test-pcap-distributed.js <pcap-file> [options]
//
// Options:
//   --pcap-stream <index>   Select a specific stream from the PCAP (default: 0)
//   --list-streams          List all streams found in the PCAP and exit
//   --client-host <host>    Client agent host (default: localhost)
//   --client-port <port>    Client agent control port (default: 9200)
//   --server-host <host>    Server agent host (default: localhost)
//   --server-port <port>    Server agent control port (default: 9201)
//   --target-host <host>    Target host for the TLS connection (default: from PCAP SNI)
//   --target-port <port>    Target port for the TLS connection (default: 443)
//   --timeout <ms>          Connection timeout (default: 10000)
//
// Examples:
//   # List streams in a PCAP
//   node test-pcap-distributed.js capture.pcap --list-streams
//
//   # Run stream 0 against local agents
//   node test-pcap-distributed.js capture.pcap
//
//   # Run against remote agents
//   node test-pcap-distributed.js capture.pcap \
//     --client-host 10.0.0.1 --client-port 9200 \
//     --server-host 10.0.0.2 --server-port 9201 \
//     --target-host example.com --target-port 443

const http = require('http');
const path = require('path');
const {
  parsePcapToScenario,
  readPcap,
  groupStreams,
  analyzeStream,
  serializePcapScenario,
} = require('./lib/pcap-parser');

// ─── Argument Parsing ──────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      if (key === 'list-streams') {
        args[key] = true;
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        args[key] = argv[++i];
      } else {
        args[key] = true;
      }
    } else {
      args._.push(argv[i]);
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const pcapFile = args._[0];

if (!pcapFile) {
  console.error('Usage: node test-pcap-distributed.js <pcap-file> [options]');
  console.error('  Use --list-streams to see available streams');
  process.exit(1);
}

const CLIENT_HOST = args['client-host'] || 'localhost';
const CLIENT_PORT = parseInt(args['client-port'] || 9200);
const SERVER_HOST = args['server-host'] || 'localhost';
const SERVER_PORT = parseInt(args['server-port'] || 9201);
const TARGET_PORT = parseInt(args['target-port'] || 443);
const TIMEOUT = parseInt(args.timeout || 10000);
const STREAM_INDEX = parseInt(args['pcap-stream'] || 0);

// ─── HTTP Helpers ──────────────────────────────────────────────────────────

function httpRequest(host, port, method, urlPath, body, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: host, port, path: urlPath, method, timeout,
      headers: { 'Content-Type': 'application/json' },
    };
    if (payload) opts.headers['Content-Length'] = Buffer.byteLength(payload);

    const req = http.request(opts, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => {
        try { resolve(JSON.parse(buf)); } catch { resolve(buf); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error(`Request timed out: ${method} ${urlPath}`)); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function httpPost(host, port, urlPath, body) {
  return httpRequest(host, port, 'POST', urlPath, body);
}

function httpGet(host, port, urlPath) {
  return httpRequest(host, port, 'GET', urlPath, null);
}

// ─── Event Stream Collector ────────────────────────────────────────────────

function startEventCollector(host, port, role) {
  http.get({ hostname: host, port, path: '/events' }, (res) => {
    res.on('data', (chunk) => {
      const lines = chunk.toString().split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);
          if (event.type === 'logger' && event.event) {
            const e = event.event;
            if (e.type === 'scenario') {
              console.log(`  [${role}] ━━━ ${e.name}: ${e.description}`);
            } else if (e.type === 'sent') {
              console.log(`  [${role}] → SENT ${e.label || ''} (${e.size || 0}B)`);
            } else if (e.type === 'received') {
              console.log(`  [${role}] ← RECV ${e.label || ''} (${e.size || 0}B)`);
            } else if (e.type === 'info') {
              console.log(`  [${role}] ℹ ${e.message}`);
            } else if (e.type === 'error') {
              console.log(`  [${role}] ✗ ${e.message}`);
            }
          } else if (event.type === 'result') {
            const r = event.result;
            console.log(`  [${role}] RESULT: ${r.scenario} → ${r.status} (${r.response || ''})`);
          }
        } catch (_) {}
      }
    });
  }).on('error', () => {});
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function run() {
  // ── Step 1: Read and analyze PCAP ──────────────────────────────────────
  console.log(`\n  PCAP Distributed Test`);
  console.log(`  ═══════════════════════════════════════════════\n`);

  const packets = readPcap(pcapFile);
  const streams = groupStreams(packets);

  if (streams.length === 0) {
    console.error('No data streams found in PCAP');
    process.exit(1);
  }

  // List streams mode
  if (args['list-streams']) {
    const natCount = streams.filter(s => s.natMerged).length;
    console.log(`  Streams in ${pcapFile}: (${streams.length} streams${natCount > 0 ? `, ${natCount} NAT-merged` : ''})\n`);
    streams.forEach((s, idx) => {
      const analysis = analyzeStream(s);
      const tag = analysis.natMerged ? '\x1b[33m' : '';
      const reset = analysis.natMerged ? '\x1b[0m' : '';
      console.log(`    ${tag}[${idx}]${reset} ${analysis.description}`);
    });
    if (natCount > 0) {
      console.log(`\n  \x1b[33mNote:\x1b[0m ${natCount} stream(s) auto-merged from NAT-split captures.`);
    }
    process.exit(0);
  }

  // ── Step 2: Generate scenario from PCAP ────────────────────────────────
  console.log(`  PCAP file:    ${pcapFile}`);
  console.log(`  Stream index: ${STREAM_INDEX}`);

  const scenario = parsePcapToScenario(pcapFile, STREAM_INDEX);
  const targetHost = args['target-host'] || scenario.pcapParams?.clientParams?.hostname || 'localhost';

  console.log(`  Scenario:     ${scenario.name}`);
  console.log(`  Description:  ${scenario.description}`);
  console.log(`  Protocol:     ${scenario.protocol}`);
  console.log(`  Target:       ${targetHost}:${TARGET_PORT}`);
  console.log(`  Explanation:  ${scenario.explanation}`);

  // Show handshake analysis if available
  if (scenario.pcapParams?.handshakeAnalysis) {
    console.log(`\n  Handshake Analysis:`);
    for (const entry of scenario.pcapParams.handshakeAnalysis) {
      const dir = entry.dir === 'c2s' ? '→' : '←';
      let detail = entry.msg;
      if (entry.version) detail += ` (${entry.version})`;
      if (entry.sni) detail += ` SNI=${entry.sni}`;
      if (entry.selectedCipher) detail += ` cipher=${entry.selectedCipher}`;
      if (entry.certCount) detail += ` certs=${entry.certCount}`;
      if (entry.level) detail += ` ${entry.level}: ${entry.descName}`;
      console.log(`    ${dir} ${detail}`);
    }
  }

  // ── Step 3: Serialize scenario ─────────────────────────────────────────
  console.log(`\n  Serializing scenario for distributed mode...`);
  const serialized = serializePcapScenario(scenario, { hostname: targetHost });

  const clientPayload = JSON.stringify(serialized.clientActions);
  const serverPayload = JSON.stringify(serialized.serverActions);
  console.log(`  Client actions: ${serialized.clientActions.length} (${(clientPayload.length / 1024).toFixed(1)} KB)`);
  console.log(`  Server actions: ${serialized.serverActions.length} (${(serverPayload.length / 1024).toFixed(1)} KB)`);

  // ── Step 4: Connect to agents ──────────────────────────────────────────
  console.log(`\n  Connecting to agents...`);
  console.log(`  Client agent: ${CLIENT_HOST}:${CLIENT_PORT}`);
  console.log(`  Server agent: ${SERVER_HOST}:${SERVER_PORT}`);

  let clientStatus, serverStatus;
  try {
    clientStatus = await httpGet(CLIENT_HOST, CLIENT_PORT, '/status');
    console.log(`  Client agent: ${clientStatus.role} (${clientStatus.status})`);
  } catch (e) {
    console.error(`  ✗ Cannot reach client agent at ${CLIENT_HOST}:${CLIENT_PORT}: ${e.message}`);
    process.exit(1);
  }

  try {
    serverStatus = await httpGet(SERVER_HOST, SERVER_PORT, '/status');
    console.log(`  Server agent: ${serverStatus.role} (${serverStatus.status})`);
  } catch (e) {
    console.error(`  ✗ Cannot reach server agent at ${SERVER_HOST}:${SERVER_PORT}: ${e.message}`);
    process.exit(1);
  }

  // ── Step 5: Stop any running tests ─────────────────────────────────────
  try { await httpPost(CLIENT_HOST, CLIENT_PORT, '/stop', {}); } catch (_) {}
  try { await httpPost(SERVER_HOST, SERVER_PORT, '/stop', {}); } catch (_) {}
  await new Promise(r => setTimeout(r, 500));

  // ── Step 6: Configure both agents with the serialized scenario ─────────
  console.log(`\n  Configuring agents...`);

  // Server agent: receives the scenario with serverActions as the primary actions
  const serverScenario = {
    ...serialized,
    // For the server agent, swap: serverActions become the primary actions
    // and clientActions become serverActions (the server needs to know what
    // the client will send to coordinate timing)
    name: serialized.name + '-server',
    side: 'server',
  };

  const serverConfigResult = await httpPost(SERVER_HOST, SERVER_PORT, '/configure', {
    config: {
      host: targetHost,
      port: TARGET_PORT,
      hostname: targetHost,
      protocol: serialized.protocol || 'tls',
      workers: 1,
      timeout: TIMEOUT,
      delay: 100,
      baseline: false,
    },
    scenarios: [],
    pcapScenarios: [serverScenario],
  });
  console.log(`  Server configured: ${serverConfigResult.scenarioCount} scenario(s)`);

  // Client agent: receives the scenario with clientActions as the primary actions
  const clientScenario = {
    ...serialized,
    name: serialized.name + '-client',
    side: 'client',
  };

  const clientConfigResult = await httpPost(CLIENT_HOST, CLIENT_PORT, '/configure', {
    config: {
      host: targetHost,
      port: TARGET_PORT,
      protocol: serialized.protocol || 'tls',
      workers: 1,
      timeout: TIMEOUT,
      delay: 100,
      baseline: false,
    },
    scenarios: [],
    pcapScenarios: [clientScenario],
  });
  console.log(`  Client configured: ${clientConfigResult.scenarioCount} scenario(s)`);

  // ── Step 7: Start event collectors ─────────────────────────────────────
  startEventCollector(CLIENT_HOST, CLIENT_PORT, 'CLIENT');
  startEventCollector(SERVER_HOST, SERVER_PORT, 'SERVER');

  // ── Step 8: Run in stepped mode ────────────────────────────────────────
  console.log(`\n  Running scenario...`);
  console.log(`  ───────────────────────────────────────────────`);

  // Start server first
  const serverRunPromise = httpPost(SERVER_HOST, SERVER_PORT, '/run-scenario', { index: 0 })
    .catch(err => ({ error: err.message, role: 'server' }));

  // Small delay to let server start listening
  await new Promise(r => setTimeout(r, 500));

  // Then start client
  const clientRunPromise = httpPost(CLIENT_HOST, CLIENT_PORT, '/run-scenario', { index: 0 })
    .catch(err => ({ error: err.message, role: 'client' }));

  // Wait for both to complete
  const [serverResult, clientResult] = await Promise.all([serverRunPromise, clientRunPromise]);

  console.log(`  ───────────────────────────────────────────────`);

  // ── Step 9: Signal finish ──────────────────────────────────────────────
  try { await httpPost(SERVER_HOST, SERVER_PORT, '/finish', {}); } catch (_) {}
  try { await httpPost(CLIENT_HOST, CLIENT_PORT, '/finish', {}); } catch (_) {}

  // ── Step 10: Collect and display results ───────────────────────────────
  await new Promise(r => setTimeout(r, 1000));

  let clientResults = [];
  let serverResults = [];
  try { clientResults = await httpGet(CLIENT_HOST, CLIENT_PORT, '/results'); } catch (_) {}
  try { serverResults = await httpGet(SERVER_HOST, SERVER_PORT, '/results'); } catch (_) {}

  console.log(`\n  ═══════════════════════════════════════════════`);
  console.log(`  PCAP DISTRIBUTED TEST RESULTS`);
  console.log(`  ═══════════════════════════════════════════════`);
  console.log(`  PCAP:         ${pcapFile}`);
  console.log(`  Stream:       ${STREAM_INDEX}`);
  console.log(`  Target:       ${targetHost}:${TARGET_PORT}`);
  console.log(`  Scenario:     ${scenario.name}`);

  if (scenario.pcapParams?.natMerged) {
    console.log(`  NAT:          Detected and merged`);
    if (scenario.pcapParams.natDetails) {
      console.log(`                ${scenario.pcapParams.natDetails.clientEndpoint} ↔ ${scenario.pcapParams.natDetails.natClientEndpoint}`);
    }
  }

  console.log(`\n  Client Results (${clientResults.length}):`);
  for (const r of clientResults) {
    console.log(`    ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status}`);
    if (r.response) console.log(`      ${r.response.substring(0, 200)}`);
  }

  console.log(`\n  Server Results (${serverResults.length}):`);
  for (const r of serverResults) {
    console.log(`    ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status}`);
    if (r.response) console.log(`      ${r.response.substring(0, 200)}`);
  }

  // Check for errors in the run responses
  if (clientResult.error) console.log(`\n  Client error: ${clientResult.error}`);
  if (serverResult.error) console.log(`\n  Server error: ${serverResult.error}`);

  const allPassed = clientResults.every(r => r.status === 'PASSED') &&
                    serverResults.every(r => r.status === 'PASSED');

  console.log(`\n  Overall: ${allPassed ? '✓ PASSED' : '✗ FAILED'}`);
  console.log(`  ═══════════════════════════════════════════════\n`);

  // Cleanup
  try { await httpPost(CLIENT_HOST, CLIENT_PORT, '/stop', {}); } catch (_) {}
  try { await httpPost(SERVER_HOST, SERVER_PORT, '/stop', {}); } catch (_) {}

  setTimeout(() => process.exit(allPassed ? 0 : 1), 1000);
}

run().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
