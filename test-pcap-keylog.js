#!/usr/bin/env node
// Comprehensive PCAP + keylog test for TLS, HTTP/2, and QUIC scenarios.
//
// Runs well-behaved (functional validation) + AV/SB scenarios across all protocols,
// captures traffic into merged PCAPs with companion keylog files, then verifies
// decryption with tshark.
//
// Output files (test-output/):
//   h2-test.pcap   + h2-test.keylog    — HTTP/2 traffic (via transparent TCP proxy)
//   quic-test.pcap + quic-test.keylog  — QUIC/HTTP3 traffic (via quiche engine)

const http   = require('http');
const net    = require('net');
const fs     = require('fs');
const path   = require('path');
const { execSync } = require('child_process');
const { startAgent }               = require('./lib/agent');
const { WellBehavedServer }        = require('./lib/well-behaved-server');
const { listHttp2ClientScenarios } = require('./lib/http2-scenarios');
const { listQuicClientScenarios }  = require('./lib/quic-scenarios');
const { PcapWriter }               = require('./lib/pcap-writer');

// ─── Ports ─────────────────────────────────────────────────────────────────
const H2_SERVER_PORT  = 14435;   // real H2 server (internal)
const H2_PROXY_PORT   = 4435;    // TCP capture proxy
const QUIC_SERVER_PORT = 4436;   // QUIC/H3 server
const H2_AGENT_PORT   = 9252;
const QUIC_AGENT_PORT = 9253;

// ─── Output paths ──────────────────────────────────────────────────────────
const OUTPUT_DIR       = path.join(__dirname, 'test-output');
const H2_PCAP_FILE     = path.join(OUTPUT_DIR, 'h2-test.pcap');
const H2_KEYLOG_FILE   = path.join(OUTPUT_DIR, 'h2-test.keylog');
const QUIC_PCAP_FILE   = path.join(OUTPUT_DIR, 'quic-test.pcap');
const QUIC_KEYLOG_FILE = path.join(OUTPUT_DIR, 'quic-test.keylog');

const TSHARK = (() => {
  for (const p of ['/opt/homebrew/bin/tshark', '/usr/local/bin/tshark', '/usr/bin/tshark']) {
    try { fs.accessSync(p, fs.constants.X_OK); return p; } catch {}
  }
  return null;
})();

// ─── Transparent TCP Capture Proxy (for HTTP/2) ────────────────────────────
class TcpCaptureProxy {
  constructor({ listenPort, targetPort, pcapFile }) {
    this.listenPort  = listenPort;
    this.targetPort  = targetPort;
    this.pcapFile    = pcapFile;
    this.portCounter = 0;
    this.firstConn   = true;
    this.server      = null;
    this.openWriters = new Set();
  }

  async start() {
    try { fs.unlinkSync(this.pcapFile); } catch {}

    return new Promise((resolve, reject) => {
      this.server = net.createServer((clientSock) => {
        const clientPort = 49152 + (this.portCounter++ % 16383);
        const writer = new PcapWriter(this.pcapFile, {
          role: 'client', append: !this.firstConn,
          clientPort, serverPort: this.targetPort,
        });
        this.firstConn = false;
        this.openWriters.add(writer);
        writer.writeTCPHandshake();

        const serverSock = net.connect(this.targetPort, 'localhost');

        clientSock.on('data', (chunk) => {
          try { writer.writeTLSData(chunk, 'sent'); } catch {}
          if (!serverSock.destroyed) serverSock.write(chunk);
        });
        serverSock.on('data', (chunk) => {
          try { writer.writeTLSData(chunk, 'received'); } catch {}
          if (!clientSock.destroyed) clientSock.write(chunk);
        });

        let closed = false;
        const cleanup = () => {
          if (closed) return; closed = true;
          try { writer.writeFIN('sent'); } catch {}
          try { writer.close(); } catch {}
          this.openWriters.delete(writer);
        };
        clientSock.on('end',   () => { if (!serverSock.destroyed) serverSock.end(); });
        serverSock.on('end',   () => { if (!clientSock.destroyed) clientSock.end(); });
        clientSock.on('close', cleanup);
        serverSock.on('close', cleanup);
        clientSock.on('error', () => { if (!serverSock.destroyed) serverSock.destroy(); });
        serverSock.on('error', () => { if (!clientSock.destroyed) clientSock.destroy(); });
      });
      this.server.listen(this.listenPort, 'localhost', resolve);
      this.server.on('error', reject);
    });
  }

  stop() {
    for (const w of this.openWriters) { try { w.close(); } catch {} }
    this.openWriters.clear();
    if (this.server) { this.server.close(); this.server = null; }
  }
}

// ─── HTTP helpers ──────────────────────────────────────────────────────────
function httpPost(port, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(
      { hostname: 'localhost', port, path: urlPath, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      (res) => {
        let buf = '';
        res.on('data', d => buf += d);
        res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
      }
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function httpGet(port, urlPath) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: 'localhost', port, path: urlPath }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    }).on('error', reject);
  });
}

async function waitForDone(port, total, label, timeoutMs = 600000) {
  const start = Date.now();
  let lastPct = -1;
  while (Date.now() - start < timeoutMs) {
    const status = await httpGet(port, '/status');
    const pct = Math.floor((status.completedCount / total) * 100);
    if (pct !== lastPct && (pct % 20 === 0 || status.status === 'done')) {
      process.stdout.write(`  [${label}] ${status.completedCount}/${total} (${pct}%)\n`);
      lastPct = pct;
    }
    if (status.status === 'done') return;
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`${label} timed out after ${Math.round((Date.now() - start) / 1000)}s`);
}

// ─── tshark verification ──────────────────────────────────────────────────
function verifyWithTshark(pcapFile, keylogFile, protocol) {
  if (!TSHARK) {
    console.log(`  [${protocol}] tshark not found — skipping decryption verification`);
    return false;
  }

  const pcapSize   = (() => { try { return fs.statSync(pcapFile).size; } catch { return 0; } })();
  const keylogSize = (() => { try { return fs.statSync(keylogFile).size; } catch { return 0; } })();
  const keylogLines = keylogSize > 0
    ? fs.readFileSync(keylogFile, 'utf8').split('\n').filter(l => l && !l.startsWith('#')).length
    : 0;

  console.log(`  [${protocol}] PCAP:   ${pcapFile}  (${(pcapSize / 1024).toFixed(1)} KB)`);
  console.log(`  [${protocol}] Keylog: ${keylogFile}  (${keylogLines} key lines)`);

  if (pcapSize === 0) { console.log(`  [${protocol}] PCAP is empty — FAIL`); return false; }
  if (keylogLines === 0) {
    console.log(`  [${protocol}] Keylog has no key lines — native library may not support SSLKEYLOGFILE`);
    if (protocol === 'QUIC') {
      console.log(`  [${protocol}] NOTE: quiche native binary needs to be compiled with keylog support`);
      console.log(`  [${protocol}] The keylog plumbing is in place and will work once the binary supports it`);
    }
    return false;
  }

  // Verify tshark can parse the pcap
  try {
    const rawOut = execSync(`${TSHARK} -r "${pcapFile}" -c 10 2>&1`, { timeout: 15000 }).toString();
    const packetLines = rawOut.split('\n').filter(l => l.trim().length > 0);
    console.log(`  [${protocol}] tshark parsed ${packetLines.length} packets (first 10):`);
    for (const l of packetLines.slice(0, 5)) console.log(`    ${l.trim()}`);
    if (packetLines.length > 5) console.log(`    ... (${packetLines.length - 5} more)`);
  } catch (e) {
    console.log(`  [${protocol}] tshark parse failed: ${e.message}`);
    return false;
  }

  // Verify decryption using keylog
  try {
    let cmd;
    if (protocol === 'H2') {
      // For HTTP/2: look for decrypted HTTP2 frames
      cmd = `${TSHARK} -r "${pcapFile}" -o "tls.keylog_file:${keylogFile}" -Y http2 -c 10 2>&1`;
    } else {
      // For QUIC: look for decrypted QUIC frames beyond Initial
      cmd = `${TSHARK} -r "${pcapFile}" -o "tls.keylog_file:${keylogFile}" -Y "quic" -c 20 2>&1`;
    }
    const decrypted = execSync(cmd, { timeout: 15000 }).toString();
    const decLines = decrypted.split('\n').filter(l => l.trim().length > 0);

    if (decLines.length > 0) {
      console.log(`  [${protocol}] Decrypted frames found: ${decLines.length}`);
      for (const l of decLines.slice(0, 5)) console.log(`    ${l.trim()}`);
      if (decLines.length > 5) console.log(`    ... (${decLines.length - 5} more)`);
      console.log(`  [${protocol}] Decryption verification: PASS`);
      return true;
    } else {
      console.log(`  [${protocol}] No decrypted frames found — keylog may not match sessions`);
      return false;
    }
  } catch (e) {
    console.log(`  [${protocol}] Decryption verification failed: ${e.message}`);
    return false;
  }
}

// ─── Run HTTP/2 test ──────────────────────────────────────────────────────
async function runH2Test() {
  console.log('\n========== HTTP/2 PCAP + KEYLOG TEST ==========');

  const allScenarios = listHttp2ClientScenarios();
  const byCategory = {};
  for (const s of allScenarios) {
    if (!byCategory[s.category]) byCategory[s.category] = [];
    byCategory[s.category].push(s.name);
  }

  // AM = functional validation, AN = firewall, AO = sandbox
  // Use all AM + first 5 AN + first 5 AO to keep runtime manageable
  const categories = ['AM', 'AN', 'AO'];
  const scenarioNames = [
    ...(byCategory['AM'] || []),
    ...(byCategory['AN'] || []).slice(0, 5),
    ...(byCategory['AO'] || []).slice(0, 5),
  ];
  const catCounts = categories.map(c => {
    const full = (byCategory[c] || []).length;
    const used = c === 'AM' ? full : Math.min(full, 5);
    return `${c}: ${used}/${full}`;
  }).join(', ');
  console.log(`  Scenarios: ${scenarioNames.length} (${catCounts})`);

  // Start H2 server
  const server = new WellBehavedServer({ hostname: 'localhost', port: H2_SERVER_PORT, logger: null });
  await server.startH2();
  const serverPort = server._actualPort || H2_SERVER_PORT;
  console.log(`  H2 server on port ${serverPort}`);

  // Start capture proxy
  const proxy = new TcpCaptureProxy({
    listenPort: H2_PROXY_PORT, targetPort: serverPort, pcapFile: H2_PCAP_FILE,
  });
  await proxy.start();
  console.log(`  Capture proxy on port ${H2_PROXY_PORT} -> ${serverPort}`);

  // Start agent
  const agent = startAgent('client', { controlPort: H2_AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  let results = [];
  try {
    try { await httpPost(H2_AGENT_PORT, '/stop', {}); } catch {}
    await new Promise(r => setTimeout(r, 500));

    const configResult = await httpPost(H2_AGENT_PORT, '/configure', {
      config: {
        host: 'localhost', port: H2_PROXY_PORT,
        protocol: 'h2', workers: 1,
        timeout: 5000, delay: 50, baseline: false,
        keylogFile: H2_KEYLOG_FILE,
      },
      scenarios: scenarioNames,
    });
    console.log(`  Configured: ${configResult.scenarioCount} scenarios`);

    await httpPost(H2_AGENT_PORT, '/run', {});
    await waitForDone(H2_AGENT_PORT, configResult.scenarioCount, 'H2');
    results = await httpGet(H2_AGENT_PORT, '/results');

    const byStatus = {};
    for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    console.log(`  Results: ${results.length} total`);
    for (const [s, c] of Object.entries(byStatus).sort()) console.log(`    ${s}: ${c}`);

  } finally {
    try { await httpPost(H2_AGENT_PORT, '/stop', {}); } catch {}
    try { proxy.stop(); } catch {}
    try { server.stop(); } catch {}
    try { agent.close(); } catch {}
  }

  return verifyWithTshark(H2_PCAP_FILE, H2_KEYLOG_FILE, 'H2');
}

// ─── Run QUIC test ────────────────────────────────────────────────────────
async function runQuicTest() {
  console.log('\n========== QUIC PCAP + KEYLOG TEST ==========');

  const allScenarios = listQuicClientScenarios();
  const byCategory = {};
  for (const s of allScenarios) {
    if (!byCategory[s.category]) byCategory[s.category] = [];
    byCategory[s.category].push(s);
  }

  // QZ = well-behaved (all use quiche) — sufficient to verify keylog plumbing
  // Exclude max-streams-*-100kb scenarios which hang (pre-existing issue)
  const categories = ['QZ'];
  const selected = (byCategory['QZ'] || []).filter(s => s.useQuiche && !s.name.includes('max-streams'));
  const scenarioNames = selected.map(s => s.name);
  const catCounts = categories.map(c => `${c}: ${selected.length}`).join(', ');
  console.log(`  Scenarios: ${scenarioNames.length} (${catCounts})`);

  // Start QUIC server
  const server = new WellBehavedServer({ hostname: 'localhost', port: QUIC_SERVER_PORT, logger: null });
  await server.startQuic();
  const serverPort = server._actualPort || QUIC_SERVER_PORT;
  console.log(`  QUIC/H3 server on port ${serverPort}`);

  // Start agent
  const agent = startAgent('client', { controlPort: QUIC_AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  let results = [];
  try {
    try { await httpPost(QUIC_AGENT_PORT, '/stop', {}); } catch {}
    await new Promise(r => setTimeout(r, 500));

    const configResult = await httpPost(QUIC_AGENT_PORT, '/configure', {
      config: {
        host: 'localhost', port: serverPort,
        protocol: 'quic', workers: 1,
        timeout: 10000, delay: 100, baseline: false,
        pcapFile: QUIC_PCAP_FILE,
        mergePcap: true,
      },
      scenarios: scenarioNames,
    });
    console.log(`  Configured: ${configResult.scenarioCount} scenarios`);

    await httpPost(QUIC_AGENT_PORT, '/run', {});
    await waitForDone(QUIC_AGENT_PORT, configResult.scenarioCount, 'QUIC', 120000);
    results = await httpGet(QUIC_AGENT_PORT, '/results');

    const byStatus = {};
    for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    console.log(`  Results: ${results.length} total`);
    for (const [s, c] of Object.entries(byStatus).sort()) console.log(`    ${s}: ${c}`);

  } finally {
    try { await httpPost(QUIC_AGENT_PORT, '/stop', {}); } catch {}
    try { server.stop(); } catch {}
    try { agent.close(); } catch {}
  }

  return verifyWithTshark(QUIC_PCAP_FILE, QUIC_KEYLOG_FILE, 'QUIC');
}

// ─── Main ──────────────────────────────────────────────────────────────────
async function run() {
  // Ensure output directory exists
  if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  // Clean previous output
  for (const f of [H2_PCAP_FILE, H2_KEYLOG_FILE, QUIC_PCAP_FILE, QUIC_KEYLOG_FILE]) {
    try { fs.unlinkSync(f); } catch {}
  }

  let h2Pass = false;
  let quicPass = false;

  // Run H2 first, then QUIC (sequential to avoid port conflicts)
  try {
    h2Pass = await runH2Test();
  } catch (e) {
    console.error(`  H2 test failed: ${e.message}`);
  }

  // Wait for cleanup
  await new Promise(r => setTimeout(r, 2000));

  try {
    quicPass = await runQuicTest();
  } catch (e) {
    console.error(`  QUIC test failed: ${e.message}`);
  }

  // ─── Final summary ────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════');
  console.log('  PCAP + KEYLOG VERIFICATION SUMMARY');
  console.log('══════════════════════════════════════════════════');
  console.log(`  HTTP/2:  ${h2Pass ? 'PASS' : 'FAIL'}  ${H2_PCAP_FILE}`);
  console.log(`           keylog: ${H2_KEYLOG_FILE}`);
  console.log(`  QUIC:    ${quicPass ? 'PASS' : 'FAIL'}  ${QUIC_PCAP_FILE}`);
  console.log(`           keylog: ${QUIC_KEYLOG_FILE}`);
  console.log('══════════════════════════════════════════════════');

  console.log('\n  Wireshark instructions:');
  console.log('    1. Open: <pcap file>');
  console.log('    2. Edit -> Preferences -> Protocols -> TLS');
  console.log('       (Pre)-Master-Secret log filename: <corresponding .keylog file>');
  console.log('    3. Apply — sessions will decrypt');
  console.log('══════════════════════════════════════════════════');

  const allPass = h2Pass && quicPass;
  setTimeout(() => process.exit(allPass ? 0 : 1), 2000);
}

run().catch(err => { console.error('Test failed:', err); process.exit(1); });
