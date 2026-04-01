#!/usr/bin/env node
// Run HTTP/2 AV/SB (AN=virus/firewall, AO=sandbox) scenarios in distributed mode
// with real PCAP capture via a transparent TCP proxy and TLS keylog export.
//
// How it works:
//   - A transparent TCP proxy sits between the fuzzer client and the H2 server.
//   - All raw (encrypted) bytes flowing through the proxy are written to a PCAP.
//   - The fuzzer client's TLS keylog events write NSS Key Log lines to a .keylog file.
//   - In Wireshark: open the PCAP, then Preferences > Protocols > TLS > set the keylog file.
//
// Output files:
//   /tmp/h2-avsb.pcap    — captured TLS traffic (open in Wireshark)
//   /tmp/h2-avsb.keylog  — TLS session keys for decryption

const http   = require('http');
const net    = require('net');
const fs     = require('fs');
const path   = require('path');
const { startAgent }              = require('./lib/agent');
const { WellBehavedServer }       = require('./lib/well-behaved-server');
const { listHttp2ClientScenarios } = require('./lib/http2-scenarios');
const { PcapWriter }              = require('./lib/pcap-writer');

const SERVER_PORT  = 14434;   // real H2 server (internal)
const PROXY_PORT   = 4434;    // capture proxy (what the agent sees)
const AGENT_PORT   = 9251;
const PCAP_FILE    = '/tmp/h2-avsb.pcap';
const KEYLOG_FILE  = '/tmp/h2-avsb.keylog';

// ─── Transparent TCP Capture Proxy ─────────────────────────────────────────
// Forwards every byte between client and server unchanged, and writes them
// to a PCAP file.  Each new connection gets its own unique client port so
// Wireshark doesn't flag port reuse.
class TcpCaptureProxy {
  constructor({ listenPort, targetHost, targetPort, pcapFile }) {
    this.listenPort  = listenPort;
    this.targetHost  = targetHost || 'localhost';
    this.targetPort  = targetPort;
    this.pcapFile    = pcapFile;
    this.portCounter = 0;
    this.firstConn   = true;
    this.server      = null;
    this.openWriters = new Set();
  }

  async start() {
    // Remove stale PCAP so the first PcapWriter creates a fresh file
    try { fs.unlinkSync(this.pcapFile); } catch (_) {}

    return new Promise((resolve, reject) => {
      this.server = net.createServer((clientSock) => {
        // Unique synthetic client port per connection so Wireshark sees distinct streams
        const clientPort = 49152 + (this.portCounter++ % 16383);

        const writer = new PcapWriter(this.pcapFile, {
          role:       'client',
          append:     !this.firstConn,
          clientPort,
          serverPort: this.targetPort,
        });
        this.firstConn = false;
        this.openWriters.add(writer);

        // Write TCP handshake immediately — before any data events fire
        writer.writeTCPHandshake();

        const serverSock = net.connect(this.targetPort, this.targetHost);

        clientSock.on('data', (chunk) => {
          try { writer.writeTLSData(chunk, 'sent'); } catch (_) {}
          if (!serverSock.destroyed) serverSock.write(chunk);
        });

        serverSock.on('data', (chunk) => {
          try { writer.writeTLSData(chunk, 'received'); } catch (_) {}
          if (!clientSock.destroyed) clientSock.write(chunk);
        });

        let closed = false;
        const cleanup = () => {
          if (closed) return;
          closed = true;
          try { writer.writeFIN('sent'); } catch (_) {}
          try { writer.close(); } catch (_) {}
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
    for (const w of this.openWriters) { try { w.close(); } catch (_) {} }
    this.openWriters.clear();
    if (this.server) { this.server.close(); this.server = null; }
  }
}

// ─── HTTP helpers ───────────────────────────────────────────────────────────
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

async function waitForDone(port, total, timeoutMs = 300000) {
  const start = Date.now();
  let lastPct = -1;
  while (Date.now() - start < timeoutMs) {
    const status = await httpGet(port, '/status');
    const pct = Math.floor((status.completedCount / total) * 100);
    if (pct !== lastPct && (pct % 10 === 0 || status.status === 'done')) {
      process.stdout.write(`  Progress: ${status.completedCount}/${total} (${pct}%)\n`);
      lastPct = pct;
    }
    if (status.status === 'done') return;
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`Timed out after ${Math.round((Date.now() - start) / 1000)}s`);
}

// ─── Main ───────────────────────────────────────────────────────────────────
async function run() {
  const allScenarios = listHttp2ClientScenarios();
  const expectedMap = {};
  const byCategory  = {};
  for (const s of allScenarios) {
    expectedMap[s.name] = s.expected || 'DROPPED';
    if (!byCategory[s.category]) byCategory[s.category] = [];
    byCategory[s.category].push(s.name);
  }

  // AN = virus/firewall spoofs, AO = sandbox detection
  const scenarioNames = ['AN', 'AO'].flatMap(c => byCategory[c] || []);
  console.log(`Running ${scenarioNames.length} scenarios  (AN: ${(byCategory.AN || []).length}, AO: ${(byCategory.AO || []).length})`);
  console.log(`PCAP:   ${PCAP_FILE}`);
  console.log(`Keylog: ${KEYLOG_FILE}`);

  // Start H2 server on internal port
  const server = new WellBehavedServer({ hostname: 'localhost', port: SERVER_PORT, logger: null });
  await server.startH2();
  const actualServerPort = server._actualPort || SERVER_PORT;
  console.log(`H2 server on port ${actualServerPort} (internal)`);

  // Start capture proxy: agent → proxy:PROXY_PORT → server:actualServerPort
  const proxy = new TcpCaptureProxy({
    listenPort:  PROXY_PORT,
    targetHost:  'localhost',
    targetPort:  actualServerPort,
    pcapFile:    PCAP_FILE,
  });
  await proxy.start();
  console.log(`Capture proxy on port ${PROXY_PORT} → ${actualServerPort}`);

  // Start agent
  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  let results = [];
  try {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    await new Promise(r => setTimeout(r, 500));

    const configResult = await httpPost(AGENT_PORT, '/configure', {
      config: {
        host:        'localhost',
        port:        PROXY_PORT,     // connect through the capture proxy
        protocol:    'h2',
        workers:     1,              // single-threaded = sequential connections = clean PCAP
        timeout:     5000,
        delay:       50,
        baseline:    false,
        keylogFile:  KEYLOG_FILE,    // TLS key export (decryption) — no synthetic PCAP
      },
      scenarios: scenarioNames,
    });
    console.log(`Configured: ${configResult.scenarioCount} scenarios`);

    await httpPost(AGENT_PORT, '/run', {});
    await waitForDone(AGENT_PORT, configResult.scenarioCount);
    results = await httpGet(AGENT_PORT, '/results');

    // ─── Analysis ─────────────────────────────────────────────────────────
    const catMap = {};
    for (const cat of ['AN', 'AO']) for (const n of (byCategory[cat] || [])) catMap[n] = cat;
    const grouped = { AN: [], AO: [] };
    for (const r of results) { const c = catMap[r.scenario]; if (c) grouped[c].push(r); }

    console.log('\n══════════════════════════════════════════════════');
    console.log('  VIRUS / FIREWALL SCENARIOS (AN)');
    console.log('══════════════════════════════════════════════════');
    for (const r of grouped.AN) {
      const exp = expectedMap[r.scenario];
      console.log(`  ${r.status === exp ? '✓' : '✗'} ${r.scenario}: ${r.status} (expected ${exp})`);
      if (r.response) console.log(`      ${r.response.substring(0, 150)}`);
    }

    console.log('\n══════════════════════════════════════════════════');
    console.log('  SANDBOX SCENARIOS (AO)');
    console.log('══════════════════════════════════════════════════');
    for (const r of grouped.AO) {
      const exp = expectedMap[r.scenario];
      console.log(`  ${r.status === exp ? '✓' : '✗'} ${r.scenario}: ${r.status} (expected ${exp})`);
      if (r.response) console.log(`      ${r.response.substring(0, 150)}`);
    }

    const byStatus = {};
    for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    const suspicious = results.filter(r => {
      const exp = expectedMap[r.scenario];
      return (exp && r.status !== exp) || r.status === 'ERROR';
    });

    console.log('\n══════════════════════════════════════════════════');
    console.log('  FINAL SUMMARY');
    console.log('══════════════════════════════════════════════════');
    console.log(`  Total: ${results.length}`);
    for (const [s, c] of Object.entries(byStatus).sort()) console.log(`  ${s.padEnd(12)} ${c}`);
    console.log(`  Suspicious: ${suspicious.length}`);
    if (suspicious.length > 0) {
      for (const r of suspicious)
        console.log(`    - ${r.scenario}: got ${r.status}, expected ${expectedMap[r.scenario] || '?'}`);
    }
    console.log('══════════════════════════════════════════════════');

    const pcapSize   = (() => { try { return fs.statSync(PCAP_FILE).size;   } catch { return 0; } })();
    const keylogSize = (() => { try { return fs.statSync(KEYLOG_FILE).size; } catch { return 0; } })();
    const keylogLines = keylogSize > 0 ? fs.readFileSync(KEYLOG_FILE, 'utf8').split('\n').filter(Boolean).length : 0;

    console.log(`\n  PCAP:   ${PCAP_FILE}  (${(pcapSize/1024).toFixed(1)} KB)`);
    console.log(`  Keylog: ${KEYLOG_FILE}  (${keylogLines} key lines)`);
    if (keylogSize === 0) console.log('  ⚠  Keylog empty — TLS keylog events did not fire');

    console.log('\n  Wireshark instructions:');
    console.log(`    1. Open: ${PCAP_FILE}`);
    console.log(`    2. Edit → Preferences → Protocols → TLS`);
    console.log(`       (Pre)-Master-Secret log filename: ${KEYLOG_FILE}`);
    console.log('    3. Apply — sessions will decrypt and show HTTP/2 frames');

  } finally {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    try { proxy.stop(); }  catch {}
    try { server.stop(); } catch {}
    try { agent.close(); } catch {}
    setTimeout(() => process.exit(0), 2000);
  }
}

run().catch(err => { console.error('Test failed:', err); process.exit(1); });
