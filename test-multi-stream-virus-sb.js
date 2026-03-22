#!/usr/bin/env node
// Test multi-stream virus/sandbox upload+download scenarios for both HTTP/2 and QUIC.
// Verifies that application data is successfully exchanged across all streams.

const http = require('http');
const { startAgent } = require('./lib/agent');
const { WellBehavedServer } = require('./lib/well-behaved-server');

const SERVER_PORT = 4433;
const H2_SERVER_PORT = 8443;
const AGENT_PORT = 9252;

function httpPost(port, pth, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ hostname: '127.0.0.1', port, path: pth, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function httpGet(port, pth) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, path: pth }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    }).on('error', reject);
  });
}

async function waitForDone(port, total, timeout = 300000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const status = await httpGet(port, '/status');
    if (status.status === 'done') return;
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error('Timed out');
}

async function runBatch(agentPort, serverPort, protocol, scenarioNames) {
  try { await httpPost(agentPort, '/stop', {}); } catch {}
  await new Promise(r => setTimeout(r, 500));
  const configResult = await httpPost(agentPort, '/configure', {
    config: { host: '127.0.0.1', port: serverPort, protocol, workers: 1, timeout: 20000, delay: 50, baseline: false },
    scenarios: scenarioNames,
  });
  if (configResult.scenarioCount === 0) throw new Error('No scenarios resolved');
  await httpPost(agentPort, '/run', {});
  await waitForDone(agentPort, configResult.scenarioCount);
  return await httpGet(agentPort, '/results');
}

async function run() {
  console.log('══════════════════════════════════════════════════');
  console.log('  MULTI-STREAM VIRUS/SANDBOX UPLOAD+DOWNLOAD TEST');
  console.log('══════════════════════════════════════════════════\n');

  // ── Start servers ──
  const server = new WellBehavedServer({ hostname: '127.0.0.1', port: SERVER_PORT, logger: null });
  await server.startQuic();
  const quicPort = server._actualPort || SERVER_PORT;
  console.log(`QUIC/H3 server on port ${quicPort}`);

  // Start H2 server using WellBehavedServer
  const h2Server = new WellBehavedServer({ hostname: '127.0.0.1', port: H2_SERVER_PORT, logger: null });
  await h2Server.startH2();
  const h2Port = h2Server._actualPort || H2_SERVER_PORT;
  console.log(`HTTP/2 server on port ${h2Port}`);

  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  const allResults = [];

  try {
    // ── QUIC multi-stream virus ──
    console.log('\n── QUIC: Multi-stream virus upload+download (44 streams) ──');
    const qVirusResults = await runBatch(AGENT_PORT, quicPort, 'quic', ['quic-multi-stream-virus-upload-download']);
    allResults.push(...qVirusResults);
    for (const r of qVirusResults) {
      console.log(`  ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status}`);
      console.log(`    ${r.response}`);
    }

    // ── QUIC multi-stream sandbox ──
    console.log('\n── QUIC: Multi-stream sandbox upload+download (100 streams) ──');
    const qSbResults = await runBatch(AGENT_PORT, quicPort, 'quic', ['quic-multi-stream-sb-upload-download']);
    allResults.push(...qSbResults);
    for (const r of qSbResults) {
      console.log(`  ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status}`);
      console.log(`    ${r.response}`);
    }

    // ── HTTP/2 multi-stream virus ──
    console.log('\n── HTTP/2: Multi-stream virus upload+download (44 streams) ──');
    const h2VirusResults = await runBatch(AGENT_PORT, h2Port, 'h2', ['h2-fv-multi-stream-virus-upload-download']);
    allResults.push(...h2VirusResults);
    for (const r of h2VirusResults) {
      console.log(`  ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status}`);
      console.log(`    ${r.response}`);
    }

    // ── HTTP/2 multi-stream sandbox ──
    console.log('\n── HTTP/2: Multi-stream sandbox upload+download (100 streams) ──');
    const h2SbResults = await runBatch(AGENT_PORT, h2Port, 'h2', ['h2-fv-multi-stream-sb-upload-download']);
    allResults.push(...h2SbResults);
    for (const r of h2SbResults) {
      console.log(`  ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status}`);
      console.log(`    ${r.response}`);
    }

    // ── Summary ──
    console.log('\n══════════════════════════════════════════════════');
    console.log('  SUMMARY');
    console.log('══════════════════════════════════════════════════');
    let allPassed = true;
    for (const r of allResults) {
      const ok = r.status === 'PASSED';
      if (!ok) allPassed = false;
      console.log(`  ${ok ? '✓' : '✗'} ${r.scenario}: ${r.status}`);
      console.log(`    ${r.response}`);
    }
    console.log(`\n  Overall: ${allPassed ? 'ALL PASSED' : 'SOME FAILURES'}`);
    console.log('══════════════════════════════════════════════════');

  } finally {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    try { server.stop(); } catch {}
    try { h2Server.close(); } catch {}
    try { agent.close(); } catch {}
    setTimeout(() => process.exit(0), 2000);
  }
}

run().catch(err => { console.error('Test failed:', err); process.exit(1); });
