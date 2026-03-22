#!/usr/bin/env node
// Test PCAP merge functionality: run a sample of QUIC scenarios producing a single merged PCAP,
// then validate the PCAP with tshark.

const http = require('http');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const { startAgent } = require('./lib/agent');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { listQuicClientScenarios } = require('./lib/quic-scenarios');

const SERVER_PORT = 4433;
const AGENT_PORT = 9251;
const PCAP_FILE = path.join(__dirname, 'test-output', 'merged-quic.pcap');

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
  throw new Error('Timed out waiting for scenarios');
}

async function run() {
  // Ensure output directory exists
  const outDir = path.dirname(PCAP_FILE);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  // Remove old pcap if exists
  if (fs.existsSync(PCAP_FILE)) fs.unlinkSync(PCAP_FILE);

  const allScenarios = listQuicClientScenarios();
  const byCategory = {};
  for (const s of allScenarios) {
    if (!byCategory[s.category]) byCategory[s.category] = [];
    byCategory[s.category].push(s.name);
  }

  // Pick a representative sample: all QZ (well-behaved), first 5 QM (virus), first 3 QA (native fuzz)
  const scenarioNames = [
    ...(byCategory.QZ || []),
    ...(byCategory.QM || []).slice(0, 5),
    ...(byCategory.QA || []).slice(0, 3),
    ...(byCategory.QN || []).slice(0, 3),
  ];

  console.log(`Selected ${scenarioNames.length} scenarios for merged PCAP test`);

  const server = new WellBehavedServer({ hostname: '127.0.0.1', port: SERVER_PORT, logger: null });
  await server.startQuic();
  const actualPort = server._actualPort || SERVER_PORT;
  console.log(`QUIC server on port ${actualPort}`);

  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  try {
    const configResult = await httpPost(AGENT_PORT, '/configure', {
      config: {
        host: '127.0.0.1',
        port: actualPort,
        protocol: 'quic',
        workers: 1,
        timeout: 5000,
        delay: 50,
        baseline: false,
        pcapFile: PCAP_FILE,
        mergePcap: true,
      },
      scenarios: scenarioNames,
    });

    console.log(`Configured: ${configResult.scenarioCount} scenarios, pcap → ${PCAP_FILE}`);

    await httpPost(AGENT_PORT, '/run', {});
    await waitForDone(AGENT_PORT, configResult.scenarioCount);

    const results = await httpGet(AGENT_PORT, '/results');
    console.log(`Completed: ${results.length} results`);

    // Check PCAP file
    if (!fs.existsSync(PCAP_FILE)) {
      console.error('FAIL: Merged PCAP file was not created!');
      process.exit(1);
    }

    const stat = fs.statSync(PCAP_FILE);
    console.log(`\nMerged PCAP file: ${PCAP_FILE}`);
    console.log(`  Size: ${stat.size} bytes`);

    if (stat.size < 24) {
      console.error('FAIL: PCAP file too small (no global header)');
      process.exit(1);
    }

    // Validate global header
    const fd = fs.openSync(PCAP_FILE, 'r');
    const hdr = Buffer.alloc(24);
    fs.readSync(fd, hdr, 0, 24, 0);
    fs.closeSync(fd);

    const magic = hdr.readUInt32LE(0);
    const vMajor = hdr.readUInt16LE(4);
    const vMinor = hdr.readUInt16LE(6);
    const snaplen = hdr.readUInt32LE(16);
    const linktype = hdr.readUInt32LE(20);

    console.log(`  Magic:    0x${magic.toString(16)} (expected 0xa1b2c3d4)`);
    console.log(`  Version:  ${vMajor}.${vMinor} (expected 2.4)`);
    console.log(`  Snaplen:  ${snaplen}`);
    console.log(`  Linktype: ${linktype} (1=Ethernet)`);

    const headerOk = magic === 0xa1b2c3d4 && vMajor === 2 && vMinor === 4 && linktype === 1;
    if (!headerOk) {
      console.error('FAIL: PCAP global header is invalid');
      process.exit(1);
    }
    console.log('  Header:   VALID ✓');

    // Count packets by parsing pcap records
    let offset = 24;
    let packetCount = 0;
    const fileData = fs.readFileSync(PCAP_FILE);
    while (offset + 16 <= fileData.length) {
      const inclLen = fileData.readUInt32LE(offset + 8);
      if (offset + 16 + inclLen > fileData.length) {
        console.error(`  WARNING: Truncated packet at offset ${offset}`);
        break;
      }
      packetCount++;
      offset += 16 + inclLen;
    }
    console.log(`  Packets:  ${packetCount}`);

    if (offset !== fileData.length) {
      console.error(`  WARNING: ${fileData.length - offset} trailing bytes after last packet`);
    }

    // Validate with tshark if available
    const tsharkPaths = ['/opt/homebrew/bin/tshark', '/usr/bin/tshark', '/usr/local/bin/tshark'];
    let tshark = null;
    for (const p of tsharkPaths) {
      if (fs.existsSync(p)) { tshark = p; break; }
    }

    if (tshark) {
      console.log(`\nValidating with tshark (${tshark})...`);
      try {
        const output = execSync(`${tshark} -r "${PCAP_FILE}" -c 20 2>&1`, { encoding: 'utf8', timeout: 15000 });
        const lines = output.trim().split('\n').filter(l => l.trim());
        console.log(`  tshark parsed ${lines.length} packets (showing first 20):`);
        for (const line of lines.slice(0, 10)) {
          console.log(`    ${line}`);
        }
        if (lines.length > 10) console.log(`    ... (${lines.length - 10} more)`);

        // Check for UDP packets
        const udpCount = lines.filter(l => /UDP/i.test(l)).length;
        console.log(`  UDP packets in first 20: ${udpCount}`);
        console.log('  tshark validation: PASSED ✓');
      } catch (e) {
        console.error(`  tshark FAILED: ${e.message}`);
        // Show stderr for debugging
        if (e.stderr) console.error(`  stderr: ${e.stderr.substring(0, 500)}`);
        process.exit(1);
      }
    } else {
      console.log('\n  tshark not found — skipping Wireshark validation');
    }

    // Check no individual per-scenario pcap files were created
    const pcapDir = path.dirname(PCAP_FILE);
    const individualPcaps = fs.readdirSync(pcapDir).filter(f => f.endsWith('.pcap') && f !== path.basename(PCAP_FILE));
    if (individualPcaps.length > 0) {
      console.log(`\n  WARNING: ${individualPcaps.length} individual PCAP files also created (should only be merged):`);
      for (const f of individualPcaps.slice(0, 5)) console.log(`    ${f}`);
    } else {
      console.log('\n  No individual PCAP files created (merge mode working) ✓');
    }

    // Summary of results
    const byStatus = {};
    for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    console.log('\n══════════════════════════════════════════════════');
    console.log('  PCAP MERGE TEST SUMMARY');
    console.log('══════════════════════════════════════════════════');
    console.log(`  Scenarios run:    ${results.length}`);
    console.log(`  PCAP file:        ${PCAP_FILE}`);
    console.log(`  PCAP size:        ${stat.size} bytes`);
    console.log(`  PCAP packets:     ${packetCount}`);
    console.log(`  Header valid:     YES`);
    console.log(`  tshark valid:     ${tshark ? 'YES' : 'SKIPPED'}`);
    for (const [s, c] of Object.entries(byStatus).sort()) console.log(`  ${s.padEnd(14)}  ${c}`);
    console.log('══════════════════════════════════════════════════');

  } finally {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    try { server.stop(); } catch {}
    try { agent.close(); } catch {}
    setTimeout(() => process.exit(0), 2000);
  }
}

run().catch(err => { console.error('Test failed:', err); process.exit(1); });
