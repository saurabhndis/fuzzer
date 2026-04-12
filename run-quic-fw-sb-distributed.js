const http = require('http');
const { startAgent } = require('./lib/agent');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { listQuicClientScenarios } = require('./lib/quic-scenarios');

const SERVER_PORT = 4433;
const AGENT_PORT = 9250;

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

async function waitForDone(port, total, timeout = 7200000) {
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
    await new Promise(r => setTimeout(r, 2000));
  }
  throw new Error(`Timed out after ${Math.round((Date.now() - start)/1000)}s`);
}

async function runBatch(agentPort, serverPort, scenarioNames) {
  try { await httpPost(agentPort, '/stop', {}); } catch {}
  await new Promise(r => setTimeout(r, 500));
  const configResult = await httpPost(agentPort, '/configure', {
    config: { host: 'localhost', port: serverPort, protocol: 'quic', workers: 1, timeout: 5000, delay: 50, baseline: false },
    scenarios: scenarioNames,
  });
  if (configResult.scenarioCount === 0) throw new Error('No scenarios resolved');
  await httpPost(agentPort, '/run', {});
  await waitForDone(agentPort, configResult.scenarioCount);
  return await httpGet(agentPort, '/results');
}

async function run() {
  const allScenarios = listQuicClientScenarios();
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

  const server = new WellBehavedServer({ hostname: 'localhost', port: SERVER_PORT, logger: null });
  await server.startQuic();
  const actualPort = server._actualPort || SERVER_PORT;
  console.log(`Server on port ${actualPort}`);

  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));

  const allResults = [];

  try {
    const keyCats = ['QM', 'QN'];
    const keyNames = keyCats.flatMap(c => byCategory[c] || []);
    console.log(`\n── QUIC Firewall & Sandbox (${keyNames.length} scenarios) ──`);
    const r1 = await runBatch(AGENT_PORT, actualPort, keyNames);
    allResults.push(...r1);
    console.log(`  Done: ${r1.length} results\n`);

    console.log('══════════════════════════════════════════════════');
    console.log('  ANALYSIS');
    console.log('══════════════════════════════════════════════════');
    for (const r of allResults) {
      console.log(`[${r.scenario}] -> ${r.status}`);
      console.log(`    Response: ${r.response}`);
    }
  } finally {
    try { await httpPost(AGENT_PORT, '/stop', {}); } catch {}
    try { server.stop(); } catch {}
    try { agent.close(); } catch {}
    setTimeout(() => process.exit(0), 1000);
  }
}

run().catch(err => { console.error('Test failed:', err); process.exit(1); });
