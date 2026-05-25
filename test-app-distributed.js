#!/usr/bin/env node
// Real distributed APP regression: two agents + controller + stepped pairing.
// Covers SMTP, FTP, LDAP (Implicit & STARTTLS) and the injection variants.

const { startAgent } = require('./lib/agent');
const { Controller } = require('./lib/controller');
const { getScenariosByCategory, getScenario } = require('./lib/scenarios');
const {
  getDistributedAppServerHelper,
  getDistributedAppClientHelper,
} = require('./lib/app-protocol-scenarios');

const CLIENT_AGENT_PORT = 9253;
const SERVER_AGENT_PORT = 9254;
const TARGET_PORT = 4437;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function summarize(label, results) {
  console.log(`\n${label}`);
  console.log('='.repeat(label.length));
  let passed = 0;
  let failed = 0;
  for (const r of results) {
    const meta = getScenario(r.scenario);
    const expected = (meta && meta.expected) || 'PASSED';
    const ok = r.status === expected;
    if (ok) passed++; else failed++;
    console.log(`  ${ok ? 'PASS' : 'FAIL'} ${r.scenario.padEnd(45)} | Got: ${String(r.status).padEnd(8)} | Expected: ${expected}`);
    if (!ok) console.log(`       Response: ${r.response}`);
  }
  console.log(`  Total: ${results.length} | Passed: ${passed} | Failed: ${failed}`);
  return failed;
}

async function runBatch(controller, clientNames, serverNames, label, helperPairs = {}) {
  const clientConfig = { host: 'localhost', port: TARGET_PORT, protocol: 'tls', workers: 1, timeout: 5000, delay: 10, baseline: false };
  const serverConfig = { hostname: 'localhost', port: TARGET_PORT, protocol: 'tls', workers: 1, timeout: 5000, delay: 10, baseline: false };
  await controller.configureAll(clientNames, serverNames, clientConfig, serverConfig, [], [], helperPairs);
  const stepped = await controller.runStepped(Math.max(clientNames.length, serverNames.length));
  if (!stepped.ok) {
    throw new Error(`${label} stepped execution reported failures: ${JSON.stringify(stepped.failures || [])}`);
  }
  const clientResults = await controller.getResults('client');
  const serverResults = await controller.getResults('server');
  return { clientResults, serverResults };
}

async function run() {
  const clientAgent = startAgent('client', { controlPort: CLIENT_AGENT_PORT });
  const serverAgent = startAgent('server', { controlPort: SERVER_AGENT_PORT });
  await sleep(1000);

  const controller = new Controller();
  await controller.connect('client', 'localhost', CLIENT_AGENT_PORT);
  await controller.connect('server', 'localhost', SERVER_AGENT_PORT);

  const clientScenarios = getScenariosByCategory('APP').filter((s) => s.side === 'client').map((s) => s.name);
  const serverHelpers = clientScenarios.map(getDistributedAppServerHelper);
  const serverScenarios = getScenariosByCategory('APP').filter((s) => s.side === 'server').map((s) => s.name);
  const clientHelpers = serverScenarios.map(getDistributedAppClientHelper);
  const clientDrivenHelperPairs = {
    client: [],
    server: clientScenarios.map((_, i) => String(i)),
  };
  const serverDrivenHelperPairs = {
    client: serverScenarios.map((_, i) => String(i)),
    server: [],
  };

  let failures = 0;
  try {
    const first = await runBatch(controller, clientScenarios, serverHelpers, 'client-driven', clientDrivenHelperPairs);
    failures += summarize('Client-Driven APP Distributed Results', first.clientResults);
    if (first.serverResults.length > 0) {
      failures += summarize('Client-Driven Helper Server Results', first.serverResults);
    } else {
      console.log('\nClient-Driven Helper Server Results\n===================================\n  Helpers suppressed as debug results');
    }

    const second = await runBatch(controller, clientHelpers, serverScenarios, 'server-driven', serverDrivenHelperPairs);
    if (second.clientResults.length > 0) {
      failures += summarize('Server-Driven Helper Client Results', second.clientResults);
    } else {
      console.log('\nServer-Driven Helper Client Results\n===================================\n  Helpers suppressed as debug results');
    }
    failures += summarize('Server-Driven APP Distributed Results', second.serverResults);
  } finally {
    try { await controller.stopAll(); } catch (_) {}
    try { clientAgent.close(); } catch (_) {}
    try { serverAgent.close(); } catch (_) {}
  }

  process.exit(failures > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
