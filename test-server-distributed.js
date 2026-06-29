#!/usr/bin/env node
// Run every TLS server-side scenario through the distributed two-agent path.
// Mirrors the UI server phase: real server scenario on the server agent,
// protocol-aware helper client on the client agent, stepped one pair at a time.

const { startAgent } = require('./lib/agent');
const { Controller } = require('./lib/controller');
const { getServerScenarios, getScenario } = require('./lib/scenarios');
const { computeExpected } = require('./lib/compute-expected');
const { getDistributedAppClientHelper } = require('./lib/app-protocol-scenarios');

const CLIENT_AGENT_PORT = 9263;
const SERVER_AGENT_PORT = 9264;
const TARGET_PORT = 4441;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function helperClientForServerScenario(name) {
  const appHelper = getDistributedAppClientHelper(name);
  if (appHelper) return appHelper;
  return String(name || '').includes('pqc')
    ? 'fv-tls-well-behaved-pqc-ch'
    : 'fv-tls-well-behaved-small-ch';
}

function expectedFor(name) {
  const scenario = getScenario(name);
  if (!scenario) return null;
  const computed = computeExpected(scenario);
  return 'expected' in scenario ? scenario.expected : computed.expected;
}

function isPassing(result) {
  if (!result) return false;
  if (result.verdict === 'AS EXPECTED') return true;
  if (result.expected && result.status === result.expected) return true;
  const expected = expectedFor(result.scenario);
  if (expected === 'DROPPED') {
    return result.status === 'DROPPED' ||
      result.status === 'tls-alert-client' ||
      result.status === 'tls-alert-server';
  }
  return expected === result.status;
}

async function run() {
  const serverScenarios = getServerScenarios().map((s) => s.name);
  const clientHelpers = serverScenarios.map(helperClientForServerScenario);
  const helperPairs = {
    client: serverScenarios.map((_, i) => String(i)),
    server: [],
  };

  console.log(`Running ${serverScenarios.length} TLS server-side scenario(s) in distributed mode`);

  const clientAgent = startAgent('client', { controlPort: CLIENT_AGENT_PORT });
  const serverAgent = startAgent('server', { controlPort: SERVER_AGENT_PORT });
  await sleep(1000);

  const controller = new Controller();
  let exitCode = 0;
  try {
    await controller.connect('client', 'localhost', CLIENT_AGENT_PORT);
    await controller.connect('server', 'localhost', SERVER_AGENT_PORT);

    const clientConfig = {
      host: 'localhost',
      port: TARGET_PORT,
      protocol: 'tls',
      workers: 1,
      timeout: 5000,
      delay: 10,
      baseline: false,
    };
    const serverConfig = {
      bindAddress: '0.0.0.0',
      hostname: 'localhost',
      port: TARGET_PORT,
      protocol: 'tls',
      workers: 1,
      timeout: 5000,
      delay: 10,
      baseline: false,
    };

    await controller.configureAll(
      clientHelpers,
      serverScenarios,
      clientConfig,
      serverConfig,
      [],
      [],
      helperPairs,
    );

    const stepped = await controller.runStepped(serverScenarios.length);
    if (!stepped.ok) {
      console.error(`Controller failures: ${JSON.stringify(stepped.failures || [], null, 2)}`);
      exitCode = 1;
    }

    const serverResults = await controller.getResults('server') || [];
    const byName = new Map(serverResults.map((r) => [r.scenario, r]));
    const missing = serverScenarios.filter((name) => !byName.has(name));
    const unexpected = [];

    for (const name of serverScenarios) {
      const result = byName.get(name);
      if (!result) continue;
      if (!isPassing(result)) unexpected.push(result);
    }

    let passed = 0;
    for (const name of serverScenarios) {
      const result = byName.get(name);
      if (result && isPassing(result)) passed++;
    }

    console.log(`\nServer-side distributed results: ${passed}/${serverScenarios.length} passed`);
    if (missing.length > 0) {
      console.log(`Missing result rows (${missing.length}):`);
      for (const name of missing) console.log(`  MISSING ${name}`);
      exitCode = 1;
    }
    if (unexpected.length > 0) {
      console.log(`Unexpected result rows (${unexpected.length}):`);
      for (const r of unexpected) {
        console.log(`  FAIL ${r.scenario} | status=${r.status} expected=${r.expected || expectedFor(r.scenario) || 'N/A'} verdict=${r.verdict || 'N/A'} | ${r.response || ''}`);
      }
      exitCode = 1;
    }
    if (missing.length === 0 && unexpected.length === 0 && !stepped.failures?.length) {
      console.log('All server-side distributed scenarios passed.');
    }
  } finally {
    try { await controller.stopAll(); } catch (_) {}
    try { clientAgent.close(); } catch (_) {}
    try { serverAgent.close(); } catch (_) {}
  }

  process.exit(exitCode);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
