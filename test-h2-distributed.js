#!/usr/bin/env node
// Test all TLS and HTTP/2 scenarios in distributed mode
// Launches client + server agents, a well-behaved counterpart for each,
// and drives them through the Controller.

const { startAgent } = require('./lib/agent');
const { Controller } = require('./lib/controller');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { WellBehavedClient } = require('./lib/well-behaved-client');
const { SCENARIOS, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { HTTP2_SCENARIOS, HTTP2_CATEGORY_DEFAULT_DISABLED } = require('./lib/http2-scenarios');

const CLIENT_CONTROL_PORT = 19200;
const SERVER_CONTROL_PORT = 19201;
const FUZZ_PORT = 14433;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Reusable phase runner ────────────────────────────────────────────────

async function runClientPhase(label, scenarios, protocol, serverStartFn, config, timeoutMs) {
  console.log(`  \x1b[1m── ${label}: Client-side (${scenarios.length}) ──\x1b[0m`);

  const wbServer = new WellBehavedServer({ port: FUZZ_PORT, hostname: 'localhost' });
  await serverStartFn(wbServer);
  console.log(`  Target server on port ${wbServer.actualPort}`);

  const clientAgent = startAgent('client', { controlPort: CLIENT_CONTROL_PORT });
  await sleep(500);

  const controller = new Controller();
  await controller.connect('client', 'localhost', CLIENT_CONTROL_PORT);

  await controller.configure('client', scenarios.map(s => s.name), {
    host: 'localhost',
    port: wbServer.actualPort,
    protocol,
    timeout: 5000,
    delay: 50,
    ...config,
  });
  console.log(`  Configured ${scenarios.length} scenarios`);

  const { results, errors } = await collectResults(controller, scenarios.length, timeoutMs);

  controller.disconnect();
  clientAgent.close();
  wbServer.stop();
  await sleep(500);

  printPhaseSummary(label + ' Client', results, scenarios.length, errors);
  return { results, errors };
}

async function runServerPhase(label, scenarios, protocol, connectFn, config, timeoutMs) {
  console.log(`  \x1b[1m── ${label}: Server-side (${scenarios.length}) ──\x1b[0m`);

  const serverAgent = startAgent('server', { controlPort: SERVER_CONTROL_PORT });
  await sleep(500);

  const controller = new Controller();
  await controller.connect('server', 'localhost', SERVER_CONTROL_PORT);

  await controller.configure('server', scenarios.map(s => s.name), {
    hostname: 'localhost',
    port: FUZZ_PORT,
    protocol,
    timeout: 10000,
    delay: 50,
    ...config,
  });
  console.log(`  Configured ${scenarios.length} scenarios`);

  const wbClient = new WellBehavedClient({ host: 'localhost', port: FUZZ_PORT });
  let done = false;

  // Drive well-behaved client connections triggered by progress events.
  // When the server agent starts a new scenario it emits a 'progress' event;
  // we wait a short delay for the server to register its stream listener,
  // then connect. This avoids timing-based races where the client connects
  // before the scenario is ready or after it has timed out.
  let pendingConnect = null;
  const unsubProgress = controller.onEvent((role, event) => {
    if (done) return;
    if (event.type === 'progress') {
      // Small delay to let the server scenario register its stream listener
      pendingConnect = sleep(500).then(() => {
        if (done) return;
        return connectFn(wbClient).catch(() => {});
      });
    }
  });

  const { results, errors } = await collectResults(controller, scenarios.length, timeoutMs, () => { done = true; });

  done = true;
  unsubProgress();
  if (pendingConnect) await pendingConnect.catch(() => {});
  wbClient.stop();
  controller.disconnect();
  serverAgent.close();
  await sleep(500);

  printPhaseSummary(label + ' Server', results, scenarios.length, errors);
  return { results, errors };
}

async function collectResults(controller, total, timeoutMs, onDone) {
  const results = [];
  const errors = [];
  let done = false;
  let report = null;

  controller.onEvent((role, event) => {
    if (event.type === 'result') {
      const r = event.result;
      const icon = r.verdict === 'AS EXPECTED' ? '\x1b[32m✓\x1b[0m'
        : r.status === 'TIMEOUT' ? '\x1b[33m⏱\x1b[0m'
        : '\x1b[31m✗\x1b[0m';
      const pad = r.scenario.padEnd(50);
      console.log(`    ${icon} ${pad} ${r.status.padEnd(12)} ${r.verdict}`);
      results.push(r);
    } else if (event.type === 'error') {
      errors.push(event.message);
      console.log(`    \x1b[31mERROR: ${event.message}\x1b[0m`);
    } else if (event.type === 'report') {
      report = event.report;
    } else if (event.type === 'done') {
      done = true;
      if (onDone) onDone();
    }
  });

  await controller.runAll();
  console.log('  Running...');
  console.log('');

  const deadline = Date.now() + timeoutMs;
  while (!done && Date.now() < deadline) {
    await sleep(500);
  }
  if (!done) console.log('  \x1b[33mWarning: phase timed out\x1b[0m');

  return { results, errors, report };
}

function printPhaseSummary(label, results, total, errors) {
  const passed = results.filter(r => r.verdict === 'AS EXPECTED').length;
  const unexpected = results.filter(r => r.verdict === 'UNEXPECTED').length;
  const errCount = results.filter(r => r.status === 'ERROR').length;
  const timeouts = results.filter(r => r.status === 'TIMEOUT').length;

  console.log('');
  console.log(`  \x1b[1m${label}:\x1b[0m ${results.length}/${total} ran` +
    ` | \x1b[32m${passed} expected\x1b[0m` +
    ` | \x1b[31m${unexpected} unexpected\x1b[0m` +
    ` | \x1b[33m${errCount} errors\x1b[0m` +
    ` | \x1b[33m${timeouts} timeouts\x1b[0m`);
  if (errors.length > 0) console.log(`  \x1b[31mAgent errors: ${errors.length}\x1b[0m`);
  console.log('');
}

// ── Main ─────────────────────────────────────────────────────────────────

async function main() {
  const allResults = [];
  const allErrors = [];

  // Gather scenarios
  const tlsClient = SCENARIOS.filter(s => s.side === 'client' && !CATEGORY_DEFAULT_DISABLED.has(s.category));
  const tlsServer = SCENARIOS.filter(s => s.side === 'server' && !CATEGORY_DEFAULT_DISABLED.has(s.category));
  const h2Client = HTTP2_SCENARIOS.filter(s => s.side === 'client');
  const h2Server = HTTP2_SCENARIOS.filter(s => s.side === 'server');

  const totalScenarios = tlsClient.length + tlsServer.length + h2Client.length + h2Server.length;

  console.log('');
  console.log('  \x1b[1m\x1b[36mTLS + HTTP/2 Distributed Mode Test\x1b[0m');
  console.log('');
  console.log(`  TLS  client: ${tlsClient.length}   server: ${tlsServer.length}`);
  console.log(`  H2   client: ${h2Client.length}    server: ${h2Server.length}`);
  console.log(`  Total: ${totalScenarios}`);
  console.log('');

  // ── Phase 1: TLS Client ──────────────────────────────────────────────
  if (tlsClient.length > 0) {
    const r = await runClientPhase('TLS', tlsClient, 'tls',
      (srv) => srv.startTLS(), {}, 1800000);  // 30 min
    allResults.push(...r.results);
    allErrors.push(...r.errors);
  }

  // ── Phase 2: TLS Server ──────────────────────────────────────────────
  if (tlsServer.length > 0) {
    const r = await runServerPhase('TLS', tlsServer, 'tls',
      (client) => client.connectRawTLS(), {}, 600000);  // 10 min
    allResults.push(...r.results);
    allErrors.push(...r.errors);
  }

  // ── Phase 3: H2 Client ───────────────────────────────────────────────
  if (h2Client.length > 0) {
    const r = await runClientPhase('H2', h2Client, 'h2',
      (srv) => srv.startH2(), {}, 600000);  // 10 min
    allResults.push(...r.results);
    allErrors.push(...r.errors);
  }

  // ── Phase 4: H2 Server ───────────────────────────────────────────────
  if (h2Server.length > 0) {
    const r = await runServerPhase('H2', h2Server, 'h2',
      (client) => client.connectH2(), {}, 600000);  // 10 min
    allResults.push(...r.results);
    allErrors.push(...r.errors);
  }

  // ── Final Summary ────────────────────────────────────────────────────
  const passed = allResults.filter(r => r.verdict === 'AS EXPECTED').length;
  const unexpected = allResults.filter(r => r.verdict === 'UNEXPECTED').length;
  const errCount = allResults.filter(r => r.status === 'ERROR').length;

  console.log('  ════════════════════════════════════════════════════');
  console.log(`  \x1b[1mFinal: ${allResults.length}/${totalScenarios} scenarios ran\x1b[0m`);
  console.log(`    \x1b[32mAs expected: ${passed}\x1b[0m`);
  console.log(`    \x1b[31mUnexpected:  ${unexpected}\x1b[0m`);
  console.log(`    \x1b[33mErrors:      ${errCount}\x1b[0m`);
  if (allErrors.length > 0) console.log(`    \x1b[31mAgent errors: ${allErrors.length}\x1b[0m`);
  console.log('  ════════════════════════════════════════════════════');
  console.log('');

  if (errCount > 0 || allErrors.length > 0) {
    console.log('  \x1b[31mFAILED — there were errors\x1b[0m');
    process.exit(1);
  } else {
    console.log('  \x1b[1m\x1b[32mAll distributed tests complete.\x1b[0m');
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  console.error(err.stack);
  process.exit(1);
});
