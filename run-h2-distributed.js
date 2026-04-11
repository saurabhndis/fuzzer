#!/usr/bin/env node
// Run all HTTP/2 scenarios in distributed mode (client + server on localhost)
// with PCAP capture. Reports timeouts and sync issues.

const { UnifiedClient } = require('./lib/unified-client');
const { UnifiedServer } = require('./lib/unified-server');
const { WellBehavedClient } = require('./lib/well-behaved-client');
const { HTTP2_SCENARIOS } = require('./lib/http2-scenarios');
const { Logger } = require('./lib/logger');
const { computeOverallGrade } = require('./lib/grader');

const FUZZER_PORT = 4433;
const PCAP_FILE = 'dist-h2-all.pcap';

// Prevent unhandled H2 stream errors from crashing the process
// (expected when the server switches from H2 to raw TCP mode between scenarios)
process.on('uncaughtException', (err) => {
  if (err.code === 'ERR_HTTP2_STREAM_ERROR' || err.code === 'ERR_HTTP2_ERROR') return;
  console.error(`\n  Uncaught exception: ${err.message}`);
  console.error(err.stack);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  if (reason && reason.code && reason.code.startsWith('ERR_HTTP2_')) return;
  console.error(`\n  Unhandled rejection: ${reason}`);
});

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  const clientScenarios = HTTP2_SCENARIOS.filter(s => s.side === 'client');
  const serverScenarios = HTTP2_SCENARIOS.filter(s => s.side === 'server');

  console.log(`\n  HTTP/2 Distributed Test Run`);
  console.log(`  ═══════════════════════════════════════`);
  console.log(`  Total scenarios:  ${HTTP2_SCENARIOS.length}`);
  console.log(`  Client-side:      ${clientScenarios.length}`);
  console.log(`  Server-side:      ${serverScenarios.length}`);
  console.log(`  PCAP file:        ${PCAP_FILE}`);
  console.log(`  Fuzzer port:      ${FUZZER_PORT}`);
  console.log(`  ═══════════════════════════════════════\n`);

  const allResults = [];
  let timeouts = 0;
  let errors = 0;
  let passed = 0;

  // ── Phase 1: Client-side scenarios ──────────────────────────────────────
  // Start a passive H2 server, then run client scenarios against it
  console.log(`  ── Phase 1: Client-side scenarios (${clientScenarios.length}) ──\n`);

  const serverLogger = new Logger({ verbose: false, json: false, quiet: true });
  const server = new UnifiedServer({
    port: FUZZER_PORT, hostname: 'localhost', bindAddress: '::',
    timeout: 10000, delay: 50, logger: serverLogger,
  });
  await server.startH2();
  console.log(`  H2 server started on port ${FUZZER_PORT}`);

  const clientLogger = new Logger({ verbose: false, json: false, quiet: true });
  const client = new UnifiedClient({
    host: '127.0.0.1', port: FUZZER_PORT,
    timeout: 10000, delay: 50, logger: clientLogger,
    pcapFile: PCAP_FILE, mergePcap: true,
  });

  // Run client-side scenarios
  for (let i = 0; i < clientScenarios.length; i++) {
    const scenario = clientScenarios[i];
    const result = await client.runScenario(scenario);
    allResults.push(result);

    if (result.status === 'TIMEOUT') timeouts++;
    else if (result.status === 'ERROR') errors++;
    else passed++;

    const isPass = ['PASSED', 'DROPPED', 'CONNECTED'].includes(result.status);
    const icon = isPass ? '✓' : result.status === 'TIMEOUT' ? '⏱' : '✗';
    const color = isPass ? '\x1b[32m' : result.status === 'TIMEOUT' ? '\x1b[33m' : '\x1b[31m';
    console.log(`  ${color}${icon}\x1b[0m [${i+1}/${clientScenarios.length}] ${result.scenario}: ${result.status} — ${(result.response || '').slice(0, 80)}`);
  }

  client.close();
  server.abort();
  // Close H2 server
  if (server.h2Server) { try { server.h2Server.close(); } catch (_) {} }
  await sleep(500);

  // ── Phase 2: Server-side scenarios ──────────────────────────────────────
  // Start H2 fuzzer server, run each scenario, have a well-behaved client connect
  console.log(`\n  ── Phase 2: Server-side scenarios (${serverScenarios.length}) ──\n`);

  const srvFuzzLogger = new Logger({ verbose: false, json: false, quiet: true });
  const srvFuzzer = new UnifiedServer({
    port: FUZZER_PORT, hostname: 'localhost', bindAddress: '::',
    timeout: 10000, delay: 50, logger: srvFuzzLogger,
    pcapFile: PCAP_FILE, mergePcap: true,
  });

  // Start H2 server for server-side scenarios
  await srvFuzzer.startH2();
  console.log(`  H2 fuzzer server started on port ${FUZZER_PORT}`);

  for (let i = 0; i < serverScenarios.length; i++) {
    const scenario = serverScenarios[i];

    // Connect with well-behaved client when server signals it's listening
    const wbClientLogger = new Logger({ verbose: false, json: false, quiet: true });
    const wbClient = new WellBehavedClient({
      host: '127.0.0.1', port: FUZZER_PORT, logger: wbClientLogger,
    });

    // When the server is ready for this scenario, connect the client after a brief delay
    srvFuzzer._onListening = () => {
      srvFuzzer._onListening = null;
      setTimeout(async () => {
        try { await wbClient.connectH2(); } catch (_) {}
      }, 200);
    };

    // Run server scenario (waits for client to connect)
    const result = await srvFuzzer.runScenario(scenario);
    try { wbClient.stop(); } catch (_) {}
    await sleep(200); // let H2 streams drain before next scenario

    allResults.push(result);

    if (result.status === 'TIMEOUT') timeouts++;
    else if (result.status === 'ERROR') errors++;
    else passed++;

    const isPass = ['PASSED', 'DROPPED', 'CONNECTED'].includes(result.status);
    const icon = isPass ? '✓' : result.status === 'TIMEOUT' ? '⏱' : '✗';
    const color = isPass ? '\x1b[32m' : result.status === 'TIMEOUT' ? '\x1b[33m' : '\x1b[31m';
    console.log(`  ${color}${icon}\x1b[0m [${i+1}/${serverScenarios.length}] ${result.scenario}: ${result.status} — ${(result.response || '').slice(0, 80)}`);
  }

  srvFuzzer.abort();
  if (srvFuzzer.h2Server) { try { srvFuzzer.h2Server.close(); } catch (_) {} }
  await sleep(500);

  // ── Summary ─────────────────────────────────────────────────────────────
  console.log(`\n  ═══════════════════════════════════════`);
  console.log(`  RESULTS SUMMARY`);
  console.log(`  ═══════════════════════════════════════`);
  console.log(`  Total:    ${allResults.length}/${HTTP2_SCENARIOS.length}`);
  console.log(`  Passed:   ${passed}`);
  console.log(`  Timeouts: ${timeouts}`);
  console.log(`  Errors:   ${errors}`);
  console.log(`  PCAP:     ${PCAP_FILE}`);

  if (timeouts > 0) {
    console.log(`\n  ⏱ TIMEOUT SCENARIOS:`);
    for (const r of allResults.filter(r => r.status === 'TIMEOUT')) {
      console.log(`    - ${r.scenario}: ${r.response || 'No response'}`);
    }
  }
  if (errors > 0) {
    console.log(`\n  ✗ ERROR SCENARIOS:`);
    for (const r of allResults.filter(r => r.status === 'ERROR')) {
      console.log(`    - ${r.scenario}: ${r.response || 'Unknown error'}`);
    }
  }

  const grade = computeOverallGrade(allResults);
  console.log(`\n  Grade: ${grade.grade} (${grade.score}%)`);
  console.log(`  ═══════════════════════════════════════\n`);

  process.exit(timeouts > 0 || errors > 0 ? 1 : 0);
}

main().catch(e => {
  console.error(`Fatal: ${e.message}`);
  console.error(e.stack);
  process.exit(1);
});
