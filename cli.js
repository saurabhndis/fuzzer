#!/usr/bin/env node
// TLS/TCP Protocol Fuzzer — CLI Entry Point

const { FuzzerClient } = require('./lib/fuzzer-client');
const { FuzzerServer } = require('./lib/fuzzer-server');
const { UnifiedClient } = require('./lib/unified-client');
const { UnifiedServer } = require('./lib/unified-server');
const { Logger } = require('./lib/logger');
const { runBaseline } = require('./lib/baseline');
const { listScenarios, getScenario, getScenariosByCategory, getClientScenarios, getServerScenarios, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { listHttp2Scenarios, getHttp2Scenario, getHttp2ScenariosByCategory, listHttp2ClientScenarios, listHttp2ServerScenarios } = require('./lib/http2-scenarios');
const { listQuicScenarios, getQuicScenario, getQuicScenariosByCategory, listQuicClientScenarios, listQuicServerScenarios } = require('./lib/quic-scenarios');
const { getTcpScenario, getTcpScenariosByCategory, getTcpClientScenarios, getTcpServerScenarios, listTcpScenarios, TCP_CATEGORIES } = require('./lib/tcp-scenarios');
const { isRawAvailable } = require('./lib/raw-tcp');
const { generateServerCert } = require('./lib/cert-gen');

const USAGE = `
  TLS/TCP Protocol Fuzzer

  Usage:
    node cli.js client <host> <port> [options]
    node cli.js server <port> [options]
    node cli.js list
    node cli.js pcap-tests                    List saved PCAP-based tests
    node cli.js verify-pcap-test <name>       Mark a PCAP test as verified
    node cli.js delete-pcap-test <name>       Delete a PCAP test

  Options:
    --scenario <name|all>   Run specific scenario or all
    --category <A-Y|PCAP>   Run all scenarios in a category (PCAP = pcap-based tests)
    --hostname <name>       Server cert CN/SAN (default: localhost)
    --delay <ms>            Delay between actions (default: 100)
    --timeout <ms>          Connection timeout (default: 5000)
    --protocol <type>       Protocol: tls (default), h2, quic, raw-tcp
    --verbose               Show hex dumps of all packets
    --json                  Output results as JSON
    --pcap <file.pcap>      Record packets to PCAP file
    --merge-pcap            Merge all scenarios into a single PCAP file
    --ingest-pcap <file>    Ingest PCAP, save as test, and run it
    --pcap-stream <index>   Select a specific stream from the PCAP (default: 0)
    --list-streams          List all streams found in the PCAP
    --pcap-name <name>      Custom name for the saved PCAP test
    --no-save               Don't save the ingested PCAP test (run only)
    --distributed           Run ingested PCAP scenario in distributed mode (requires agents)
    --client-agent <h:p>    Client agent host:port for distributed mode (default: localhost:9200)
    --server-agent <h:p>    Server agent host:port for distributed mode (default: localhost:9201)
    --no-baseline           Skip OpenSSL/baseline comparison testing

  PCAP Test Workflow:
    1. Ingest:  node cli.js client host 443 --ingest-pcap capture.pcap
    2. List:    node cli.js pcap-tests
    3. Run:     node cli.js client host 443 --scenario pcap-tls-session-0
    4. Verify:  node cli.js verify-pcap-test pcap-tls-session-0
    5. Run all: node cli.js client host 443 --category PCAP

  Examples:
    node cli.js list
    node cli.js client google.com 443 --scenario duplicate-client-hello --verbose
    node cli.js client google.com 443 --category D --verbose --pcap fuzz.pcap
    node cli.js client google.com 443 --scenario all
    node cli.js server 4433 --scenario server-hello-before-client-hello
    node cli.js client example.com 443 --ingest-pcap capture.pcap
    node cli.js client example.com 443 --ingest-pcap capture.pcap --distributed
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      if (key === 'verbose' || key === 'json' || key === 'merge-pcap' || key === 'distributed' || key === 'list-streams' || key === 'no-save') {
        args[key] = true;
      } else if (key === 'no-baseline') {
        args.baseline = false;
      } else if (i + 1 < argv.length) {
        args[key] = argv[++i];
      }
    } else {
      args._.push(argv[i]);
    }
  }
  
  // Default baseline to true only for TLS protocol
  const protocol = args.protocol || 'tls';
  if (args.baseline === undefined) {
    args.baseline = (protocol === 'tls');
  }

  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (!command || command === 'help') {
    console.log(USAGE);
    process.exit(0);
  }

  if (command === 'list') {
    const { categories, scenarios } = listScenarios();
    console.log('\n  TLS/TCP Fuzzer — Available Scenarios\n');
    for (const [cat, label] of Object.entries(categories)) {
      const items = scenarios[cat] || [];
      const disabledNote = CATEGORY_DEFAULT_DISABLED.has(cat) ? ' \x1b[33m[opt-in]\x1b[0m' : '';
      console.log(`  \x1b[1m\x1b[35m${cat}: ${label}\x1b[0m (${items.length} scenarios)${disabledNote}`);
      for (const s of items) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }

    // HTTP/2 scenarios
    const h2Groups = listHttp2Scenarios();
    console.log('  \x1b[1m\x1b[33mHTTP/2 Scenarios\x1b[0m\n');
    for (const [cat, items] of Object.entries(h2Groups.scenarios)) {
      console.log(`  \x1b[1m\x1b[35m${cat}: ${h2Groups.categories[cat]}\x1b[0m (${items.length} scenarios)`);
      for (const s of items) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }

    // QUIC scenarios
    const quicGroups = listQuicScenarios();
    console.log('  \x1b[1m\x1b[33mQUIC Scenarios\x1b[0m\n');
    for (const [cat, items] of Object.entries(quicGroups.scenarios)) {
      console.log(`  \x1b[1m\x1b[35m${cat}: ${quicGroups.categories[cat]}\x1b[0m (${items.length} scenarios)`);
      for (const s of items) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }

    // TCP scenarios
    const tcpGroups = listTcpScenarios();
    const rawStatus = isRawAvailable() ? '\x1b[32m[available]\x1b[0m' : '\x1b[31m[unavailable — needs CAP_NET_RAW]\x1b[0m';
    console.log(`  \x1b[1m\x1b[33mRaw TCP Scenarios\x1b[0m ${rawStatus}\n`);
    for (const [cat, group] of Object.entries(tcpGroups)) {
      console.log(`  \x1b[1m\x1b[35m${cat}: ${group.label}\x1b[0m (${group.scenarios.length} scenarios) \x1b[33m[opt-in]\x1b[0m`);
      for (const s of group.scenarios) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }
    process.exit(0);
  }

  // ─── PCAP Test Management Commands ──────────────────────────────────────
  if (command === 'pcap-tests') {
    const { listPcapTests, PCAP_TESTS_DIR } = require('./lib/pcap-scenarios');
    const tests = listPcapTests({ includePending: true });
    console.log(`\n  PCAP-Based Tests (${tests.length} saved in ${PCAP_TESTS_DIR})\n`);
    if (tests.length === 0) {
      console.log('  No PCAP tests saved yet.');
      console.log('  Use: node cli.js client <host> <port> --ingest-pcap <file.pcap>\n');
    } else {
      for (const t of tests) {
        const statusColor = t.meta.status === 'verified' ? '\x1b[32m' : '\x1b[33m';
        const statusTag = `${statusColor}[${t.meta.status}]\x1b[0m`;
        const natTag = t.scenario.pcapParams?.natMerged ? ' \x1b[33m[NAT]\x1b[0m' : '';
        console.log(`  ${statusTag} ${t.name}${natTag}`);
        console.log(`    ${t.meta.description}`);
        console.log(`    Created: ${t.meta.createdAt}${t.meta.verifiedAt ? ` | Verified: ${t.meta.verifiedAt}` : ''}`);
        if (t.meta.sourceFile) console.log(`    Source: ${t.meta.sourceFile} (stream ${t.meta.streamIndex})`);
        console.log('');
      }
      const pending = tests.filter(t => t.meta.status === 'pending').length;
      const verified = tests.filter(t => t.meta.status === 'verified').length;
      console.log(`  Summary: ${verified} verified, ${pending} pending`);
      if (pending > 0) {
        console.log(`  To verify: node cli.js verify-pcap-test <name>`);
      }
      console.log(`  To run:    node cli.js client <host> <port> --scenario <name>`);
      console.log(`  To run all: node cli.js client <host> <port> --category PCAP\n`);
    }
    process.exit(0);
  }

  if (command === 'verify-pcap-test') {
    const testName = args._[1];
    if (!testName) {
      console.error('Usage: node cli.js verify-pcap-test <name>');
      process.exit(1);
    }
    const { verifyPcapTest, getPcapTestInfo } = require('./lib/pcap-scenarios');
    const info = getPcapTestInfo(testName);
    if (!info) {
      console.error(`PCAP test not found: ${testName}`);
      console.error('Use: node cli.js pcap-tests  to list available tests');
      process.exit(1);
    }
    if (info.status === 'verified') {
      console.log(`\x1b[33m  Test "${testName}" is already verified.\x1b[0m`);
      process.exit(0);
    }
    const ok = verifyPcapTest(testName);
    if (ok) {
      console.log(`\x1b[32m  ✓ Test "${testName}" marked as verified.\x1b[0m`);
      console.log(`  It will now appear in --category PCAP and --scenario all.`);
    } else {
      console.error(`  Failed to verify test "${testName}".`);
      process.exit(1);
    }
    process.exit(0);
  }

  if (command === 'delete-pcap-test') {
    const testName = args._[1];
    if (!testName) {
      console.error('Usage: node cli.js delete-pcap-test <name>');
      process.exit(1);
    }
    const { deletePcapTest } = require('./lib/pcap-scenarios');
    const ok = deletePcapTest(testName);
    if (ok) {
      console.log(`\x1b[32m  ✓ Test "${testName}" deleted.\x1b[0m`);
    } else {
      console.error(`  Test "${testName}" not found.`);
      process.exit(1);
    }
    process.exit(0);
  }

  const logger = new Logger({ verbose: args.verbose, json: args.json });
  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 5000;
  const pcapFile = args.pcap || null;
  const mergePcap = args['merge-pcap'] || false;
  let protocol = args.protocol || 'tls';

  if (command === 'client') {
    const host = args._[1];
    const port = parseInt(args._[2]);
    if (!host || !port) {
      console.error('Error: client requires <host> <port>');
      console.log(USAGE);
      process.exit(1);
    }

    const useRawTcp = protocol === 'raw-tcp';

    if (useRawTcp && !isRawAvailable()) {
      console.error('\x1b[33mWarning: Raw sockets not available. Requires CAP_NET_RAW on Linux.\x1b[0m');
      console.error('  Run: sudo setcap cap_net_raw+ep $(which node)');
      console.error('  Raw TCP scenarios will be skipped.\n');
    }

    // Determine which scenarios to run
    let scenarios;
    if (args['ingest-pcap']) {
      const { parsePcapToScenario, readPcap, groupStreams, analyzeStream } = require('./lib/pcap-parser');
      try {
        const streamIdx = parseInt(args['pcap-stream'] || 0);
        if (args['list-streams']) {
          const packets = readPcap(args['ingest-pcap']);
          const streams = groupStreams(packets);
          const natCount = streams.filter(s => s.natMerged).length;
          console.log(`\n  Streams found in ${args['ingest-pcap']}: (${streams.length} streams${natCount > 0 ? `, ${natCount} NAT-merged` : ''})\n`);
          streams.forEach((s, idx) => {
            const analysis = analyzeStream(s);
            if (analysis.natMerged) {
              console.log(`    \x1b[33m[${idx}]\x1b[0m ${analysis.description}`);
            } else {
              console.log(`    [${idx}] ${analysis.description}`);
            }
          });
          if (natCount > 0) {
            console.log(`\n  \x1b[33mNote:\x1b[0m ${natCount} stream(s) were auto-merged from NAT-split captures.`);
            console.log(`  Streams marked \x1b[33m[NAT-merged]\x1b[0m had client/server traffic with different IPs (NAT rewrite).`);
          }
          process.exit(0);
        }
        const scenario = parsePcapToScenario(args['ingest-pcap'], streamIdx);
        console.log(`\x1b[32m  Ingested scenario from PCAP: ${scenario.description}\x1b[0m`);
        console.log(`\x1b[90m  Explanation: ${scenario.explanation}\x1b[0m\n`);

        // ── Auto-save the PCAP test (unless --no-save) ─────────────────
        if (!args['no-save']) {
          const { savePcapTest } = require('./lib/pcap-scenarios');
          const saved = savePcapTest(scenario, {
            hostname: host,
            sourceFile: args['ingest-pcap'],
            streamIndex: streamIdx,
            name: args['pcap-name'] || scenario.name,
          });
          console.log(`\x1b[36m  Saved PCAP test: ${saved.name}\x1b[0m`);
          console.log(`\x1b[90m  File: ${saved.filePath}\x1b[0m`);
          console.log(`\x1b[90m  Status: pending (run and verify to add to suite permanently)\x1b[0m`);
          console.log(`\x1b[90m  Verify: node cli.js verify-pcap-test ${saved.name}\x1b[0m\n`);
        }

        // ── Distributed mode: serialize and push to remote agents ──────
        if (args.distributed) {
          const { serializePcapScenario } = require('./lib/pcap-parser');
          const http = require('http');

          // Parse agent addresses
          const clientAgentStr = args['client-agent'] || 'localhost:9200';
          const serverAgentStr = args['server-agent'] || 'localhost:9201';
          const [clientAgentHost, clientAgentPort] = clientAgentStr.split(':');
          const [serverAgentHost, serverAgentPort] = serverAgentStr.split(':');

          const serialized = serializePcapScenario(scenario, { hostname: host });
          console.log(`  \x1b[36mDistributed mode:\x1b[0m pushing scenario to agents...`);
          console.log(`    Client agent: ${clientAgentHost}:${clientAgentPort}`);
          console.log(`    Server agent: ${serverAgentHost}:${serverAgentPort}`);
          console.log(`    Client actions: ${serialized.clientActions.length}`);
          console.log(`    Server actions: ${serialized.serverActions.length}\n`);

          // Helper for HTTP requests
          function agentRequest(agentHost, agentPort, method, urlPath, body, reqTimeout = 30000) {
            return new Promise((resolve, reject) => {
              const payload = body ? JSON.stringify(body) : null;
              const opts = {
                hostname: agentHost, port: parseInt(agentPort), path: urlPath, method, timeout: reqTimeout,
                headers: { 'Content-Type': 'application/json' },
              };
              if (payload) opts.headers['Content-Length'] = Buffer.byteLength(payload);
              const req = http.request(opts, (res) => {
                let buf = '';
                res.on('data', d => buf += d);
                res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
              });
              req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
              req.on('error', reject);
              if (payload) req.write(payload);
              req.end();
            });
          }

          try {
            // Stop any running tests
            try { await agentRequest(clientAgentHost, clientAgentPort, 'POST', '/stop', {}); } catch (_) {}
            try { await agentRequest(serverAgentHost, serverAgentPort, 'POST', '/stop', {}); } catch (_) {}
            await new Promise(r => setTimeout(r, 500));

            // Configure server agent
            const serverConfig = await agentRequest(serverAgentHost, serverAgentPort, 'POST', '/configure', {
              config: { host, port, hostname: host, protocol: scenario.protocol || 'tls', workers: 1, timeout, delay, baseline: false },
              scenarios: [],
              pcapScenarios: [{ ...serialized, name: serialized.name + '-server', side: 'server' }],
            });
            console.log(`  Server configured: ${serverConfig.scenarioCount} scenario(s)`);

            // Configure client agent
            const clientConfig = await agentRequest(clientAgentHost, clientAgentPort, 'POST', '/configure', {
              config: { host, port, protocol: scenario.protocol || 'tls', workers: 1, timeout, delay, baseline: false },
              scenarios: [],
              pcapScenarios: [{ ...serialized, name: serialized.name + '-client', side: 'client' }],
            });
            console.log(`  Client configured: ${clientConfig.scenarioCount} scenario(s)`);

            // Run server first, then client (stepped mode)
            console.log(`\n  Running scenario in distributed mode...\n`);
            const serverRunPromise = agentRequest(serverAgentHost, serverAgentPort, 'POST', '/run-scenario', { index: 0 }, 120000)
              .catch(err => ({ error: err.message }));
            await new Promise(r => setTimeout(r, 500));
            const clientRunPromise = agentRequest(clientAgentHost, clientAgentPort, 'POST', '/run-scenario', { index: 0 }, 120000)
              .catch(err => ({ error: err.message }));

            const [serverResult, clientResult] = await Promise.all([serverRunPromise, clientRunPromise]);

            // Finish
            try { await agentRequest(serverAgentHost, serverAgentPort, 'POST', '/finish', {}); } catch (_) {}
            try { await agentRequest(clientAgentHost, clientAgentPort, 'POST', '/finish', {}); } catch (_) {}
            await new Promise(r => setTimeout(r, 500));

            // Collect results
            let clientResults = [], serverResults = [];
            try { clientResults = await agentRequest(clientAgentHost, clientAgentPort, 'GET', '/results', null); } catch (_) {}
            try { serverResults = await agentRequest(serverAgentHost, serverAgentPort, 'GET', '/results', null); } catch (_) {}

            console.log(`  ═══════════════════════════════════════════════`);
            console.log(`  PCAP DISTRIBUTED RESULTS`);
            console.log(`  ═══════════════════════════════════════════════`);
            console.log(`  Client results: ${Array.isArray(clientResults) ? clientResults.length : 0}`);
            if (Array.isArray(clientResults)) {
              for (const r of clientResults) console.log(`    ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status} ${r.response || ''}`);
            }
            console.log(`  Server results: ${Array.isArray(serverResults) ? serverResults.length : 0}`);
            if (Array.isArray(serverResults)) {
              for (const r of serverResults) console.log(`    ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status} ${r.response || ''}`);
            }
            if (clientResult.error) console.log(`  Client error: ${clientResult.error}`);
            if (serverResult.error) console.log(`  Server error: ${serverResult.error}`);
            console.log(`  ═══════════════════════════════════════════════\n`);

            // Cleanup
            try { await agentRequest(clientAgentHost, clientAgentPort, 'POST', '/stop', {}); } catch (_) {}
            try { await agentRequest(serverAgentHost, serverAgentPort, 'POST', '/stop', {}); } catch (_) {}
          } catch (err) {
            console.error(`  Distributed mode failed: ${err.message}`);
            console.error(`  Make sure agents are running:`);
            console.error(`    Client: node cli.js client-agent --control-port ${clientAgentPort}`);
            console.error(`    Server: node cli.js server-agent --control-port ${serverAgentPort}`);
          }
          process.exit(0);
        }

        // ── Local mode (default) ───────────────────────────────────────
        scenarios = [scenario];
        protocol = scenario.protocol || protocol;
      } catch (err) {
        console.error(`Failed to ingest PCAP: ${err.message}`);
        process.exit(1);
      }
    } else if (args.category) {
      if (useRawTcp) scenarios = getTcpScenariosByCategory(args.category);
      else if (protocol === 'h2') scenarios = getHttp2ScenariosByCategory(args.category);
      else if (protocol === 'quic') scenarios = getQuicScenariosByCategory(args.category);
      else scenarios = getScenariosByCategory(args.category);

      scenarios = scenarios.filter(s => s.side === 'client');
      if (scenarios.length === 0) {
        console.error(`No client scenarios in category ${args.category}`);
        process.exit(1);
      }
    } else if (args.scenario === 'all') {
      if (useRawTcp) {
        scenarios = getTcpClientScenarios();
      } else if (protocol === 'h2') {
        scenarios = listHttp2ClientScenarios();
      } else if (protocol === 'quic') {
        scenarios = listQuicClientScenarios();
      } else {
        scenarios = getClientScenarios().filter(s => !CATEGORY_DEFAULT_DISABLED.has(s.category));
      }
      if (scenarios.length === 0) {
        console.error('No enabled client scenarios found');
        process.exit(1);
      }
    } else if (args.scenario) {
      let s;
      if (useRawTcp) s = getTcpScenario(args.scenario);
      else if (protocol === 'h2') s = getHttp2Scenario(args.scenario);
      else if (protocol === 'quic') s = getQuicScenario(args.scenario);
      
      if (!s) s = getScenario(args.scenario);

      if (!s) {
        console.error(`Unknown scenario: ${args.scenario}`);
        process.exit(1);
      }
      if (s.side !== 'client') {
        console.error(`Scenario "${args.scenario}" is a server-side scenario. Use: node cli.js server`);
        process.exit(1);
      }
      scenarios = [s];
    } else {
      console.error('Error: specify --scenario <name|all> or --category <A-H|RA-RG>');
      console.log(USAGE);
      process.exit(1);
    }


    // Use UnifiedClient for raw-tcp (or h2/quic), FuzzerClient for plain TLS
    const client = (useRawTcp || protocol === 'h2' || protocol === 'quic')
      ? new UnifiedClient({ host, port, timeout, delay, logger, pcapFile, mergePcap })
      : new FuzzerClient({ host, port, timeout, delay, logger, pcapFile, mergePcap });

    const originalRunScenario = client.runScenario.bind(client);
    client.runScenario = async (scenario) => {
      if (args.baseline) {
        if (!logger.json) console.log(`\x1b[90m    [baseline] testing against local OpenSSL...\x1b[0m`);
        const baselineRes = await runBaseline(scenario, protocol);
        scenario._baselineResponse = baselineRes.response;
      }
      return originalRunScenario(scenario);
    };

    const originalResult = logger.result.bind(logger);
    logger.result = (scenarioName, status, response, verdict, expectedReason, hostDown, finding, compliance) => {
      const s = scenarios.find(x => x.name === scenarioName);
      const baselineResponse = s ? s._baselineResponse : null;
      if (!logger.json && baselineResponse) {
        if (baselineResponse === response) {
          console.log(`\x1b[32m    ✓ Response matches OpenSSL baseline\x1b[0m`);
        } else {
          console.log(`\x1b[33m    ⚠ Differs from OpenSSL! OpenSSL response: ${baselineResponse}\x1b[0m`);
        }
      }
      originalResult(scenarioName, status, response, verdict, expectedReason, hostDown, finding, compliance);
    };

    // Handle ctrl+c
    process.on('SIGINT', () => {
      client.abort();
      client.close();
      process.exit(0);
    });

    const { results, report } = await client.runScenarios(scenarios);
    
    // Send graceful shutdown signal to fuzzer server
    if (client.shutdown) {
      await client.shutdown(protocol);
    }
    
    client.close();

    if (pcapFile) {
      logger.info(`PCAP saved to: ${pcapFile}`);
    }

    // Exit with non-zero if any failures, errors, or host went down
    const hasErrors = results.some(r => r.status === 'ERROR');
    const hostWentDown = results.some(r => r.hostDown);
    const hasFails = report && report.stats.fail > 0;
    process.exit(hasErrors || hostWentDown || hasFails ? 1 : 0);

  } else if (command === 'server') {
    const port = parseInt(args._[1]);
    if (!port) {
      console.error('Error: server requires <port>');
      console.log(USAGE);
      process.exit(1);
    }

    const useRawTcp = protocol === 'raw-tcp';

    // Determine which scenarios to run
    let scenarios;
    if (args.category) {
      if (useRawTcp) scenarios = getTcpScenariosByCategory(args.category);
      else if (protocol === 'h2') scenarios = getHttp2ScenariosByCategory(args.category);
      else if (protocol === 'quic') scenarios = getQuicScenariosByCategory(args.category);
      else scenarios = getScenariosByCategory(args.category);

      scenarios = scenarios.filter(s => s.side === 'server');
    } else if (args.scenario === 'all') {
      if (useRawTcp) {
        scenarios = getTcpServerScenarios();
      } else if (protocol === 'h2') {
        scenarios = listHttp2ServerScenarios();
      } else if (protocol === 'quic') {
        scenarios = listQuicServerScenarios();
      } else {
        scenarios = getServerScenarios().filter(s => !CATEGORY_DEFAULT_DISABLED.has(s.category));
      }
      if (scenarios.length === 0) {
        console.error('No enabled server scenarios found');
        process.exit(1);
      }
    } else if (args.scenario) {
      let s;
      if (useRawTcp) s = getTcpScenario(args.scenario);
      else if (protocol === 'h2') s = getHttp2Scenario(args.scenario);
      else if (protocol === 'quic') s = getQuicScenario(args.scenario);
      
      if (!s) s = getScenario(args.scenario);

      if (!s) {
        console.error(`Unknown scenario: ${args.scenario}`);
        process.exit(1);
      }
      if (s.side !== 'server') {
        console.error(`Scenario "${args.scenario}" is a client-side scenario. Use: node cli.js client`);
        process.exit(1);
      }
      scenarios = [s];
    } else {
      console.error('Error: specify --scenario <name|all> or --category <A-H|RA-RG>');
      console.log(USAGE);
      process.exit(1);
    }

    const hostname = args.hostname || 'localhost';
    const certInfo = generateServerCert(hostname);
    const fp = (certInfo.fingerprint.match(/.{2}/g) || []).join(':').toUpperCase();
    logger.info(`Server certificate: CN=${hostname} | SHA256=${fp}`);

    // UnifiedServer handles all protocols and fallback logic
    const server = new UnifiedServer({
      port, hostname, timeout, delay, logger, pcapFile, mergePcap,
      cert: certInfo.certDER,
      certInfo,
    });

    const originalRunScenario = server.runScenario.bind(server);
    server.runScenario = async (scenario) => {
      if (args.baseline) {
        if (!logger.json) console.log(`\x1b[90m    [baseline] testing against local OpenSSL...\x1b[0m`);
        const baselineRes = await runBaseline(scenario, protocol);
        scenario._baselineResponse = baselineRes.response;
      }
      return originalRunScenario(scenario);
    };

    const originalResult = logger.result.bind(logger);
    logger.result = (scenarioName, status, response, verdict, expectedReason, hostDown, finding, compliance) => {
      const s = scenarios.find(x => x.name === scenarioName);
      const baselineResponse = s ? s._baselineResponse : null;
      if (!logger.json && baselineResponse) {
        if (baselineResponse === response) {
          console.log(`\x1b[32m    ✓ Response matches OpenSSL baseline\x1b[0m`);
        } else {
          console.log(`\x1b[33m    ⚠ Differs from OpenSSL! OpenSSL response: ${baselineResponse}\x1b[0m`);
        }
      }
      originalResult(scenarioName, status, response, verdict, expectedReason, hostDown, finding, compliance);
    };

    // Handle ctrl+c
    process.on('SIGINT', () => {
      server.abort();
      server.close();
      process.exit(0);
    });

    const { results, report } = await server.runScenarios(scenarios);
    server.close();

    if (pcapFile) {
      logger.info(`PCAP saved to: ${pcapFile}`);
    }

    const hasErrors = results.some(r => r.status === 'ERROR');
    const hasFails = report && report.stats.fail > 0;
    process.exit(hasErrors || hasFails ? 1 : 0);

  } else {
    console.error(`Unknown command: ${command}`);
    console.log(USAGE);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
