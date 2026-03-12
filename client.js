#!/usr/bin/env node
// TLS/TCP Protocol Fuzzer — Standalone Client
// Run client-side fuzzing scenarios independently against any target

const { UnifiedClient } = require('./lib/unified-client');
const { Logger } = require('./lib/logger');
const { getScenario, getScenariosByCategory, getClientScenarios, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { getHttp2Scenario, getHttp2ScenariosByCategory, listHttp2ClientScenarios } = require('./lib/http2-scenarios');
const { getQuicScenario, getQuicScenariosByCategory, listQuicClientScenarios } = require('./lib/quic-scenarios');
const { getTcpScenario, getTcpScenariosByCategory, getTcpClientScenarios } = require('./lib/tcp-scenarios');
const { isRawAvailable } = require('./lib/raw-tcp');

const USAGE = `
  TLS/TCP Protocol Fuzzer — Client Mode

  Starts a client agent with an HTTP control channel, or runs
  client-side fuzzing scenarios directly against a target TLS server.

  Usage:
    node client.js                          Start client agent (control on 0.0.0.0:9200)
    node client.js <host> <port> [options]  Run scenarios directly

  Agent options:
    --control-port <port>   Agent control port (default: 9200)
    --token <string>        Authentication token for agent mode

  Direct-run options:
    --scenario <name|all>   Run specific scenario or all client scenarios
    --category <A-Z|RA-RG>  Run all scenarios in a category
    --protocol <tls|raw-tcp|h2|quic> Protocol type (default: tls)
    --delay <ms>            Delay between actions (default: 100)
    --timeout <ms>          Connection timeout (default: 5000)
    --verbose               Show hex dumps of all packets
    --json                  Output results as JSON
    --pcap <file.pcap>      Record packets to PCAP file

  Examples:
    node client.js
    node client.js google.com 443 --scenario all
    node client.js example.com 443 --scenario syn-flood-100 --protocol raw-tcp
    node client.js 192.168.1.100 443 --category RA --protocol raw-tcp --pcap fuzz.pcap
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      if (key === 'verbose' || key === 'json') {
        args[key] = true;
      } else if (i + 1 < argv.length) {
        args[key] = argv[++i];
      }
    } else {
      args._.push(argv[i]);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const host = args._[0];
  const port = parseInt(args._[1]);

  // Agent mode — no host/port args means start the control channel
  if (!host || !port) {
    const controlPort = parseInt(args['control-port']) || 9200;
    const token = args['token'] || null;
    const { startAgent } = require('./lib/agent');
    startAgent('client', { controlPort, token });
    process.on('SIGINT', () => process.exit(0));
    return;
  }

  if (port < 1 || port > 65535) {
    console.log(USAGE);
    process.exit(1);
  }

  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 5000;
  const pcapFile = args.pcap || null;
  const protocol = args.protocol || 'tls';
  const useRawTcp = protocol === 'raw-tcp';

  if (useRawTcp && !isRawAvailable()) {
    console.warn('\x1b[33mWarning: Raw sockets not available. Requires CAP_NET_RAW on Linux.\x1b[0m');
  }

  console.log('');
  console.log('  \x1b[1m\x1b[36mTLS/TCP Protocol Fuzzer — Client\x1b[0m');
  console.log('');
  console.log(`  \x1b[90mTarget\x1b[0m        ${host}:${port}`);
  console.log(`  \x1b[90mProtocol\x1b[0m      ${protocol}`);
  console.log('');

  // Determine which scenarios to run
  let scenarios;
  if (args.category) {
    const cat = args.category.toUpperCase();
    if (useRawTcp) scenarios = getTcpScenariosByCategory(cat);
    else if (protocol === 'h2') scenarios = getHttp2ScenariosByCategory(cat);
    else if (protocol === 'quic') scenarios = getQuicScenariosByCategory(cat);
    else scenarios = getScenariosByCategory(cat);

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
      console.error(`Scenario "${args.scenario}" is a server-side scenario.`);
      process.exit(1);
    }
    scenarios = [s];
  } else {
    console.error('Error: specify --scenario <name|all> or --category <A-Z|RA-RG>');
    console.log(USAGE);
    process.exit(1);
  }

  console.log(`  \x1b[90mScenarios\x1b[0m     ${scenarios.length} scenario(s) queued`);
  console.log('');

  const logger = new Logger({ verbose: args.verbose, json: args.json });
  const client = new UnifiedClient({ host, port, timeout, delay, logger, pcapFile });

  // Handle ctrl+c
  process.on('SIGINT', () => {
    client.abort();
    client.close();
    process.exit(0);
  });

  const { results, report } = await client.runScenarios(scenarios);
  client.close();

  if (pcapFile) {
    logger.info(`PCAP saved to: ${pcapFile}`);
  }

  // Exit with non-zero if any failures, errors, or host went down
  const hasErrors = results.some(r => r.status === 'ERROR');
  const hostWentDown = results.some(r => r.hostDown);
  const hasFails = report && report.stats.fail > 0;
  process.exit(hasErrors || hostWentDown || hasFails ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
