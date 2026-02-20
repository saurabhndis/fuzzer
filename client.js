#!/usr/bin/env node
// TLS/TCP Protocol Fuzzer — Standalone Client
// Run client-side fuzzing scenarios independently against any target

const { FuzzerClient } = require('./lib/fuzzer-client');
const { Logger } = require('./lib/logger');
const { getScenario, getScenariosByCategory, getClientScenarios, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');

const USAGE = `
  TLS/TCP Protocol Fuzzer — Client Mode

  Runs client-side fuzzing scenarios against a target TLS server.
  Connects to the target and sends fuzzed TLS handshake messages.

  Usage:
    node client.js <host> <port> [options]

  Options:
    --scenario <name|all>   Run specific scenario or all client scenarios
    --category <A-Y>        Run all scenarios in a category
    --delay <ms>            Delay between actions (default: 100)
    --timeout <ms>          Connection timeout (default: 5000)
    --verbose               Show hex dumps of all packets
    --json                  Output results as JSON
    --pcap <file.pcap>      Record packets to PCAP file
    --agent                 Run as remote agent (HTTP control server)
    --control-port <port>   Agent control port (default: 9100)

  Examples:
    node client.js google.com 443 --scenario all
    node client.js example.com 443 --scenario duplicate-client-hello --verbose
    node client.js 192.168.1.100 443 --category A --pcap fuzz.pcap
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      if (key === 'verbose' || key === 'json' || key === 'agent') {
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

  // Agent mode — start HTTP control server instead of running scenarios directly
  if (args.agent) {
    const controlPort = parseInt(args['control-port']) || 9100;
    const { startAgent } = require('./lib/agent');
    startAgent('client', { controlPort });
    process.on('SIGINT', () => process.exit(0));
    return;
  }

  const host = args._[0];
  const port = parseInt(args._[1]);

  if (!host || !port || port < 1 || port > 65535) {
    console.log(USAGE);
    process.exit(!host && !port ? 0 : 1);
  }

  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 5000;
  const pcapFile = args.pcap || null;

  console.log('');
  console.log('  \x1b[1m\x1b[36mTLS/TCP Protocol Fuzzer — Client\x1b[0m');
  console.log('');
  console.log(`  \x1b[90mTarget\x1b[0m        ${host}:${port}`);
  console.log('');

  // Determine which scenarios to run
  let scenarios;
  if (args.category) {
    scenarios = getScenariosByCategory(args.category).filter(s => s.side === 'client');
    if (scenarios.length === 0) {
      console.error(`No client scenarios in category ${args.category}`);
      process.exit(1);
    }
  } else if (args.scenario === 'all') {
    scenarios = getClientScenarios().filter(s => !CATEGORY_DEFAULT_DISABLED.has(s.category));
    if (scenarios.length === 0) {
      console.error('No enabled client scenarios found');
      process.exit(1);
    }
  } else if (args.scenario) {
    const s = getScenario(args.scenario);
    if (!s) {
      console.error(`Unknown scenario: ${args.scenario}`);
      process.exit(1);
    }
    if (s.side !== 'client') {
      console.error(`Scenario "${args.scenario}" is a server-side scenario. Use: node server.js`);
      process.exit(1);
    }
    scenarios = [s];
  } else {
    console.error('Error: specify --scenario <name|all> or --category <A-Y>');
    console.log(USAGE);
    process.exit(1);
  }

  console.log(`  \x1b[90mScenarios\x1b[0m     ${scenarios.length} scenario(s) queued`);
  console.log('');

  const logger = new Logger({ verbose: args.verbose, json: args.json });
  const client = new FuzzerClient({ host, port, timeout, delay, logger, pcapFile });

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
