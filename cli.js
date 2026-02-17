#!/usr/bin/env node
// TLS/TCP Protocol Fuzzer — CLI Entry Point

const { FuzzerClient } = require('./lib/fuzzer-client');
const { FuzzerServer } = require('./lib/fuzzer-server');
const { Logger } = require('./lib/logger');
const { listScenarios, getScenario, getScenariosByCategory, getClientScenarios, getServerScenarios } = require('./lib/scenarios');

const USAGE = `
  TLS/TCP Protocol Fuzzer

  Usage:
    node cli.js client <host> <port> [options]
    node cli.js server <port> [options]
    node cli.js list

  Options:
    --scenario <name|all>   Run specific scenario or all
    --category <A-M>        Run all scenarios in a category
    --delay <ms>            Delay between actions (default: 100)
    --timeout <ms>          Connection timeout (default: 5000)
    --verbose               Show hex dumps of all packets
    --json                  Output results as JSON
    --pcap <file.pcap>      Record packets to PCAP file

  Examples:
    node cli.js list
    node cli.js client google.com 443 --scenario duplicate-client-hello --verbose
    node cli.js client google.com 443 --category D --verbose --pcap fuzz.pcap
    node cli.js client google.com 443 --scenario all
    node cli.js server 4433 --scenario server-hello-before-client-hello
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
      console.log(`  \x1b[1m\x1b[35m${cat}: ${label}\x1b[0m (${items.length} scenarios)`);
      for (const s of items) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }
    process.exit(0);
  }

  const logger = new Logger({ verbose: args.verbose, json: args.json });
  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 5000;
  const pcapFile = args.pcap || null;

  if (command === 'client') {
    const host = args._[1];
    const port = parseInt(args._[2]);
    if (!host || !port) {
      console.error('Error: client requires <host> <port>');
      console.log(USAGE);
      process.exit(1);
    }

    // Determine which scenarios to run
    let scenarios;
    if (args.category) {
      scenarios = getScenariosByCategory(args.category).filter(s => s.side === 'client');
      if (scenarios.length === 0) {
        console.error(`No client scenarios in category ${args.category}`);
        process.exit(1);
      }
    } else if (args.scenario === 'all') {
      scenarios = getClientScenarios();
    } else if (args.scenario) {
      const s = getScenario(args.scenario);
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
      console.error('Error: specify --scenario <name|all> or --category <A-H>');
      console.log(USAGE);
      process.exit(1);
    }

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

  } else if (command === 'server') {
    const port = parseInt(args._[1]);
    if (!port) {
      console.error('Error: server requires <port>');
      console.log(USAGE);
      process.exit(1);
    }

    let scenarios;
    if (args.category) {
      scenarios = getScenariosByCategory(args.category).filter(s => s.side === 'server');
    } else if (args.scenario === 'all') {
      scenarios = getServerScenarios();
    } else if (args.scenario) {
      const s = getScenario(args.scenario);
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
      console.error('Error: specify --scenario <name|all> or --category <A-H>');
      console.log(USAGE);
      process.exit(1);
    }

    const server = new FuzzerServer({ port, timeout, delay, logger, pcapFile });

    process.on('SIGINT', () => {
      server.abort();
      process.exit(0);
    });

    const results = await server.runScenarios(scenarios);
    process.exit(0);

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
