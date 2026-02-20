#!/usr/bin/env node
// TLS/TCP Protocol Fuzzer — Standalone Server
// Run server-side fuzzing scenarios independently on any host

const { FuzzerServer } = require('./lib/fuzzer-server');
const { Logger } = require('./lib/logger');
const { getScenario, getScenariosByCategory, getServerScenarios, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { generateServerCert } = require('./lib/cert-gen');

const USAGE = `
  TLS/TCP Protocol Fuzzer — Server Mode

  Runs server-side fuzzing scenarios. Listens for incoming connections
  and responds with fuzzed TLS handshake messages using a baked-in
  self-signed certificate.

  Usage:
    node server.js <port> [options]

  Options:
    --scenario <name|all>   Run specific scenario or all server scenarios
    --category <A-Y>        Run all server scenarios in a category
    --hostname <name>       Certificate CN/SAN (default: localhost)
    --delay <ms>            Delay between actions (default: 100)
    --timeout <ms>          Connection timeout (default: 10000)
    --verbose               Show hex dumps of all packets
    --json                  Output results as JSON
    --pcap <file.pcap>      Record packets to PCAP file
    --agent                 Run as remote agent (HTTP control server)
    --control-port <port>   Agent control port (default: 9101)

  Examples:
    node server.js 4433 --scenario all --hostname evil.test --verbose
    node server.js 4433 --category W --hostname test.local
    node server.js 4433 --scenario cert-expired --verbose
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
    const controlPort = parseInt(args['control-port']) || 9101;
    const { startAgent } = require('./lib/agent');
    startAgent('server', { controlPort });
    process.on('SIGINT', () => process.exit(0));
    return;
  }

  const port = parseInt(args._[0]);

  if (!port || port < 1 || port > 65535) {
    console.log(USAGE);
    process.exit(port === undefined ? 0 : 1);
  }

  const hostname = args.hostname || 'localhost';
  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 10000;
  const pcapFile = args.pcap || null;

  // Generate self-signed certificate
  const certInfo = generateServerCert(hostname);
  const fp = certInfo.fingerprint;
  const fpFormatted = fp.match(/.{2}/g).join(':').toUpperCase();

  console.log('');
  console.log('  \x1b[1m\x1b[36mTLS/TCP Protocol Fuzzer — Server\x1b[0m');
  console.log('');
  console.log(`  \x1b[90mListening on\x1b[0m  0.0.0.0:${port}`);
  console.log(`  \x1b[90mCertificate\x1b[0m   CN=${hostname}`);
  console.log(`  \x1b[90mSHA256\x1b[0m        ${fpFormatted}`);
  console.log(`  \x1b[90mCert size\x1b[0m     ${certInfo.certDER.length} bytes (DER)`);
  console.log('');

  // Determine which scenarios to run
  let scenarios;
  if (args.category) {
    scenarios = getScenariosByCategory(args.category).filter(s => s.side === 'server');
    if (scenarios.length === 0) {
      console.error(`No server scenarios in category ${args.category}`);
      process.exit(1);
    }
  } else if (args.scenario === 'all') {
    scenarios = getServerScenarios().filter(s => !CATEGORY_DEFAULT_DISABLED.has(s.category));
    if (scenarios.length === 0) {
      console.error('No enabled server scenarios found');
      process.exit(1);
    }
    console.log(`  Running ${scenarios.length} server scenarios (opt-in categories excluded, use --category to include)`);
  } else if (args.scenario) {
    const s = getScenario(args.scenario);
    if (!s) {
      console.error(`Unknown scenario: ${args.scenario}`);
      process.exit(1);
    }
    if (s.side !== 'server') {
      console.error(`Scenario "${args.scenario}" is a client-side scenario. Use: node client.js`);
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
  const server = new FuzzerServer({
    port, hostname, timeout, delay, logger, pcapFile,
    cert: certInfo.certDER,
    certInfo,
  });

  // Handle ctrl+c
  process.on('SIGINT', () => {
    server.abort();
    process.exit(0);
  });

  const { results, report } = await server.runScenarios(scenarios);

  if (pcapFile) {
    logger.info(`PCAP saved to: ${pcapFile}`);
  }

  // Exit with non-zero if any failures
  const hasErrors = results.some(r => r.status === 'ERROR');
  const hasFails = report && report.stats.fail > 0;
  process.exit(hasErrors || hasFails ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
