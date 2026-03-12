#!/usr/bin/env node
// TLS/TCP Protocol Fuzzer — Standalone Server
// Run server-side fuzzing scenarios independently on any host

const { FuzzerServer } = require('./lib/fuzzer-server');
const { UnifiedServer } = require('./lib/unified-server');
const { Logger } = require('./lib/logger');
const { getScenario, getScenariosByCategory, getServerScenarios, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { getHttp2Scenario, getHttp2ScenariosByCategory, listHttp2ServerScenarios } = require('./lib/http2-scenarios');
const { getQuicScenario, getQuicScenariosByCategory, listQuicServerScenarios } = require('./lib/quic-scenarios');
const { getTcpScenario, getTcpScenariosByCategory, getTcpServerScenarios } = require('./lib/tcp-scenarios');
const { isRawAvailable } = require('./lib/raw-tcp');
const { generateServerCert } = require('./lib/cert-gen');

const USAGE = `
  TLS/TCP Protocol Fuzzer — Server Mode

  Starts a server agent with an HTTP control channel, or runs
  server-side fuzzing scenarios directly. Listens for incoming
  connections and responds with fuzzed TLS handshake messages.

  Usage:
    node server.js                    Start server agent (control on 0.0.0.0:9201)
    node server.js <port> [options]   Run scenarios directly

  Agent options:
    --control-port <port>   Agent control port (default: 9201)
    --token <string>        Authentication token for agent mode

  Direct-run options:
    --scenario <name|all>   Run specific scenario or all server scenarios
    --category <A-Y|RA-RG>  Run all server scenarios in a category
    --protocol <type>       Protocol: tls (default), h2, quic, raw-tcp
    --hostname <name>       Certificate CN/SAN (default: localhost)
    --delay <ms>            Delay between actions (default: 100)
    --timeout <ms>          Connection timeout (default: 10000)
    --verbose               Show hex dumps of all packets
    --json                  Output results as JSON
    --pcap <file.pcap>      Record packets to PCAP file

  Examples:
    node server.js
    node server.js 4433 --scenario all --hostname evil.test --verbose
    node server.js 4433 --category W --hostname test.local
    node server.js 4433 --scenario cert-expired --verbose
    node server.js 4433 --category RG --protocol raw-tcp
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

  const port = parseInt(args._[0]);

  // Agent mode — no port arg means start the control channel
  if (!port) {
    const controlPort = parseInt(args['control-port']) || 9201;
    const token = args['token'] || null;
    const { startAgent } = require('./lib/agent');
    startAgent('server', { controlPort, token });
    process.on('SIGINT', () => process.exit(0));
    return;
  }

  if (port < 1 || port > 65535) {
    console.log(USAGE);
    process.exit(1);
  }

  const hostname = args.hostname || 'localhost';
  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 10000;
  const pcapFile = args.pcap || null;
  const protocol = args.protocol || 'tls';
  const useRawTcp = protocol === 'raw-tcp';

  if (useRawTcp && !isRawAvailable()) {
    console.warn('\x1b[33mWarning: Raw sockets not available. Requires CAP_NET_RAW on Linux.\x1b[0m');
    console.warn('  Run: sudo setcap cap_net_raw+ep $(which node)');
    console.warn('  Raw TCP scenarios will be skipped.\n');
  }

  // Generate self-signed certificate
  const certInfo = generateServerCert(hostname);
  const fp = certInfo.fingerprint;
  const fpFormatted = fp.match(/.{2}/g).join(':').toUpperCase();

  console.log('');
  console.log('  \x1b[1m\x1b[36mTLS/TCP Protocol Fuzzer — Server\x1b[0m');
  console.log('');
  console.log(`  \x1b[90mListening on\x1b[0m  0.0.0.0:${port}`);
  console.log(`  \x1b[90mProtocol\x1b[0m      ${protocol}`);
  console.log(`  \x1b[90mCertificate\x1b[0m   CN=${hostname}`);
  console.log(`  \x1b[90mSHA256\x1b[0m        ${fpFormatted}`);
  console.log(`  \x1b[90mCert size\x1b[0m     ${certInfo.certDER.length} bytes (DER)`);
  console.log('');

  // Determine which scenarios to run
  let scenarios;
  if (args.category) {
    const cat = args.category.toUpperCase();
    if (useRawTcp) scenarios = getTcpScenariosByCategory(cat);
    else if (protocol === 'h2') scenarios = getHttp2ScenariosByCategory(cat);
    else if (protocol === 'quic') scenarios = getQuicScenariosByCategory(cat);
    else scenarios = getScenariosByCategory(cat);

    scenarios = scenarios.filter(s => s.side === 'server');
    if (scenarios.length === 0) {
      console.error(`No server scenarios in category ${args.category}`);
      process.exit(1);
    }
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
    console.log(`  Running ${scenarios.length} server scenarios (opt-in categories excluded, use --category to include)`);
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
      console.error(`Scenario "${args.scenario}" is a client-side scenario. Use: node client.js`);
      process.exit(1);
    }
    scenarios = [s];
  } else {
    console.error('Error: specify --scenario <name|all> or --category <A-Y|RA-RG>');
    console.log(USAGE);
    process.exit(1);
  }

  console.log(`  \x1b[90mScenarios\x1b[0m     ${scenarios.length} scenario(s) queued`);
  console.log('');

  const logger = new Logger({ verbose: args.verbose, json: args.json });

  // Use UnifiedServer for raw-tcp/h2/quic, FuzzerServer for plain TLS
  const server = (useRawTcp || protocol === 'h2' || protocol === 'quic')
    ? new UnifiedServer({
        port, hostname, timeout, delay, logger, pcapFile,
        certInfo,
      })
    : new FuzzerServer({
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
