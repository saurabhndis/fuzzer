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
const { getLdapScenario, getLdapScenariosByCategory, listLdapScenarios, listLdapClientScenarios, listLdapServerScenarios, LDAP_CATEGORIES, LDAP_CATEGORY_DEFAULT_DISABLED } = require('./lib/ldap/scenarios');
const { isRawAvailable } = require('./lib/raw-tcp');
const { generateServerCert } = require('./lib/cert-gen');

const USAGE = `
  TLS/TCP Protocol Fuzzer

  Usage:
    node cli.js client <host> <port> [options]
    node cli.js server <port> [options]
    node cli.js list

  Options:
    --scenario <name|all>   Run specific scenario or all
    --category <A-Y>        Run all scenarios in a category
    --hostname <name>       Server cert CN/SAN (default: localhost)
    --delay <ms>            Delay between actions (default: 100)
    --timeout <ms>          Connection timeout (default: 5000)
    --protocol <type>       Protocol: tls (default), h2, quic, raw-tcp
    --verbose               Show hex dumps of all packets
    --json                  Output results as JSON
    --pcap <file.pcap>      Record packets to PCAP file
    --merge-pcap            Merge all scenarios into a single PCAP file
    --no-baseline           Skip OpenSSL/baseline comparison testing

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
      if (key === 'verbose' || key === 'json' || key === 'merge-pcap') {
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

    // LDAP scenarios
    const ldapGroups = listLdapScenarios();
    console.log('  \x1b[1m\x1b[33mLDAP Scenarios\x1b[0m\n');
    for (const [cat, items] of Object.entries(ldapGroups.scenarios)) {
      const disabledNote = LDAP_CATEGORY_DEFAULT_DISABLED.has(cat) ? ' \x1b[33m[opt-in]\x1b[0m' : '';
      console.log(`  \x1b[1m\x1b[35m${cat}: ${ldapGroups.categories[cat]}\x1b[0m (${items.length} scenarios)${disabledNote}`);
      for (const s of items) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(50)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }
    process.exit(0);
  }

  const logger = new Logger({ verbose: args.verbose, json: args.json });
  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 5000;
  const pcapFile = args.pcap || null;
  const mergePcap = args['merge-pcap'] || false;
  const protocol = args.protocol || 'tls';

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
    if (args.category) {
      if (useRawTcp) scenarios = getTcpScenariosByCategory(args.category);
      else if (protocol === 'h2') scenarios = getHttp2ScenariosByCategory(args.category);
      else if (protocol === 'quic') scenarios = getQuicScenariosByCategory(args.category);
      else if (protocol === 'ldap') scenarios = getLdapScenariosByCategory(args.category);
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
      } else if (protocol === 'ldap') {
        scenarios = listLdapClientScenarios().filter(s => !LDAP_CATEGORY_DEFAULT_DISABLED.has(s.category));
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
      else if (protocol === 'ldap') s = getLdapScenario(args.scenario);

      if (!s) s = getLdapScenario(args.scenario) || getScenario(args.scenario);

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
      else if (protocol === 'ldap') scenarios = getLdapScenariosByCategory(args.category);
      else scenarios = getScenariosByCategory(args.category);

      scenarios = scenarios.filter(s => s.side === 'server');
    } else if (args.scenario === 'all') {
      if (useRawTcp) {
        scenarios = getTcpServerScenarios();
      } else if (protocol === 'h2') {
        scenarios = listHttp2ServerScenarios();
      } else if (protocol === 'quic') {
        scenarios = listQuicServerScenarios();
      } else if (protocol === 'ldap') {
        scenarios = listLdapServerScenarios().filter(s => !LDAP_CATEGORY_DEFAULT_DISABLED.has(s.category));
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
      else if (protocol === 'ldap') s = getLdapScenario(args.scenario);

      if (!s) s = getLdapScenario(args.scenario) || getScenario(args.scenario);

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
    const fp = certInfo.fingerprint.match(/.{2}/g).join(':').toUpperCase();
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
