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
const { computeOverallGrade } = require('./lib/grader');
const cluster = require('cluster');
const os = require('os');

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
    --workers <num>         Number of concurrent worker processes (default: CPU count)
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

function getScenarios(args, useRawTcp, protocol) {
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
    const names = args.scenario.split(',');
    scenarios = [];
    for (const name of names) {
      let s;
      if (useRawTcp) s = getTcpScenario(name);
      else if (protocol === 'h2') s = getHttp2Scenario(name);
      else if (protocol === 'quic') s = getQuicScenario(name);

      if (!s) s = getScenario(name);

      if (!s) {
        console.error(`Unknown scenario: ${name}`);
        process.exit(1);
      }
      if (s.side !== 'client') {
        console.error(`Scenario "${name}" is a server-side scenario.`);
        process.exit(1);
      }
      scenarios.push(s);
    }
  } else {
    console.error('Error: specify --scenario <name|all> or --category <A-Z|RA-RG>');
    console.log(USAGE);
    process.exit(1);
  }
  return scenarios;
}

async function primaryMain(args) {
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

  const protocol = args.protocol || 'tls';
  const useRawTcp = protocol === 'raw-tcp';

  if (useRawTcp && !isRawAvailable()) {
    console.error('\x1b[33mWarning: Raw sockets not available. Requires CAP_NET_RAW on Linux.\x1b[0m');
    console.error('  Run: sudo setcap cap_net_raw+ep $(which node)');
    console.error('  Raw TCP scenarios will be skipped.\n');
  }

  const scenarios = getScenarios(args, useRawTcp, protocol);
  const workerCount = parseInt(args.workers) || os.cpus().length;

  console.log(`
  TLS/TCP Protocol Fuzzer — Client

  Target        ${host}:${port}
  Protocol      ${protocol}
  Scenarios     ${scenarios.length}
  Workers       ${workerCount}
  `);

  console.log(`  Forking ${workerCount} worker processes for concurrent fuzzing...`);

  const queue = scenarios.map(s => s.name);
  const results = [];
  let activeWorkers = 0;

  for (let i = 0; i < workerCount; i++) {
    const worker = cluster.fork();
    activeWorkers++;
    
    worker.on('message', (msg) => {
      if (msg.type === 'ready') {
        if (queue.length > 0) {
          worker.send({ type: 'scenario', name: queue.shift() });
        } else {
          worker.send({ type: 'done' });
        }
      } else if (msg.type === 'result') {
        results.push(msg.result);
      }
    });

    worker.on('exit', () => {
      activeWorkers--;
      if (activeWorkers === 0) {
        const logger = new Logger({ verbose: args.verbose, json: args.json });
        const report = computeOverallGrade(results);
        logger.summary(results);

        const pcapFile = args.pcap || null;
        if (pcapFile) {
          logger.info(`PCAP saved to: ${pcapFile}`);
        }

        const hasErrors = results.some(r => r.status === 'ERROR');
        const hostWentDown = results.some(r => r.hostDown);
        const hasFails = report && report.stats.fail > 0;
        process.exit(hasErrors || hostWentDown || hasFails ? 1 : 0);
      }
    });
  }

  process.on('SIGINT', () => {
    // Gracefully shut down workers before exiting
    for (const w of Object.values(cluster.workers || {})) {
      try { w.send({ type: 'done' }); } catch (_) {}
    }
    setTimeout(() => process.exit(0), 1000);
  });
}

async function workerMain(args) {
  const host = args._[0];
  const port = parseInt(args._[1]);
  if (!host || !port) return;

  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 5000;
  let pcapFile = args.pcap || null;
  const protocol = args.protocol || 'tls';
  const useRawTcp = protocol === 'raw-tcp';

  if (pcapFile) {
    pcapFile = `${pcapFile}.worker-${process.pid}`;
  }

  const logger = new Logger({ verbose: args.verbose, json: args.json });
  const scenarios = getScenarios(args, useRawTcp, protocol);

  const client = new UnifiedClient({ host, port, timeout, delay, logger, pcapFile });

  process.on('SIGINT', () => {
    client.abort();
    client.close();
    process.exit(0);
  });

  process.on('message', async (msg) => {
    if (msg.type === 'scenario') {
      const scenario = scenarios.find(s => s.name === msg.name);
      if (scenario) {
        const result = await client.runScenario(scenario);
        setTimeout(() => {
          process.send({ type: 'result', result });
          process.send({ type: 'ready' });
        }, 100);
      } else {
        process.send({ type: 'ready' });
      }
    } else if (msg.type === 'done') {
      client.abort();
      client.close();
      process.exit(0);
    }
  });

  process.send({ type: 'ready' });
}

if (cluster.isPrimary) {
  primaryMain(parseArgs(process.argv.slice(2))).catch((err) => {
    console.error('Fatal error:', err.message);
    process.exit(1);
  });
} else {
  workerMain(parseArgs(process.argv.slice(2))).catch((err) => {
    console.error('Worker error:', err.message);
    process.exit(1);
  });
}
