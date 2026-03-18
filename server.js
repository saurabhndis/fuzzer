#!/usr/bin/env node
// TLS/TCP Protocol Fuzzer — Standalone Server
// Run server-side fuzzing scenarios independently on any host

const net = require('net');
const { UnifiedServer } = require('./lib/unified-server');
const { Logger } = require('./lib/logger');
const { getScenario, getScenariosByCategory, getServerScenarios, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { getHttp2Scenario, getHttp2ScenariosByCategory, listHttp2ServerScenarios } = require('./lib/http2-scenarios');
const { getQuicScenario, getQuicScenariosByCategory, listQuicServerScenarios } = require('./lib/quic-scenarios');
const { getTcpScenario, getTcpScenariosByCategory, getTcpServerScenarios } = require('./lib/tcp-scenarios');
const { isRawAvailable } = require('./lib/raw-tcp');
const { generateServerCert } = require('./lib/cert-gen');
const { computeOverallGrade } = require('./lib/grader');
const cluster = require('cluster');

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
    --workers <n>           Number of concurrent workers (default: 1)

  Examples:
    node server.js
    node server.js 4433 --scenario all --hostname evil.test --verbose
    node server.js 4433 --category W --hostname test.local
    node server.js 4433 --scenario cert-expired --verbose
    node server.js 4433 --category RG --protocol raw-tcp
    node server.js 4433 --scenario all --workers 4
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
  return scenarios;
}

// Look up a scenario by name across all protocol types
function lookupScenario(name, protocol) {
  let s;
  if (protocol === 'raw-tcp') s = getTcpScenario(name);
  else if (protocol === 'h2') s = getHttp2Scenario(name);
  else if (protocol === 'quic') s = getQuicScenario(name);
  if (!s) s = getScenario(name) || getHttp2Scenario(name) || getQuicScenario(name) || getTcpScenario(name);
  return s;
}

async function primaryMain(args) {
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
  const workerCount = parseInt(args.workers) || require('os').cpus().length;

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

  const scenarios = getScenarios(args, useRawTcp, protocol);

  if (args.scenario === 'all') {
    console.log(`  Running ${scenarios.length} server scenarios (opt-in categories excluded, use --category to include)`);
  }

  console.log(`  \x1b[90mScenarios\x1b[0m     ${scenarios.length} scenario(s) queued`);
  console.log(`  \x1b[90mWorkers\x1b[0m       ${workerCount}`);
  console.log('');

  // For single-worker mode, run directly without forking
  if (workerCount <= 1) {
    const logger = new Logger({ verbose: args.verbose, json: args.json });
    const server = new UnifiedServer({ port, hostname, timeout, delay, logger, pcapFile, certInfo });

    process.on('SIGINT', () => { server.abort(); process.exit(0); });

    const { results, report } = await server.runScenarios(scenarios);
    if (pcapFile) logger.info(`PCAP saved to: ${pcapFile}`);
    const hasErrors = results.some(r => r.status === 'ERROR');
    const hasFails = report && report.stats.fail > 0;
    process.exit(hasErrors || hasFails ? 1 : 0);
  }

  // Multi-worker mode: primary owns the listening socket, dispatches
  // accepted connections to workers via IPC handle transfer.
  // Workers process scenarios concurrently — each ready worker is assigned
  // the next scenario from the queue, and the next incoming connection is
  // paired with it.
  console.log(`  Forking ${workerCount} worker processes...`);

  // Serialize certInfo — convert Buffers to base64 for IPC
  const certInfoForIPC = {
    certDER: certInfo.certDER.toString('base64'),
    keyDER: certInfo.keyDER ? certInfo.keyDER.toString('base64') : null,
    certPEM: certInfo.certPEM,
    keyPEM: certInfo.keyPEM,
    fingerprint: certInfo.fingerprint,
  };

  // Create shared TCP server in primary — pauseOnConnect ensures no data
  // is consumed before the socket is transferred to the worker
  const tcpServer = net.createServer({ allowHalfOpen: true, pauseOnConnect: true });
  tcpServer.listen(port, '0.0.0.0', () => {
    console.log(`  \x1b[32mListening on 0.0.0.0:${port} — dispatching to ${workerCount} workers\x1b[0m\n`);
  });

  const queue = [...scenarios];
  const results = [];
  let allDone = false;
  let onAllResults = null;

  // Workers that have been assigned a scenario and are waiting for a socket
  const waitingForSocket = [];  // { worker, scenarioName }
  // Connections waiting to be paired with a worker
  const pendingSockets = [];

  function tryPairSocketToWorker() {
    while (waitingForSocket.length > 0 && pendingSockets.length > 0) {
      const { worker, scenarioName } = waitingForSocket.shift();
      const socket = pendingSockets.shift();
      try {
        worker.send({ type: 'socket', scenarioName }, socket);
      } catch (e) {
        socket.destroy();
        results.push({ scenario: scenarioName, status: 'ERROR', response: `Worker IPC failed: ${e.message}` });
        console.log(`  \x1b[31m✗\x1b[0m ${scenarioName} — ERROR — Worker IPC failed`);
      }
    }
  }

  function checkDone() {
    if (allDone && results.length >= scenarios.length && onAllResults) {
      onAllResults();
    }
  }

  // Fork workers and set up IPC
  const allWorkers = [];
  const numWorkers = Math.min(workerCount, scenarios.length);

  for (let i = 0; i < numWorkers; i++) {
    const worker = cluster.fork();
    allWorkers.push(worker);

    worker.on('message', (msg) => {
      if (msg.type === 'ready') {
        // Worker is ready — assign next scenario from queue
        if (queue.length > 0) {
          const scenario = queue.shift();
          const scenarioName = scenario.name;
          waitingForSocket.push({ worker, scenarioName });
          tryPairSocketToWorker();
        } else {
          worker.send({ type: 'done' });
        }
      } else if (msg.type === 'result') {
        results.push(msg.result);
        const status = msg.result.verdict === 'AS EXPECTED' ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
        console.log(`  ${status} ${msg.result.scenario} — ${msg.result.status} — ${msg.result.response}`);
        checkDone();
      }
    });

    worker.on('exit', () => {
      const idx = allWorkers.indexOf(worker);
      if (idx !== -1) allWorkers.splice(idx, 1);
      // Safety: if all workers exit before all results, resolve anyway
      if (allWorkers.length === 0 && onAllResults) onAllResults();
    });

    // Send init with serialized cert info
    worker.send({
      type: 'init', hostname, timeout, delay,
      verbose: args.verbose, pcapFile, protocol,
      certInfo: certInfoForIPC,
    });
  }

  // Accept connections from the shared server and pair with waiting workers
  tcpServer.on('connection', (socket) => {
    pendingSockets.push(socket);
    tryPairSocketToWorker();
  });

  // Wait for all results
  allDone = true;
  await new Promise((resolve) => {
    onAllResults = resolve;
    checkDone(); // in case everything already finished
  });

  // Cleanup
  tcpServer.close();
  for (const w of allWorkers) {
    try { w.send({ type: 'done' }); } catch (_) {}
  }

  const logger = new Logger({ verbose: args.verbose, json: args.json });
  const report = computeOverallGrade(results);
  logger.summary(results);
  if (pcapFile) logger.info(`PCAP saved to: ${pcapFile}`);
  const hasErrors = results.some(r => r.status === 'ERROR');
  const hasFails = report && report.stats.fail > 0;
  process.exit(hasErrors || hasFails ? 1 : 0);
}

function workerMain() {
  let server = null;
  let protocol = 'tls';

  process.on('message', async (msg, socket) => {
    try {
      if (msg.type === 'init') {
        protocol = msg.protocol || 'tls';

        // Deserialize certInfo — convert base64 back to Buffers
        const certInfo = {
          ...msg.certInfo,
          certDER: Buffer.from(msg.certInfo.certDER, 'base64'),
          keyDER: msg.certInfo.keyDER ? Buffer.from(msg.certInfo.keyDER, 'base64') : null,
        };

        const logger = new Logger({ verbose: msg.verbose });
        server = new UnifiedServer({
          hostname: msg.hostname, port: 0, // port unused — worker never listens
          timeout: msg.timeout, delay: msg.delay,
          logger, pcapFile: msg.pcapFile, certInfo,
        });

        process.send({ type: 'ready' });

      } else if (msg.type === 'socket' && socket) {
        // socket is the IPC-transferred net.Socket handle
        const scenario = lookupScenario(msg.scenarioName, protocol);
        if (!scenario || !server) {
          socket.destroy();
          process.send({ type: 'result', result: {
            scenario: msg.scenarioName, status: 'ERROR',
            response: scenario ? 'Server not initialized' : 'Unknown scenario',
          }});
          process.send({ type: 'ready' });
          return;
        }

        const result = await server.runScenarioOnSocket(scenario, socket);
        process.send({ type: 'result', result });
        process.send({ type: 'ready' });

      } else if (msg.type === 'done') {
        if (server) server.abort();
        process.exit(0);
      }
    } catch (err) {
      console.error(`Worker ${process.pid} error:`, err.message);
      process.send({ type: 'ready' });
    }
  });
}

if (cluster.isPrimary) {
  primaryMain(parseArgs(process.argv.slice(2))).catch((err) => {
    console.error('Fatal error:', err.message);
    process.exit(1);
  });
} else {
  workerMain();
}
