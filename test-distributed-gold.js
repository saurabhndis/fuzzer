#!/usr/bin/env node
// Run all HTTP/2 and QUIC scenarios locally (server + client in same process)
// and generate gold.log with client SENT/RECV and results for every scenario.
//
// For client-fuzz: client result is captured (server runs well-behaved in background)
// For server-fuzz: server result is captured (client runs well-behaved in background)

const { UnifiedClient } = require('./lib/unified-client');
const { UnifiedServer } = require('./lib/unified-server');
const { Logger } = require('./lib/logger');
const { generateServerCert } = require('./lib/cert-gen');
const { listHttp2ClientScenarios, listHttp2ServerScenarios } = require('./lib/http2-scenarios');
const { listQuicClientScenarios, listQuicServerScenarios } = require('./lib/quic-scenarios');
const fs = require('fs');
const path = require('path');

const PORT = 9984;
const LOG_FILE = path.join(__dirname, 'gold.log');

let logStream;

function logToFile(msg) {
  if (logStream) logStream.write(`[${new Date().toISOString()}] ${msg}\n`);
}

function createCapturingLogger(role) {
  const logger = new Logger({ verbose: false, json: true });
  const seenPerScenario = new Set();

  logger.onEvent((event) => {
    if (event.type === 'sent') {
      const key = `sent-${event.label}`;
      if (!seenPerScenario.has(key)) {
        seenPerScenario.add(key);
        logToFile(`[${role}] SENT (${event.size || 0}B) ${event.label || ''}`);
        if (event.hex) logToFile(`  hex: ${event.hex.substring(0, 160)}${event.hex.length > 160 ? '...' : ''}`);
      }
    } else if (event.type === 'received') {
      const key = `recv-${event.label}`;
      if (!seenPerScenario.has(key)) {
        seenPerScenario.add(key);
        logToFile(`[${role}] RECV (${event.size || 0}B) ${event.label || ''}`);
        if (event.hex) logToFile(`  hex: ${event.hex.substring(0, 160)}${event.hex.length > 160 ? '...' : ''}`);
      }
    } else if (event.type === 'fuzz') {
      logToFile(`[${role}] FUZZ: ${event.message}`);
    } else if (event.type === 'scenario') {
      seenPerScenario.clear();
    }
  });

  return logger;
}

async function runClientFuzzBatch(protocol, clientScenarios, wellBehavedServerName, certInfo) {
  const count = clientScenarios.length;
  logToFile(`\n========== ${protocol.toUpperCase()} CLIENT FUZZ (${count} scenarios) ==========`);
  console.log(`  ${protocol.toUpperCase()} client fuzz: ${count} scenarios`);

  const serverLogger = createCapturingLogger('SERVER');
  const clientLogger = createCapturingLogger('CLIENT');

  const server = new UnifiedServer({
    port: PORT, hostname: 'localhost', timeout: 5000, delay: 50,
    logger: serverLogger, certInfo,
  });

  const client = new UnifiedClient({
    host: '127.0.0.1', port: PORT, timeout: 5000, delay: 50,
    logger: clientLogger,
  });

  let wbServer;
  if (protocol === 'h2') {
    const { getHttp2Scenario } = require('./lib/http2-scenarios');
    wbServer = getHttp2Scenario(wellBehavedServerName);
  } else {
    const { getQuicScenario } = require('./lib/quic-scenarios');
    wbServer = getQuicScenario(wellBehavedServerName);
  }

  let completed = 0;
  for (let i = 0; i < clientScenarios.length; i++) {
    const cs = clientScenarios[i];
    logToFile(`\n--- [${i + 1}/${count}] ${cs.name} ---`);

    try {
      // Run server in background (fire and forget — we don't wait for it)
      server._onListening = null; // will set below
      const serverPromise = server.runScenario(wbServer).catch(() => {});

      // Wait for server to signal it's listening, then run client
      const clientResult = await new Promise((resolve, reject) => {
        const clientTimeout = setTimeout(() => reject(new Error('client timeout')), 15000);

        server._onListening = () => {
          client.runScenario(cs).then(r => {
            clearTimeout(clientTimeout);
            resolve(r);
          }).catch(e => {
            clearTimeout(clientTimeout);
            reject(e);
          });
        };
      });

      logToFile(`RESULT: ${cs.name} | ${clientResult.status} | ${clientResult.verdict || 'N/A'} | ${(clientResult.response || '').substring(0, 200)}`);
      completed++;

      // Don't wait for server — it may timeout on well-behaved scenarios when
      // client sends fuzz data that doesn't trigger a proper H2 stream.
      // Just abort the server's pending scenario.
    } catch (e) {
      logToFile(`ERROR: ${cs.name} — ${e.message}`);
    }

    if ((i + 1) % 100 === 0) {
      console.log(`    Progress: ${i + 1}/${count}`);
    }
  }

  server.abort();
  client.abort();
  client.close();

  console.log(`    Done: ${completed}/${count}`);
  logToFile(`Completed: ${completed}/${count}`);
  await new Promise(r => setTimeout(r, 1000));
}

async function runServerFuzzBatch(protocol, serverScenarios, wellBehavedClientName, certInfo) {
  const count = serverScenarios.length;
  logToFile(`\n========== ${protocol.toUpperCase()} SERVER FUZZ (${count} scenarios) ==========`);
  console.log(`  ${protocol.toUpperCase()} server fuzz: ${count} scenarios`);

  const serverLogger = createCapturingLogger('SERVER');
  const clientLogger = createCapturingLogger('CLIENT');

  const server = new UnifiedServer({
    port: PORT, hostname: 'localhost', timeout: 5000, delay: 50,
    logger: serverLogger, certInfo,
  });

  const client = new UnifiedClient({
    host: '127.0.0.1', port: PORT, timeout: 5000, delay: 50,
    logger: clientLogger,
  });

  let wbClient;
  if (protocol === 'h2') {
    const { getHttp2Scenario } = require('./lib/http2-scenarios');
    wbClient = getHttp2Scenario(wellBehavedClientName);
  } else {
    const { getQuicScenario } = require('./lib/quic-scenarios');
    wbClient = getQuicScenario(wellBehavedClientName);
  }

  let completed = 0;
  for (let i = 0; i < serverScenarios.length; i++) {
    const ss = serverScenarios[i];
    logToFile(`\n--- [${i + 1}/${count}] ${ss.name} ---`);

    try {
      // For server fuzz, we capture the SERVER result
      server._onListening = () => {
        client.runScenario(wbClient).catch(() => {});
      };

      const serverResult = await Promise.race([
        server.runScenario(ss),
        new Promise((_, rej) => setTimeout(() => rej(new Error('scenario timeout (30s)')), 30000)),
      ]);

      logToFile(`RESULT: ${ss.name} | ${serverResult.status} | ${serverResult.verdict || 'N/A'} | ${(serverResult.response || '').substring(0, 200)}`);
      completed++;
    } catch (e) {
      logToFile(`ERROR: ${ss.name} — ${e.message}`);
    }

    if ((i + 1) % 10 === 0) {
      console.log(`    Progress: ${i + 1}/${count}`);
    }
  }

  server.abort();
  client.abort();
  client.close();

  console.log(`    Done: ${completed}/${count}`);
  logToFile(`Completed: ${completed}/${count}`);
  await new Promise(r => setTimeout(r, 1000));
}

async function main() {
  logStream = fs.createWriteStream(LOG_FILE);

  const isWB = (n) => n.startsWith('well-behaved') || n.startsWith('srv-quic-well-behaved');
  const h2Client = listHttp2ClientScenarios().filter(s => !isWB(s.name));
  const h2Server = listHttp2ServerScenarios().filter(s => !isWB(s.name));
  const quicClient = listQuicClientScenarios().filter(s => !isWB(s.name));
  const quicServer = listQuicServerScenarios().filter(s => !isWB(s.name));
  const total = h2Client.length + h2Server.length + quicClient.length + quicServer.length;

  console.log(`\n  Gold Test — HTTP/2 and QUIC (local mode)\n`);
  console.log(`  H2: ${h2Client.length} client + ${h2Server.length} server`);
  console.log(`  QUIC: ${quicClient.length} client + ${quicServer.length} server`);
  console.log(`  Total: ${total}\n`);

  logToFile(`=== GOLD TEST: ${total} scenarios (H2: ${h2Client.length}c/${h2Server.length}s, QUIC: ${quicClient.length}c/${quicServer.length}s) ===`);

  const certInfo = generateServerCert('localhost');
  const startTime = Date.now();

  await runClientFuzzBatch('h2', h2Client, 'well-behaved-h2-server', certInfo);
  await runServerFuzzBatch('h2', h2Server, 'well-behaved-h2-client', certInfo);
  await runClientFuzzBatch('quic', quicClient, 'srv-quic-well-behaved-echo', certInfo);
  await runServerFuzzBatch('quic', quicServer, 'well-behaved-quic-client', certInfo);

  const elapsed = Math.ceil((Date.now() - startTime) / 1000);
  logToFile(`\n=== ALL ${total} TESTS COMPLETE in ${elapsed}s ===`);
  console.log(`\n  All tests complete in ${elapsed}s.`);
  console.log(`  Log: ${LOG_FILE}\n`);

  logStream.end(() => process.exit(0));
}

process.on('SIGINT', () => { if (logStream) logStream.end(); process.exit(0); });
process.on('uncaughtException', (e) => {
  logToFile(`UNCAUGHT: ${e.message}`);
});

main().catch(e => { console.error(`Fatal: ${e.message}`); process.exit(1); });
