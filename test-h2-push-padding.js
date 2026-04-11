const { UnifiedServer } = require('./lib/unified-server');
const { UnifiedClient } = require('./lib/unified-client');
const { Logger } = require('./lib/logger');
const { generateServerCert } = require('./lib/cert-gen');
const { listHttp2ServerScenarios } = require('./lib/http2-scenarios');
const { getHttp2Scenario } = require('./lib/http2-scenarios');

let PORT = 9985;

function createCapturingLogger(role) {
  const logger = new Logger({ verbose: true, json: false });
  logger.onEvent((event) => {
    if (event.type === 'sent') {
      console.log(`[${role}] SENT (${event.size || 0}B) ${event.label || ''}`);
      if (event.hex) console.log(`  hex: ${event.hex.substring(0, 160)}${event.hex.length > 160 ? '...' : ''}`);
    } else if (event.type === 'received') {
      console.log(`[${role}] RECV (${event.size || 0}B) ${event.label || ''}`);
      if (event.hex) console.log(`  hex: ${event.hex.substring(0, 160)}${event.hex.length > 160 ? '...' : ''}`);
    } else if (event.type === 'fuzz') {
      console.log(`[${role}] FUZZ: ${event.message}`);
    } else if (event.type === 'scenario') {
      // clear
    }
  });
  return logger;
}

async function run() {
  const targetNames = [
    'h2-server-push-promise-padded-truncated',
    'h2-server-push-promise-padded-short-id'
  ];

  const serverScenarios = listHttp2ServerScenarios().filter(s => targetNames.includes(s.name));
  const certInfo = generateServerCert('localhost');
  const wbClient = getHttp2Scenario('well-behaved-h2-client');

  for (const ss of serverScenarios) {
    PORT++;
    console.log(`\n======================================================`);
    console.log(`Running test: ${ss.name} on port ${PORT}`);
    console.log(`======================================================`);

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

    try {
      const clientPromise = new Promise((resolve, reject) => {
        const clientTimeout = setTimeout(() => reject(new Error('client timeout')), 10000);
        server._onListening = () => {
          client.runScenario(wbClient).then(r => {
            clearTimeout(clientTimeout);
            resolve(r);
          }).catch(e => {
            clearTimeout(clientTimeout);
            reject(e);
          });
        };
      });

      const serverPromise = server.runScenario(ss).catch(e => {
        console.log("SERVER ERROR:", e.message);
      });

      const clientResult = await clientPromise;

      console.log(`\nCLIENT RESULT: ${clientResult.status} | ${clientResult.verdict || 'N/A'}`);
      console.log(`CLIENT RESPONSE: ${(clientResult.response || '')}`);

      const serverResult = await serverPromise;
      if (serverResult) {
        console.log(`SERVER RESULT: ${serverResult.status} | ${serverResult.verdict || 'N/A'}`);
        console.log(`SERVER RESPONSE: ${(serverResult.response || '')}`);
      }

    } catch (e) {
      console.log(`ERROR: ${ss.name} — ${e.message}`);
    }

    server.abort();
    client.abort();
    client.close();
    await new Promise(r => setTimeout(r, 500));
  }
  
  setTimeout(() => process.exit(0), 1000);
}

run();