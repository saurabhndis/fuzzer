const { WellBehavedServer } = require('./lib/well-behaved-server');
const { QuicFuzzerClient } = require('./lib/quic-fuzzer-client');
const { listQuicClientScenarios } = require('./lib/quic-scenarios');
const { Logger } = require('./lib/logger');

async function run() {
  const logger = new Logger({ verbose: false });
  const server = new WellBehavedServer({ hostname: '127.0.0.1', port: 4433, logger: null });
  await server.startQuic();

  const client = new QuicFuzzerClient({ host: '127.0.0.1', port: server._actualPort, logger: null, timeout: 500 });
  const allScenarios = listQuicClientScenarios().filter(s => typeof s.actions === 'function');
  const scenarios = allScenarios.slice(0, 100); // Test first 100 to save time
  
  console.log(`Running ${scenarios.length} QUIC client scenarios...`);
  
  let timeouts = 0;
  let drops = 0;
  let success = 0;
  
  let done = 0;
  for (const scenario of scenarios) {
    const res = await client.runScenario(scenario);
    if (res.status === 'TIMEOUT' || res.response.includes('No UDP response')) {
      timeouts++;
    } else if (res.status === 'DROPPED') {
      drops++;
    } else {
      success++;
    }
    done++;
    if (done % 10 === 0) console.log(`Finished ${done}/${scenarios.length}`);
  }
  
  console.log('\n\n--- Results ---');
  console.log(`Timeouts / No UDP response: ${timeouts}`);
  console.log(`Dropped / Reset by Server: ${drops}`);
  console.log(`Received Response (Success): ${success}`);
  
  server.stop();
}

run().catch(console.error);
