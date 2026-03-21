const { QuicFuzzerServer } = require('./lib/quic-fuzzer-server');
const { QuicFuzzerClient } = require('./lib/quic-fuzzer-client');

async function run() {
  const server = new QuicFuzzerServer({ port: 4433, hostname: '127.0.0.1' });
  await server.start();

  const client = new QuicFuzzerClient({ host: '127.0.0.1', port: 4433 });
  
  // Dummy server scenario
  const srvScenario = {
    name: 'test-srv',
    category: 'QA',
    side: 'server',
    description: 'test srv',
    serverHandler: async (rinfo, sendFn, log, msg) => {
      log('Got msg');
      await sendFn(Buffer.from('PONG'), 'pong');
    }
  };
  
  const clientScenario = {
    name: 'test-cli',
    category: 'QA',
    side: 'client',
    description: 'test cli',
    actions: () => [{ type: 'send', data: Buffer.from('PING'), label: 'ping' }, { type: 'recv' }]
  };

  // Run server in background
  const srvPromise = server.runScenario(srvScenario);
  
  const res = await client.runScenario(clientScenario);
  console.log(res);

  server.close();
  await srvPromise;
}
run().catch(console.error);
