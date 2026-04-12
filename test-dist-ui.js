const { Controller } = require('./lib/controller');
const { startAgent } = require('./lib/agent');

async function test() {
  const srvAgent = startAgent('server', { controlPort: 9251 });
  const cliAgent = startAgent('client', { controlPort: 9250 });
  await new Promise(r => setTimeout(r, 1000));
  
  const controller = new Controller();
  await controller.addAgent('server', 'localhost', 9251);
  await controller.addAgent('client', 'localhost', 9250);
  
  const clientConfig = { host: 'localhost', port: 4433, protocol: 'tls', workers: 1, timeout: 5000, delay: 50, baseline: false };
  const serverConfig = { hostname: 'localhost', port: 4433, protocol: 'tls', workers: 1, timeout: 5000, delay: 50, baseline: false };
  
  const clientScenarios = ['fw-xss-script-tag'];
  const serverScenarios = ['well-behaved-server'];
  
  await controller.configureAll(
    clientScenarios, serverScenarios,
    clientConfig, serverConfig,
    [], []
  );
  
  await controller.runStepped(0);
  
  await new Promise(r => setTimeout(r, 1000));
  
  srvAgent.close();
  cliAgent.close();
  process.exit(0);
}

test().catch(console.error);