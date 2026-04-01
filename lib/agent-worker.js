// Agent Worker — executes a single scenario for the remote agent
const { UnifiedClient } = require('./unified-client');
const { UnifiedServer } = require('./unified-server');
const { Logger } = require('./logger');
const { runBaseline } = require('./baseline');

async function main() {
  const configStr = process.argv[2];
  const scenarioName = process.argv[3];
  
  if (!configStr || !scenarioName) {
    console.error('Usage: agent-worker.js <configJSON> <scenarioName>');
    process.exit(1);
  }

  const config = JSON.parse(configStr);
  
  const logger = new Logger({ verbose: false });
  // Send logger events back to parent
  logger.onEvent(event => {
    process.send({ type: 'logger', event });
  });

  const { host, port, hostname, timeout, delay, dut, pcapFile, mergePcap, protocol, baseline, role } = config;
  
  // Scenarios are loaded dynamically by the fuzzer engines, 
  // but we need to resolve the scenario object here.
  const { getScenario } = require('./scenarios');
  const { getHttp2Scenario } = require('./http2-scenarios');
  const { getQuicScenario } = require('./quic-scenarios');
  const { getTcpScenario } = require('./tcp-scenarios');

  let scenario;
  if (protocol === 'h2') scenario = getHttp2Scenario(scenarioName);
  else if (protocol === 'quic') scenario = getQuicScenario(scenarioName);
  else if (protocol === 'raw-tcp') scenario = getTcpScenario(scenarioName);
  else scenario = getScenario(scenarioName);

  if (!scenario) {
    process.send({ type: 'error', message: `Scenario not found: ${scenarioName}` });
    process.exit(1);
  }

  try {
    let result;
    if (role === 'server') {
      const { UnifiedServer } = require('./unified-server');
      const server = new UnifiedServer({
        port,
        hostname: hostname || 'localhost',
        timeout,
        delay,
        logger,
        dut,
        pcapFile
      });
      
      result = await server.runScenario(scenario);
      server.close();
    } else {
      let baselineRes = null;
      if (baseline) {
        try {
          baselineRes = await runBaseline(scenario, protocol);
        } catch (e) {
          // Ignore baseline failure
        }
      }

      const client = new UnifiedClient({ host, port, timeout, delay, logger, dut, pcapFile, mergePcap });
      result = await client.runScenario(scenario);
      
      if (baselineRes) {
        result.baselineResponse = baselineRes.response;
        result.baselineCommand = baselineRes.command;
      }
    }

    // Wait for parent to acknowledge the result before exiting
    // This prevents the parent from receiving 'exit' before the final 'message'
    const ackTimer = setTimeout(() => {
      console.warn(`Worker for ${scenarioName} timed out waiting for parent ack, exiting...`);
      process.exit(0);
    }, 5000);

    process.on('message', (m) => {
      if (m.type === 'ack') {
        clearTimeout(ackTimer);
        process.exit(0);
      }
    });

    process.send({ type: 'result', result });
  } catch (err) {
    process.send({ type: 'error', message: err.message });
    setTimeout(() => process.exit(1), 500);
  }
}

main().catch(err => {
  console.error('Worker fatal error:', err);
  process.exit(1);
});
