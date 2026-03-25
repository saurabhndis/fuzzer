// Agent Worker Pool — long-lived worker that processes multiple scenarios via IPC.
// Replaces the fork-per-scenario model in agent.js to prevent FD exhaustion.
const { UnifiedClient } = require('./unified-client');
const { Logger } = require('./logger');
const { runBaseline } = require('./baseline');
const { getScenario } = require('./scenarios');
const { getHttp2Scenario } = require('./http2-scenarios');
const { getQuicScenario } = require('./quic-scenarios');
const { getTcpScenario } = require('./tcp-scenarios');

let client = null;
let currentScenarioName = null;

const lookup = (name, protocol) => {
  let s;
  if (protocol === 'raw-tcp') s = getTcpScenario(name);
  else if (protocol === 'quic') s = getQuicScenario(name);
  else if (protocol === 'h2') s = getHttp2Scenario(name);
  if (!s) s = getScenario(name) || getHttp2Scenario(name) || getQuicScenario(name) || getTcpScenario(name);
  return s;
};

process.on('message', async (msg) => {
  try {
    if (msg.cmd === 'init') {
      const logger = new Logger({ verbose: false });
      logger.onEvent(evt => {
        if (['scenario', 'sent', 'received', 'tcp', 'fuzz', 'info'].includes(evt.type)) {
          evt.scenario = currentScenarioName;
          process.send({ type: 'logger', event: evt });
        }
      });
      client = new UnifiedClient({
        host: msg.host, port: msg.port,
        timeout: msg.timeout, delay: msg.delay,
        logger, dut: msg.dut, pcapFile: msg.pcapFile,
        mergePcap: msg.mergePcap || false,
      });
      process.send({ type: 'ready' });

    } else if (msg.cmd === 'run') {
      if (!client) {
        process.send({ type: 'result', result: { scenario: msg.scenarioName, status: 'ERROR', response: 'Client not initialized' } });
        process.send({ type: 'ready' });
        return;
      }
      currentScenarioName = msg.scenarioName;
      const scenario = lookup(msg.scenarioName, msg.protocol);
      if (!scenario) {
        process.send({ type: 'result', result: { scenario: msg.scenarioName, status: 'ERROR', response: 'Unknown scenario' } });
        process.send({ type: 'ready' });
        return;
      }

      if (msg.baseline) {
        try {
          const baselineRes = await runBaseline(scenario, msg.protocol);
          scenario._baselineResponse = baselineRes.response;
          scenario._baselineCommand = baselineRes.command;
          const result = await client.runScenario(scenario);
          result.baselineResponse = baselineRes.response;
          result.baselineCommand = baselineRes.command;
          process.send({ type: 'result', result });
        } catch (err) {
          process.send({ type: 'result', result: { scenario: msg.scenarioName, status: 'ERROR', response: err.message } });
        }
      } else {
        try {
          const result = await client.runScenario(scenario);
          process.send({ type: 'result', result });
        } catch (err) {
          process.send({ type: 'result', result: { scenario: msg.scenarioName, status: 'ERROR', response: err.message } });
        }
      }
      process.send({ type: 'ready' });

    } else if (msg.cmd === 'abort') {
      if (client) client.close();
      process.exit(0);
    }
  } catch (err) {
    process.send({ type: 'logger', event: { type: 'info', message: `Worker error: ${err.message}` } });
    process.send({ type: 'ready' });
  }
});
