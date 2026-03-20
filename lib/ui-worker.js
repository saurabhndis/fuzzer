const { UnifiedClient } = require('./unified-client');
const { UnifiedServer } = require('./unified-server');
const { Logger } = require('./logger');
const { getScenario } = require('./scenarios');
const { getHttp2Scenario } = require('./http2-scenarios');
const { getQuicScenario } = require('./quic-scenarios');
const { getTcpScenario } = require('./tcp-scenarios');
const { runBaseline } = require('./baseline');
const { WellBehavedClient } = require('./well-behaved-client');

const lookup = (name, protocol) => {
  let s;
  if (protocol === 'raw-tcp') s = getTcpScenario(name);
  else if (protocol === 'quic') s = getQuicScenario(name);
  else if (protocol === 'h2') s = getHttp2Scenario(name);
  if (!s) {
    s = getScenario(name) || getHttp2Scenario(name) || getQuicScenario(name) || getTcpScenario(name);
  }
  return s;
};

let activeEngine = null;

process.on('message', async (msg, socket) => {
  try {
    if (msg.cmd === 'init-client') {
      const logger = new Logger({ verbose: msg.verbose });
      logger.onEvent(evt => {
        if (['sent', 'received', 'tcp', 'fuzz', 'info'].includes(evt.type)) {
          process.send({ type: 'log', data: evt });
        }
      });
      activeEngine = new UnifiedClient({
        host: msg.host, port: msg.port, timeout: msg.timeout, delay: msg.delay,
        logger, pcapFile: msg.pcapFile, dut: msg.dut
      });
      process.send({ type: 'ready' });

    } else if (msg.cmd === 'init-server') {
      const logger = new Logger({ verbose: msg.verbose });
      logger.onEvent(evt => {
        if (['sent', 'received', 'tcp', 'fuzz', 'info'].includes(evt.type)) {
          process.send({ type: 'log', data: evt });
        }
      });

      // Deserialize certInfo — convert base64 Buffers back
      const certInfo = msg.certInfo ? {
        ...msg.certInfo,
        certDER: msg.certInfo.certDER
          ? Buffer.from(msg.certInfo.certDER, 'base64')
          : undefined,
        keyDER: msg.certInfo.keyDER
          ? Buffer.from(msg.certInfo.keyDER, 'base64')
          : undefined,
      } : undefined;

      activeEngine = new UnifiedServer({
        hostname: msg.hostname, port: msg.port, timeout: msg.timeout, delay: msg.delay,
        logger, pcapFile: msg.pcapFile, dut: msg.dut, certInfo
      });
      process.send({ type: 'ready' });

    } else if (msg.cmd === 'run-on-socket') {
      // Worker receives a pre-connected socket from the primary —
      // run the scenario's fuzz actions directly on it.
      if (!socket) {
        // Socket IPC transfer failed — report error and stay ready
        process.send({ type: 'result', result: {
          scenario: msg.scenarioName, status: 'ERROR',
          response: 'Socket transfer failed (IPC handle not received)',
        }});
        process.send({ type: 'ready' });
        return;
      }
      if (!activeEngine || !(activeEngine instanceof UnifiedServer)) {
        socket.destroy();
        process.send({ type: 'result', result: {
          scenario: msg.scenarioName, status: 'ERROR',
          response: 'Server engine not initialized',
        }});
        process.send({ type: 'ready' });
        return;
      }
      const scenario = lookup(msg.scenarioName, msg.protocol);
      if (!scenario) {
        socket.destroy();
        process.send({ type: 'result', result: {
          scenario: msg.scenarioName, status: 'ERROR',
          response: 'Unknown scenario',
        }});
        process.send({ type: 'ready' });
        return;
      }

      const result = await activeEngine.runScenarioOnSocket(scenario, socket);
      process.send({ type: 'result', result });
      process.send({ type: 'ready' });

    } else if (msg.cmd === 'run') {
      if (!activeEngine) {
        process.send({ type: 'ready' });
        return;
      }
      const scenario = lookup(msg.scenarioName, msg.protocol);
      if (!scenario) {
        process.send({ type: 'ready' });
        return;
      }

      let localClient = null;
      if (msg.localMode && activeEngine instanceof UnifiedServer) {
        const logger = new Logger({ verbose: msg.verbose });
        localClient = new WellBehavedClient({ host: '127.0.0.1', port: msg.port, logger });
        let connected = false;
        activeEngine._onListening = async () => {
          if (connected) return;
          connected = true;
          activeEngine._onListening = null;
          try {
            if (msg.protocol === 'quic') await localClient.connectQuic();
            else if (msg.protocol === 'h2') await localClient.connectH2();
            else await localClient.connectTLS();
          } catch (_) {}
        };
      }

      if (msg.baseline) {
        process.send({ type: 'log', data: { type: 'info', message: `[baseline] testing against local OpenSSL...` } });
        const baselineRes = await runBaseline(scenario, msg.protocol);
        scenario._baselineResponse = baselineRes.response;
        scenario._baselineCommand = baselineRes.command;
        const result = await activeEngine.runScenario(scenario);
        result.baselineResponse = baselineRes.response;
        result.baselineCommand = baselineRes.command;
        if (localClient) localClient.stop();
        process.send({ type: 'result', result });
        process.send({ type: 'ready' });
      } else {
        const result = await activeEngine.runScenario(scenario);
        if (localClient) localClient.stop();
        process.send({ type: 'result', result });
        process.send({ type: 'ready' });
      }
    } else if (msg.cmd === 'noop') {
      // Parent timed out waiting for a socket — signal ready to pick up next scenario
      process.send({ type: 'ready' });

    } else if (msg.cmd === 'abort') {
      if (activeEngine) activeEngine.abort();
      process.exit(0);
    }
  } catch (err) {
    process.send({ type: 'log', data: { type: 'info', message: `Worker Error: ${err.message}` } });
    process.send({ type: 'ready' });
  }
});
