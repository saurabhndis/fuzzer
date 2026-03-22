// Remote Agent — HTTP control server for distributed fuzzing
// Runs on a remote VM, receives configuration from the controller (Electron UI),
// and streams results back via NDJSON over chunked Transfer-Encoding.

const http = require('http');
const { fork } = require('child_process');
const path = require('path');
const { UnifiedClient } = require('./unified-client');
const { UnifiedServer } = require('./unified-server');
const { WellBehavedServer } = require('./well-behaved-server');
const { WellBehavedClient } = require('./well-behaved-client');
const { Logger } = require('./logger');
const { getScenario, CATEGORY_DEFAULT_DISABLED } = require('./scenarios');
const { getHttp2Scenario } = require('./http2-scenarios');
const { getQuicScenario } = require('./quic-scenarios');
const { getTcpScenario } = require('./tcp-scenarios');
const { getLdapScenario } = require('./ldap/scenarios');
const { isRawAvailable } = require('./raw-tcp');
const { generateServerCert } = require('./cert-gen');
const { computeOverallGrade, normalizeResponse } = require('./grader');
const { runBaseline } = require('./baseline');

function startAgent(role, opts = {}) {
  const controlPort = opts.controlPort || (role === 'client' ? 9200 : 9201);
  const authToken = opts.token || null;

  // Agent state
  const state = {
    role,
    status: 'idle',       // idle | ready | running | done
    scenarios: [],         // resolved scenario objects
    config: {},            // target config (host, port, hostname, etc.)
    results: [],
    report: null,
    eventStreams: [],       // active SSE-like response streams
    fuzzer: null,          // active FuzzerClient or FuzzerServer
    activeWorkers: new Set(), // Set of active ChildProcess workers
  };

  function killWorkers() {
    if (state.activeWorkers.size > 0) {
      console.log(`Killing ${state.activeWorkers.size} active workers...`);
      for (const worker of state.activeWorkers) {
        try {
          if (worker.connected) worker.kill('SIGKILL');
        } catch (_) {}
      }
      state.activeWorkers.clear();
      broadcastEvent({ type: 'status', role, status: state.status, activeWorkerCount: 0 });
    }
  }

  function broadcastEvent(event) {
    const line = JSON.stringify(event) + '\n';
    state.eventStreams = state.eventStreams.filter(res => !res.destroyed);
    for (const res of state.eventStreams) {
      try { res.write(line); } catch (_) {}
    }
  }

  function sendJSON(res, code, body) {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(body));
  }

  const logger = {
    info: (msg) => broadcastEvent({ type: 'logger', event: { type: 'info', ts: new Date().toISOString(), message: msg } }),
    error: (msg) => broadcastEvent({ type: 'logger', event: { type: 'error', ts: new Date().toISOString(), message: msg } }),
    scenario: (name, desc) => broadcastEvent({ type: 'logger', event: { type: 'scenario', ts: new Date().toISOString(), name, description: desc } }),
    fuzz: (msg) => broadcastEvent({ type: 'logger', event: { type: 'fuzz', ts: new Date().toISOString(), message: msg } }),
    sent: (data, label) => {
      const size = data ? (data.length || 0) : 0;
      const hex = data ? data.toString('hex') : '';
      broadcastEvent({ type: 'logger', event: { type: 'sent', ts: new Date().toISOString(), size, hex, label: label || '' } });
    },
    received: (data, label) => {
      const size = data ? (data.length || 0) : 0;
      const hex = data ? data.toString('hex') : '';
      broadcastEvent({ type: 'logger', event: { type: 'received', ts: new Date().toISOString(), size, hex, label: label || '' } });
    },
    tcpEvent: (dir, label) => broadcastEvent({ type: 'logger', event: { type: 'tcp', ts: new Date().toISOString(), direction: dir, event: label } }),
    hostDown: (host, port, scenarioName) => broadcastEvent({ type: 'logger', event: { type: 'host-down', ts: new Date().toISOString(), host, port, scenario: scenarioName } }),
    healthProbe: (host, port, probe) => broadcastEvent({ type: 'logger', event: { type: 'health-probe', ts: new Date().toISOString(), host, port, probe } }),
    result: (name, status, response, verdict, expectedReason, hostDown, finding) => {
      // Result logging is handled by broadcastEvent({ type: 'result' }) separately
    },
    summary: (results, report) => {
      // Summary is handled by broadcastEvent({ type: 'report' }) separately
    }
  };

  const httpServer = http.createServer(async (req, res) => {
    // CORS Preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      });
      res.end();
      return;
    }

    // Basic Auth Check
    if (authToken) {
      const auth = req.headers['authorization'];
      if (!auth || auth !== `Bearer ${authToken}`) {
        return sendJSON(res, 401, { error: 'Unauthorized' });
      }
    }

    const url = new URL(req.url, `http://${req.headers.host}`);
    
    try {
      if (req.method === 'GET' && url.pathname === '/status') return handleStatus(req, res);
      if (req.method === 'GET' && url.pathname === '/results') return handleResults(req, res);
      if (req.method === 'GET' && url.pathname === '/events') return handleEvents(req, res);
      if (req.method === 'POST' && url.pathname === '/configure') return handleConfigure(req, res);
      if (req.method === 'POST' && url.pathname === '/run') return handleRun(req, res);
      if (req.method === 'POST' && url.pathname === '/stop') return handleStop(req, res);

      sendJSON(res, 404, { error: 'Not Found' });
    } catch (err) {
      sendJSON(res, 500, { error: err.message });
    }
  });

  function handleStatus(req, res) {
    sendJSON(res, 200, {
      role: state.role,
      status: state.status,
      scenarioCount: state.scenarios.length,
      completedCount: state.results.length,
      activeWorkerCount: state.activeWorkers.size,
      rawAvailable: isRawAvailable(),
    });
  }

  function handleResults(req, res) {
    sendJSON(res, 200, state.results);
  }

  function handleEvents(req, res) {
    res.writeHead(200, {
      'Content-Type': 'application/x-ndjson',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    // Send current status as first event
    res.write(JSON.stringify({ type: 'status', role, status: state.status, scenarioCount: state.scenarios.length, activeWorkerCount: state.activeWorkers.size }) + '\n');

    state.eventStreams.push(res);

    req.on('close', () => {
      state.eventStreams = state.eventStreams.filter(s => s !== res);
    });
  }

  async function handleConfigure(req, res) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const names = payload.scenarios || [];
        
        state.config = payload.config || {};
        state.results = [];
        state.report = null;
        
        // Resolve and validate scenarios (try TLS, then H2, then QUIC)
        const resolved = [];
        for (const name of names) {
          let s = getScenario(name);
          if (!s) s = (require('./http2-scenarios').getHttp2Scenario(name));
          if (!s) s = (require('./quic-scenarios').getQuicScenario(name));
          if (!s) s = (require('./tcp-scenarios').getTcpScenario(name));
          if (!s) s = getLdapScenario(name);
          
          if (s) resolved.push(s);
        }

        state.scenarios = resolved;
        state.status = 'ready';

        broadcastEvent({ type: 'status', role, status: 'ready', scenarioCount: resolved.length });

        sendJSON(res, 200, {
          ok: true,
          status: 'ready',
          scenarioCount: resolved.length,
        });
      } catch (err) {
        sendJSON(res, 400, { error: err.message });
      }
    });
  }

  function handleRun(req, res) {
    if (state.status === 'running') {
      return sendJSON(res, 400, { error: 'Agent is already running' });
    }
    if (state.scenarios.length === 0) {
      return sendJSON(res, 400, { error: 'No scenarios configured' });
    }

    state.status = 'running';
    state.results = [];
    broadcastEvent({ type: 'status', role, status: 'running' });

    runScenarios();

    sendJSON(res, 200, { ok: true, status: 'running' });
  }

  function handleStop(req, res) {
    state.status = 'idle';
    
    // Stop single-threaded fuzzer
    if (state.fuzzer) {
      if (typeof state.fuzzer.stop === 'function') state.fuzzer.stop();
      if (typeof state.fuzzer.abort === 'function') state.fuzzer.abort();
      if (typeof state.fuzzer.close === 'function') state.fuzzer.close();
      state.fuzzer = null;
    }

    // Stop multi-threaded workers
    killWorkers();

    state.scenarios = [];
    state.results = [];
    state.report = null;
    broadcastEvent({ type: 'status', role, status: 'idle' });
    sendJSON(res, 200, { ok: true, status: 'idle' });
  }

  async function runScenarios() {
    const { scenarios, config } = state;
    const protocol = config.protocol || 'tls';

    if (role === 'client') {
      // Small delay to allow server agent to start listening
      await sleep(500);
    }

    // Server role must be sequential as it binds to a single port
    const workers = role === 'server' ? 1 : (parseInt(config.workers) || 1);
    const host = config.host;
    const port = config.port;

    if (role === 'server') {
      // --- SERVER ROLE LOGIC ---
      const timeout = parseInt(config.timeout) || 10000;
      const delay = parseInt(config.delay) || 100;
      const server = new UnifiedServer({ port, hostname: config.hostname || config.host, timeout, delay, logger });
      state.fuzzer = server;

      if (workers > 1) {
        // Multi-threaded server mode (experimental)
        // Fork workers that wait for a socket via IPC
        const queue = scenarios.map(s => s.name);
        const total = queue.length;
        let completed = 0;
        let active = 0;

        const runNext = async () => {
          if (state.status !== 'running') return;
          
          // Always try to fill available worker slots
          while (active < workers && queue.length > 0) {
            const scenarioName = queue.shift();
            active++;
            
            // Small delay between spawns to prevent process flood/bursts
            if (active > 1) await sleep(50);

            try {
              const workerConfig = { ...config, role };
              const worker = fork(path.join(__dirname, 'agent-worker.js'), [
                JSON.stringify(workerConfig),
                scenarioName
              ]);
              state.activeWorkers.add(worker);

              worker.on('message', (msg) => {
                try {
                  if (msg.type === 'logger') {
                    broadcastEvent({ type: 'logger', event: msg.event });
                  } else if (msg.type === 'result') {
                    // Skip well-behaved counterpart results — they are internal helpers, not actual tests
                    if (!(msg.result.scenario && msg.result.scenario.startsWith('well-behaved-'))) {
                      state.results.push(msg.result);
                      broadcastEvent({ type: 'result', result: msg.result });
                    }
                    if (worker.connected) worker.send({ type: 'ack' });
                  } else if (msg.type === 'error') {
                    broadcastEvent({ type: 'error', message: msg.message });
                  }
                } catch (err) {
                  console.error(`Error handling worker message: ${err.message}`);
                  if (msg.type === 'result' && worker.connected) worker.send({ type: 'ack' });
                }
              });

              worker.on('exit', (code) => {
                state.activeWorkers.delete(worker);
                active--;
                completed++;
                broadcastEvent({ type: 'progress', current: completed, total, scenario: scenarioName, activeWorkerCount: active });
                
                if (completed >= total && active === 0) {
                  try {
                    state.report = computeOverallGrade(state.results);
                    logger.summary(state.results, state.report);
                    broadcastEvent({ type: 'report', report: state.report });
                  } catch (e) {
                    broadcastEvent({ type: 'error', message: `Report generation failed: ${e.message}` });
                  } finally {
                    state.status = 'done';
                    broadcastEvent({ type: 'done', role });
                  }
                } else {
                  runNext();
                }
              });

              worker.on('error', (err) => {
                broadcastEvent({ type: 'error', message: `Worker process error: ${err.message}` });
              });
            } catch (err) {
              active--;
              completed++; // Count as completed (with error) so we don't hang
              broadcastEvent({ type: 'error', message: `Failed to fork worker for ${scenarioName}: ${err.message}` });
              if (completed >= total && active === 0) {
                state.status = 'done';
                broadcastEvent({ type: 'done', role });
              } else {
                runNext();
              }
            }
          }
        };

        // Start initial batch
        runNext();
        return;
      }

      // Sequential server logic (fallback)
      if (protocol === 'h2') await server.startH2();
      else if (protocol === 'quic') await server.startQuic();

      for (let i = 0; i < scenarios.length; i++) {
        if (state.status !== 'running') break;
        // Clean up between scenarios to prevent resource accumulation
        if (server._cleanupBetweenScenarios) server._cleanupBetweenScenarios();
        // Periodic resource diagnostics
        if ((i + 1) % 200 === 0) {
          try {
            const fs = require('fs');
            const fdCount = fs.readdirSync('/dev/fd').length;
            logger.info(`[diag] Test #${i + 1}: open FDs=${fdCount}, activeSockets=${server.activeSockets.size}, heapMB=${Math.round(process.memoryUsage().heapUsed / 1048576)}`);
          } catch (_) {
            logger.info(`[diag] Test #${i + 1}: activeSockets=${server.activeSockets.size}, heapMB=${Math.round(process.memoryUsage().heapUsed / 1048576)}`);
          }
        }
        broadcastEvent({ type: 'progress', scenario: scenarios[i].name, current: i + 1, total: scenarios.length });
        const result = await server.runScenario(scenarios[i]);
        state.results.push(result);
        broadcastEvent({ type: 'result', result });
        await sleep(100);
      }

      try {
        state.report = computeOverallGrade(state.results);
        logger.summary(state.results, state.report);
        broadcastEvent({ type: 'report', report: state.report });
      } catch (e) {
        broadcastEvent({ type: 'error', message: `Report generation failed: ${e.message}` });
      } finally {
        state.status = 'done';
        broadcastEvent({ type: 'done', role });
      }

    } else {
      // --- CLIENT ROLE LOGIC ---
      if (workers > 1) {
        // Reusable worker pool — fork N long-lived workers, feed scenarios via IPC.
        // Previous fork-per-scenario model leaked FDs after ~1100 cycles.
        const queue = scenarios.map(s => s.name);
        const total = queue.length;
        let completed = 0;
        const numWorkers = Math.min(workers, queue.length);

        await new Promise((resolve) => {
          let activeCount = 0;
          for (let i = 0; i < numWorkers; i++) {
            const worker = fork(path.join(__dirname, 'agent-worker-pool.js'));
            state.activeWorkers.add(worker);
            activeCount++;

            worker.on('message', (msg) => {
              try {
                if (msg.type === 'ready') {
                  // Worker ready — assign next scenario from queue
                  if (state.status !== 'running' || queue.length === 0) {
                    worker.send({ cmd: 'abort' });
                    return;
                  }
                  const scenarioName = queue.shift();
                  broadcastEvent({ type: 'progress', scenario: scenarioName, current: completed + 1, total, activeWorkerCount: state.activeWorkers.size });
                  worker.send({ cmd: 'run', scenarioName, protocol: config.protocol, baseline: config.baseline });
                } else if (msg.type === 'logger') {
                  broadcastEvent({ type: 'logger', event: msg.event });
                } else if (msg.type === 'result') {
                  if (!(msg.result.scenario && msg.result.scenario.startsWith('well-behaved-'))) {
                    state.results.push(msg.result);
                    broadcastEvent({ type: 'result', result: msg.result });
                  }
                  completed++;
                  broadcastEvent({ type: 'progress', current: completed, total, scenario: msg.result.scenario, activeWorkerCount: state.activeWorkers.size });
                  if (completed >= total) {
                    // All done — kill remaining workers
                    for (const w of state.activeWorkers) {
                      try { if (w.connected) w.send({ cmd: 'abort' }); } catch (_) {}
                    }
                  }
                } else if (msg.type === 'error') {
                  broadcastEvent({ type: 'error', message: msg.message });
                }
              } catch (err) {
                console.error(`Error handling worker message: ${err.message}`);
              }
            });

            worker.on('exit', () => {
              state.activeWorkers.delete(worker);
              activeCount--;
              if (activeCount === 0) {
                try {
                  state.report = computeOverallGrade(state.results);
                  logger.summary(state.results, state.report);
                  broadcastEvent({ type: 'report', report: state.report });
                } catch (e) {
                  broadcastEvent({ type: 'error', message: `Report generation failed: ${e.message}` });
                } finally {
                  state.status = 'done';
                  broadcastEvent({ type: 'done', role });
                  resolve();
                }
              }
            });

            worker.on('error', (err) => {
              broadcastEvent({ type: 'error', message: `Worker process error: ${err.message}` });
            });

            // Initialize worker with client config
            worker.send({
              cmd: 'init', host, port, protocol: config.protocol,
              timeout: parseInt(config.timeout) || 5000,
              delay: parseInt(config.delay) || 100,
              dut: config.dut || null,
              pcapFile: config.pcapFile || null,
            });
          }
        });
        return;
      }

      // Single-threaded fallback
      const timeout = parseInt(config.timeout) || 5000;
      const delay = parseInt(config.delay) || 100;
      const dut = config.dut || null;

      const pcapFile = config.pcapFile || null;
      const client = new UnifiedClient({ host, port, timeout, delay, logger, dut, pcapFile });
      state.fuzzer = client;

      for (let i = 0; i < scenarios.length; i++) {
        if (client.aborted) break;
        broadcastEvent({ type: 'progress', scenario: scenarios[i].name, current: i + 1, total: scenarios.length });
        try {
          let baselineRes = null;
          if (config.baseline) {
            broadcastEvent({ type: 'logger', event: { type: 'info', ts: new Date().toISOString(), message: `[baseline] testing against local OpenSSL...` } });
            try {
              baselineRes = await runBaseline(scenarios[i], protocol);
            } catch (e) {
              broadcastEvent({ type: 'logger', event: { type: 'info', ts: new Date().toISOString(), message: `[baseline] failed: ${e.message}` } });
            }
          }
          const result = await client.runScenario(scenarios[i]);
          if (baselineRes) {
            result.baselineResponse = baselineRes.response;
            result.baselineCommand = baselineRes.command;
          }
          state.results.push(result);
          broadcastEvent({ type: 'result', result });
        } catch (err) {
          broadcastEvent({ type: 'error', message: err.message });
        }
        await sleep(config.delay || 100);
      }

      try {
        state.report = computeOverallGrade(state.results);
        logger.summary(state.results, state.report);
        broadcastEvent({ type: 'report', report: state.report });
      } catch (e) {
        broadcastEvent({ type: 'error', message: `Report generation failed: ${e.message}` });
      } finally {
        state.status = 'done';
        broadcastEvent({ type: 'done', role });
      }
    }
  }

  httpServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n  \x1b[31mError: Port ${controlPort} is already in use.\x1b[0m`);
      console.error(`  Another agent or service is likely running on this port.`);
      console.error(`  Use --control-port <port> to start this agent on a different port.\n`);
      process.exit(1);
    } else {
      console.error(`\n  \x1b[31mAgent HTTP server error: ${err.message}\x1b[0m\n`);
    }
  });

  httpServer.listen(controlPort, '0.0.0.0', () => {
    console.log('');
    console.log(`  TLS/TCP Protocol Fuzzer — ${role === 'client' ? 'Client' : 'Server'} Agent`);
    console.log('');
    if (!authToken) {
      console.log('  \x1b[33mWARNING: No authentication token set. Use --token to secure this agent.\x1b[0m');
    }
    console.log(`  Control API   http://0.0.0.0:${controlPort}`);
    console.log(`  Role          ${role}`);
    console.log(`  Status        idle — waiting for configuration`);
    console.log('');
    console.log('  Endpoints:');
    console.log('    POST /configure — Set target and scenarios');
    console.log('    POST /run       — Start execution');
    console.log('    POST /stop      — Stop execution');
    console.log('    GET  /status    — Current agent status');
    console.log('    GET  /events    — NDJSON event stream');
    console.log('    GET  /results    — Final results');
    console.log('');
  });

  return httpServer;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

module.exports = { startAgent };
