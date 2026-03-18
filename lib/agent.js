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
  };

  function broadcastEvent(event) {
    const line = JSON.stringify(event) + '\n';
    state.eventStreams = state.eventStreams.filter(res => !res.destroyed);
    for (const res of state.eventStreams) {
      try { res.write(line); } catch (_) {}
    }
  }

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try { resolve(body ? JSON.parse(body) : {}); }
        catch (e) { reject(new Error('Invalid JSON')); }
      });
      req.on('error', reject);
    });
  }

  function sendJSON(res, statusCode, data) {
    const body = JSON.stringify(data);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    };
    // Only allow CORS if we have a token (secure mode) or if explicitly allowed
    if (authToken) {
      headers['Access-Control-Allow-Origin'] = '*';
    }
    res.writeHead(statusCode, headers);
    res.end(body);
  }

  function checkAuth(req, res) {
    if (!authToken) return true;
    const authHeader = req.headers['authorization'];
    if (!authHeader || authHeader !== `Bearer ${authToken}`) {
      sendJSON(res, 401, { error: 'Unauthorized — valid token required' });
      return false;
    }
    return true;
  }

  async function handleConfigure(req, res) {
    if (state.status === 'running') {
      return sendJSON(res, 409, { error: 'Agent is running, stop first' });
    }

    let body;
    try { body = await readBody(req); }
    catch (e) { return sendJSON(res, 400, { error: e.message }); }

    const { scenarios: scenarioNames, config } = body;
    if (!Array.isArray(scenarioNames) || scenarioNames.length === 0) {
      return sendJSON(res, 400, { error: 'scenarios must be a non-empty array of scenario names' });
    }

    // Resolve and validate scenarios (try TLS, then H2, then QUIC)
    const protocol = config && config.protocol;
    const lookup = (name) => {
      let s;
      if (protocol === 'raw-tcp') s = getTcpScenario(name);
      else if (protocol === 'quic') s = getQuicScenario(name);
      else if (protocol === 'h2') s = getHttp2Scenario(name);

      if (!s) {
        s = getScenario(name) || getHttp2Scenario(name) || getQuicScenario(name) || getTcpScenario(name);
      }
      return s;
    };

    const resolved = [];
    const errors = [];
    for (const name of scenarioNames) {
      const s = lookup(name);
      if (!s) { errors.push(`Unknown scenario: ${name}`); continue; }
      if (s.side !== role) { errors.push(`Scenario "${name}" is ${s.side}-side, agent is ${role}`); continue; }
      resolved.push(s);
    }

    if (errors.length > 0 && resolved.length === 0) {
      return sendJSON(res, 400, { error: errors.join('; ') });
    }

    state.scenarios = resolved;
    state.config = config || {};
    state.results = [];
    state.report = null;
    state.status = 'ready';

    broadcastEvent({ type: 'status', role, status: 'ready', scenarioCount: resolved.length });

    sendJSON(res, 200, {
      ok: true,
      status: 'ready',
      scenarioCount: resolved.length,
      warnings: errors.length > 0 ? errors : undefined,
    });
  }

  async function handleRun(req, res) {
    if (state.status !== 'ready') {
      return sendJSON(res, 409, { error: `Cannot run: agent is ${state.status}, must be ready` });
    }

    state.status = 'running';
    state.results = [];
    state.report = null;
    broadcastEvent({ type: 'status', role, status: 'running' });
    sendJSON(res, 200, { ok: true, status: 'running' });

    // Run asynchronously
    runScenarios().catch(err => {
      broadcastEvent({ type: 'error', message: err.message });
      state.status = 'done';
      broadcastEvent({ type: 'done', role });
    });
  }

  async function runScenarios() {
    const logger = new Logger({ verbose: false });

    // Forward all logger events to event streams
    logger.onEvent(event => {
      broadcastEvent({ type: 'logger', event });
    });

    const scenarios = state.scenarios;
    const config = state.config;
    const protocol = config.protocol || 'tls';

    if (role === 'client') {
      const workers = parseInt(config.workers) || 1;
      let host = config.host || 'localhost';
      let port = parseInt(config.port) || 443;

      if (workers > 1) {
        broadcastEvent({ type: 'logger', event: { type: 'info', ts: new Date().toISOString(), message: `Starting distributed run with ${workers} worker threads...` } });
        
        const queue = scenarios.map(s => s.name);
        const total = queue.length;
        let completed = 0;
        let active = 0;

        const runNext = () => {
          if (queue.length === 0) return;
          
          const scenarioName = queue.shift();
          active++;
          
          const worker = fork(path.join(__dirname, 'agent-worker.js'), [
            JSON.stringify(config),
            scenarioName
          ]);

          worker.on('message', (msg) => {
            if (msg.type === 'logger') {
              broadcastEvent({ type: 'logger', event: msg.event });
            } else if (msg.type === 'result') {
              // Skip well-behaved counterpart results — they are internal helpers, not actual tests
              if (!(msg.result.scenario && msg.result.scenario.startsWith('well-behaved-'))) {
                state.results.push(msg.result);
                broadcastEvent({ type: 'result', result: msg.result });
              }
            } else if (msg.type === 'error') {
              broadcastEvent({ type: 'error', message: msg.message });
            }
          });

          worker.on('exit', () => {
            active--;
            completed++;
            broadcastEvent({ type: 'progress', current: completed, total });
            
            if (completed === total) {
              state.report = computeOverallGrade(state.results);
              logger.summary(state.results, state.report);
              broadcastEvent({ type: 'report', report: state.report });
              state.status = 'done';
              broadcastEvent({ type: 'done', role });
            } else {
              runNext();
            }
          });
        };

        for (let i = 0; i < Math.min(workers, total); i++) {
          runNext();
        }
        return;
      }

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
          // Skip well-behaved counterpart results — they are internal helpers, not actual tests
          if (result.scenario && result.scenario.startsWith('well-behaved-')) continue;
          state.results.push(result);
          broadcastEvent({ type: 'result', result });
        } catch (err) {
          if (scenarios[i].name && scenarios[i].name.startsWith('well-behaved-')) continue;
          const errResult = {
            scenario: scenarios[i].name,
            description: scenarios[i].description,
            category: scenarios[i].category,
            severity: 'high',
            status: 'ERROR',
            expected: scenarios[i].expected,
            verdict: 'N/A',
            response: err.message,
            compliance: null,
            finding: { grade: 'FAIL', severity: 'high', reason: `Scenario crashed: ${err.message}` },
            hostDown: false,
            probe: null,
          };
          state.results.push(errResult);
          broadcastEvent({ type: 'result', result: errResult });
        }
        await sleep(300);
      }

      client.close();
      state.fuzzer = null;

      state.report = computeOverallGrade(state.results);
      logger.summary(state.results, state.report);
      broadcastEvent({ type: 'report', report: state.report });

    } else {
      // Server role
      const hostname = config.hostname || 'localhost';
      const port = parseInt(config.port) || 4433;
      const timeout = parseInt(config.timeout) || 10000;
      const delay = parseInt(config.delay) || 100;
      const dut = config.dut || null;

      const pcapFile = config.pcapFile || null;
      const server = new UnifiedServer({
        port, hostname, timeout, delay, logger,
        dut, pcapFile,
      });
      state.fuzzer = server;

      const certInfo = server.getCertInfo();
      broadcastEvent({
        type: 'logger',
        event: {
          type: 'info',
          ts: new Date().toISOString(),
          message: `Server certificate: CN=${hostname} | SHA256=${certInfo.fingerprint}`,
        },
      });

      // Start protocol-specific server if needed
      if (protocol === 'h2') {
        await server.startH2();
      } else if (protocol === 'quic') {
        await server.startQuic();
      }

      for (let i = 0; i < scenarios.length; i++) {
        if (server.aborted) break;
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
          const result = await server.runScenario(scenarios[i]);
          if (baselineRes) {
            result.baselineResponse = baselineRes.response;
            result.baselineCommand = baselineRes.command;
          }
          // Skip well-behaved counterpart results — they are internal helpers, not actual tests
          if (result.scenario && result.scenario.startsWith('well-behaved-')) continue;
          state.results.push(result);
          broadcastEvent({ type: 'result', result });
        } catch (err) {
          if (scenarios[i].name && scenarios[i].name.startsWith('well-behaved-')) continue;
          const errResult = {
            scenario: scenarios[i].name,
            description: scenarios[i].description,
            category: scenarios[i].category,
            severity: 'high',
            status: 'ERROR',
            expected: scenarios[i].expected,
            verdict: 'N/A',
            response: err.message,
            compliance: null,
            finding: { grade: 'FAIL', severity: 'high', reason: `Scenario crashed: ${err.message}` },
            hostDown: false,
            probe: null,
          };
          state.results.push(errResult);
          broadcastEvent({ type: 'result', result: errResult });
        }
        await sleep(300);
      }

      server.close();
      state.fuzzer = null;

      state.report = computeOverallGrade(state.results);
      logger.summary(state.results, state.report);
      broadcastEvent({ type: 'report', report: state.report });
    }

    state.status = 'done';
    broadcastEvent({ type: 'done', role });
  }

  function handleStop(req, res) {
    if (state.fuzzer) {
      state.fuzzer.abort();
    }
    state.status = 'idle';
    state.scenarios = [];
    state.results = [];
    state.report = null;
    broadcastEvent({ type: 'status', role, status: 'idle' });
    sendJSON(res, 200, { ok: true, status: 'idle' });
  }

  function handleEvents(req, res) {
    res.writeHead(200, {
      'Content-Type': 'application/x-ndjson',
      'Transfer-Encoding': 'chunked',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    // Send current status as first event
    res.write(JSON.stringify({ type: 'status', role, status: state.status, scenarioCount: state.scenarios.length }) + '\n');

    state.eventStreams.push(res);

    req.on('close', () => {
      state.eventStreams = state.eventStreams.filter(s => s !== res);
    });
  }

  function handleStatus(req, res) {
    sendJSON(res, 200, {
      role: state.role,
      status: state.status,
      scenarioCount: state.scenarios.length,
      completedCount: state.results.length,
      rawAvailable: isRawAvailable(),
    });
  }

  function handleResults(req, res) {
    sendJSON(res, 200, {
      results: state.results,
      report: state.report,
    });
  }

  // Create HTTP server with TCP keepalive for connection health monitoring
  const httpServer = http.createServer(async (req, res) => {
    // CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      });
      return res.end();
    }

    if (!checkAuth(req, res)) return;

    const url = req.url.split('?')[0];

    try {
      if (url === '/status' && req.method === 'GET') return handleStatus(req, res);
      if (url === '/configure' && req.method === 'POST') return await handleConfigure(req, res);
      if (url === '/run' && req.method === 'POST') return handleRun(req, res);
      if (url === '/stop' && req.method === 'POST') return handleStop(req, res);
      if (url === '/events' && req.method === 'GET') return handleEvents(req, res);
      if (url === '/results' && req.method === 'GET') return handleResults(req, res);

      sendJSON(res, 404, { error: 'Not found' });
    } catch (err) {
      sendJSON(res, 500, { error: err.message });
    }
  });

  httpServer.keepAliveTimeout = 3000;
  httpServer.on('connection', (socket) => {
    socket.setKeepAlive(true, 500);
  });

  httpServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error('');
      console.error(`  \x1b[31m\x1b[1mERROR: Port ${controlPort} is already in use.\x1b[0m`);
      console.error(`  \x1b[90mOn Ubuntu, port 9100 is often used by CUPS (printing/JetDirect).\x1b[0m`);
      console.error(`  \x1b[90mCheck with:\x1b[0m  sudo lsof -i :${controlPort}`);
      console.error(`  \x1b[90mUse a different port:\x1b[0m  node ${role === 'client' ? 'client' : 'server'}.js --control-port ${controlPort + 100}`);
      console.error('');
    } else {
      console.error(`  \x1b[31m\x1b[1mERROR: ${err.message}\x1b[0m`);
    }
    process.exit(1);
  });

  httpServer.listen(controlPort, '::', () => {
    console.log('');
    console.log(`  \x1b[1m\x1b[36mTLS/TCP Protocol Fuzzer — ${role === 'client' ? 'Client' : 'Server'} Agent\x1b[0m`);
    console.log('');
    if (!authToken) {
      console.log(`  \x1b[31m\x1b[1mWARNING: No authentication token set. Use --token to secure this agent.\x1b[0m`);
    }
    console.log(`  \x1b[90mControl API\x1b[0m   http://0.0.0.0:${controlPort}`);
    console.log(`  \x1b[90mRole\x1b[0m          ${role}`);
    console.log(`  \x1b[90mStatus\x1b[0m        idle — waiting for configuration`);
    console.log('');
    console.log('  Endpoints:');
    console.log('    GET  /status     — Agent status');
    console.log('    POST /configure  — Push test cases');
    console.log('    POST /run        — Start execution');
    console.log('    POST /stop       — Abort');
    console.log('    GET  /events     — NDJSON event stream');
    console.log('    GET  /results    — Final results');
    console.log('');
  });

  return httpServer;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

module.exports = { startAgent };
