// Remote Agent — HTTP control server for distributed fuzzing
// Runs on a remote VM, receives configuration from the controller (Electron UI),
// and streams results back via NDJSON over chunked Transfer-Encoding.

const http = require('http');
const { FuzzerClient } = require('./fuzzer-client');
const { FuzzerServer } = require('./fuzzer-server');
const { Logger } = require('./logger');
const { getScenario, CATEGORY_DEFAULT_DISABLED } = require('./scenarios');
const { generateServerCert } = require('./cert-gen');
const { computeOverallGrade } = require('./grader');

function startAgent(role, opts = {}) {
  const controlPort = opts.controlPort || (role === 'client' ? 9100 : 9101);

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
    res.writeHead(statusCode, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      'Access-Control-Allow-Origin': '*',
    });
    res.end(body);
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

    // Resolve and validate scenarios
    const resolved = [];
    const errors = [];
    for (const name of scenarioNames) {
      const s = getScenario(name);
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

    if (role === 'client') {
      const host = config.host || 'localhost';
      const port = parseInt(config.port) || 443;
      const timeout = parseInt(config.timeout) || 5000;
      const delay = parseInt(config.delay) || 100;
      const dut = config.dut || null;

      const client = new FuzzerClient({ host, port, timeout, delay, logger, dut });
      state.fuzzer = client;

      for (let i = 0; i < scenarios.length; i++) {
        if (client.aborted) break;
        broadcastEvent({ type: 'progress', scenario: scenarios[i].name, current: i + 1, total: scenarios.length });
        const result = await client.runScenario(scenarios[i]);
        state.results.push(result);
        broadcastEvent({ type: 'result', result });
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

      const certInfo = generateServerCert(hostname);

      const server = new FuzzerServer({
        port, hostname, timeout, delay, logger,
        cert: certInfo.certDER, certInfo,
        dut,
      });
      state.fuzzer = server;

      broadcastEvent({
        type: 'logger',
        event: {
          type: 'info',
          ts: new Date().toISOString(),
          message: `Server certificate: CN=${hostname} | SHA256=${certInfo.fingerprint}`,
        },
      });

      for (let i = 0; i < scenarios.length; i++) {
        if (server.aborted) break;
        broadcastEvent({ type: 'progress', scenario: scenarios[i].name, current: i + 1, total: scenarios.length });
        const result = await server.runScenario(scenarios[i]);
        state.results.push(result);
        broadcastEvent({ type: 'result', result });
        await sleep(300);
      }

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
    });
  }

  function handleResults(req, res) {
    sendJSON(res, 200, {
      results: state.results,
      report: state.report,
    });
  }

  // Create HTTP server
  const httpServer = http.createServer(async (req, res) => {
    // CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      });
      return res.end();
    }

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

  httpServer.listen(controlPort, '0.0.0.0', () => {
    console.log('');
    console.log(`  \x1b[1m\x1b[36mTLS/TCP Protocol Fuzzer — ${role === 'client' ? 'Client' : 'Server'} Agent\x1b[0m`);
    console.log('');
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
