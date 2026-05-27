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
const { ScenarioTracer } = require('./tracer');
const { scenarioFingerprint } = require('./run-manifest');

// Stable transport rank: 0=TCP/TLS/raw, 1=H2, 2=QUIC.
// Used to batch scenarios so the listener / engine doesn't churn.
function transportRank(s) {
  const cat = typeof s.category === 'string' ? s.category : '';
  // QUIC scenarios use category codes QA–QL, QS, QSCAN
  if (cat.length >= 2 && cat[0] === 'Q' && /^Q[A-Z]/.test(cat)) return 2;
  if (s.useQuiche || s.protocol === 'quic') return 2;
  // Custom server scenarios (e.g. CV cert-verify) use raw TCP — rank 0, not H2
  if (s.useCustomServer) return 0;
  // H2 scenarios carry a serverHandler / clientHandler hook
  if (typeof s.serverHandler === 'function' || s.protocol === 'h2') return 1;
  // Raw TCP categories RA–RH
  if (cat.length === 2 && cat[0] === 'R' && cat[1] >= 'A' && cat[1] <= 'H') return 0;
  return 0;
}

function groupByTransport(scenarios) {
  return scenarios
    .map((s, i) => ({ s, i, r: transportRank(s) }))
    .sort((a, b) => (a.r - b.r) || (a.i - b.i))
    .map(x => x.s);
}

// Back-compat aliases for helper counterpart scenario names used by older UI
// code and ad hoc scripts. Keep these narrow so the unknown-scenario guard
// still catches real typos instead of silently accepting them.
const SCENARIO_ALIASES = new Map([
  ['well-behaved-client', 'fv-tls-well-behaved-small-ch'],
]);

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
    tracer: null,          // optional ScenarioTracer (when config.traceDir is set)
    scenarioFingerprints: [], // [{ name, category, fingerprint }] — cached per run
    currentScenarioName: null, // name of the scenario the fuzzer is running right now
    currentPairId: null,
    currentScenarioRunId: null,
    currentAction: null,
    lastAction: null,
    debugResults: [],
    helperPairIds: new Set(),
    hasExplicitHelperPairs: false,
    // Run-generation token. Bumped on /configure and /stop. Each
    // handleRunScenario() captures this value at entry; before mutating any
    // shared state after an `await`, it re-checks against state.runId. A
    // mismatch means a /stop or /configure has superseded this scenario, so
    // its result is silently dropped instead of leaking into the next run.
    runId: 0,
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

  // Fan out a traced event to the scenario tracer if one is open. Called by
  // every logger method below so the NDJSON trace file mirrors the NDJSON
  // event stream, plus a monotonic timestamp from scenario start.
  const tr = (event, data) => {
    if (state.tracer) state.tracer.record(event, data);
  };

  const logger = {
    info: (msg) => { broadcastEvent({ type: 'logger', event: { type: 'info', ts: new Date().toISOString(), message: msg } }); tr('info', { message: msg }); },
    error: (msg) => { broadcastEvent({ type: 'logger', event: { type: 'error', ts: new Date().toISOString(), message: msg } }); tr('error', { message: msg }); },
    scenario: (name, desc) => { broadcastEvent({ type: 'logger', event: { type: 'scenario', ts: new Date().toISOString(), name, description: desc } }); tr('scenario', { name, description: desc }); },
    fuzz: (msg) => { broadcastEvent({ type: 'logger', event: { type: 'fuzz', ts: new Date().toISOString(), message: msg } }); tr('fuzz', { message: msg }); },
    sent: (data, label) => {
      const size = data ? (data.length || 0) : 0;
      const hex = data ? data.toString('hex') : '';
      broadcastEvent({ type: 'logger', event: { type: 'sent', ts: new Date().toISOString(), size, hex, label: label || '' } });
      tr('sent', { size, label: label || '' });
    },
    received: (data, label) => {
      const size = data ? (data.length || 0) : 0;
      const hex = data ? data.toString('hex') : '';
      broadcastEvent({ type: 'logger', event: { type: 'received', ts: new Date().toISOString(), size, hex, label: label || '' } });
      tr('received', { size, label: label || '' });
    },
    tcpEvent: (dir, label) => { broadcastEvent({ type: 'logger', event: { type: 'tcp', ts: new Date().toISOString(), direction: dir, event: label } }); tr('tcp', { direction: dir, event: label }); },
    // Cross-peer sync — emitted when the fuzzer hits `{ type: 'barrier' }`.
    // The controller matches by (scenario, label) and POSTs /release-barrier
    // to both agents once both sides arrive.
    barrierArrived: (scenario, label, role) => {
      broadcastEvent({
        type: 'barrier-arrived',
        ts: new Date().toISOString(),
        scenario,
        label,
        role,
        pairId: state.currentPairId,
        runId: state.currentScenarioRunId,
      });
      tr('barrier-arrived', { label, role, pairId: state.currentPairId, runId: state.currentScenarioRunId });
    },
    // Emitted when the fuzzer hits `{ type: 'peer-done' }`. The controller
    // reacts by POSTing /abort-scenario to the peer agent.
    peerDone: (scenario, role) => {
      broadcastEvent({
        type: 'peer-done',
        ts: new Date().toISOString(),
        scenario,
        role,
        pairId: state.currentPairId,
        runId: state.currentScenarioRunId,
      });
      tr('peer-done', { role, pairId: state.currentPairId, runId: state.currentScenarioRunId });
    },
    action: (data) => {
      state.currentAction = { ...(data || {}), updatedAt: new Date().toISOString() };
      state.lastAction = state.currentAction;
      broadcastEvent({ type: 'action', action: state.currentAction });
      tr('action', state.currentAction);
    },
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
      if (req.method === 'GET' && url.pathname === '/debug-state') return handleDebugState(req, res);
      if (req.method === 'GET' && url.pathname === '/ready') return handleReady(req, res);
      if (req.method === 'GET' && url.pathname === '/results') return handleResults(req, res);
      if (req.method === 'GET' && url.pathname === '/events') return handleEvents(req, res);
      if (req.method === 'POST' && url.pathname === '/configure') return handleConfigure(req, res);
      if (req.method === 'POST' && url.pathname === '/run') return handleRun(req, res);
      if (req.method === 'POST' && url.pathname === '/run-scenario') return handleRunScenario(req, res);
      if (req.method === 'POST' && url.pathname === '/finish') return handleFinish(req, res);
      if (req.method === 'POST' && url.pathname === '/stop') return handleStop(req, res);
      if (req.method === 'POST' && url.pathname === '/abort-scenario') return handleAbortScenario(req, res);
      if (req.method === 'POST' && url.pathname === '/release-barrier') return handleReleaseBarrier(req, res);

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
      currentScenarioName: state.currentScenarioName,
      currentPairId: state.currentPairId,
      currentScenarioRunId: state.currentScenarioRunId,
      currentAction: state.currentAction,
    });
  }

  function buildDebugState() {
    const fuzzer = state.fuzzer;
    let fuzzerState = null;
    if (fuzzer && typeof fuzzer.getDebugState === 'function') {
      try { fuzzerState = fuzzer.getDebugState(); } catch (err) { fuzzerState = { error: err.message }; }
    } else if (fuzzer) {
      fuzzerState = {
        type: fuzzer.constructor && fuzzer.constructor.name,
        activeSocketCount: fuzzer.activeSockets && typeof fuzzer.activeSockets.size === 'number' ? fuzzer.activeSockets.size : undefined,
        activeChildProcessCount: fuzzer.activeChildProcesses && typeof fuzzer.activeChildProcesses.size === 'number' ? fuzzer.activeChildProcesses.size : undefined,
        lastClientPort: fuzzer._lastClientPort || null,
        scenarioAborted: !!fuzzer._scenarioAborted,
        distributedPairId: fuzzer._distributedPairId || null,
        distributedRunId: fuzzer._distributedRunId !== undefined ? fuzzer._distributedRunId : null,
      };
    }
    return {
      capturedAt: new Date().toISOString(),
      agent: {
        role: state.role,
        status: state.status,
        scenarioCount: state.scenarios.length,
        completedCount: state.results.length,
        activeWorkerCount: state.activeWorkers.size,
        rawAvailable: isRawAvailable(),
        currentScenarioName: state.currentScenarioName,
        currentPairId: state.currentPairId,
        currentScenarioRunId: state.currentScenarioRunId,
        currentAction: state.currentAction,
        lastAction: state.lastAction,
      },
      fuzzer: fuzzerState,
      debugResults: state.debugResults.slice(-10),
    };
  }

  function handleDebugState(req, res) {
    sendJSON(res, 200, buildDebugState());
  }

  // Cheap readiness probe — replaces the controller's fixed 300ms sleep.
  // For the server role, "ready" means the listener is bound and accepting.
  // For the client role, we're always ready once the HTTP agent is up.
  function handleReady(req, res) {
    let ready;
    if (role === 'server') {
      const fuzzer = state.fuzzer;
      ready = !!state.serverStarted && !!(
        (fuzzer && fuzzer.tcpServer && fuzzer.tcpServer.listening) ||
        (fuzzer && fuzzer.h2Server && fuzzer.h2Server.listening) ||
        (fuzzer && fuzzer.quicServer)
      );
    } else {
      ready = true;
    }
    sendJSON(res, 200, { ready, role, status: state.status });
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

    res.on('error', (err) => {
      state.eventStreams = state.eventStreams.filter(s => s !== res);
    });

    req.on('close', () => {
      state.eventStreams = state.eventStreams.filter(s => s !== res);
    });
  }

  process.on('uncaughtException', (err) => {
    console.error(`\n[FATAL] Uncaught Exception: ${err.message}`);
    console.error(err.stack);
  });

  process.on('unhandledRejection', (reason, promise) => {
    console.error('\n[FATAL] Unhandled Rejection at:', promise, 'reason:', reason);
  });

  // Wait for all child workers to emit 'exit' after we SIGKILL them.
  // Without this, a /stop response can return while workers are still holding
  // FDs and ports, so the next run's /configure + /run races their shutdown.
  function awaitWorkersExited(graceMs = 2000) {
    if (state.activeWorkers.size === 0) return Promise.resolve();
    return new Promise((resolve) => {
      const deadline = Date.now() + graceMs;
      const poll = () => {
        if (state.activeWorkers.size === 0 || Date.now() >= deadline) return resolve();
        setTimeout(poll, 25);
      };
      poll();
    });
  }

  const cleanup = async () => {
    state.status = 'idle';
    state.serverStarted = false;
    if (state.fuzzer) {
      // _scenarioAborted flag is read by action loops to bail out of awaits.
      if (typeof state.fuzzer._scenarioAborted !== 'undefined') state.fuzzer._scenarioAborted = true;
      // Wake any blocked server-side accept-wait synchronously so the
      // in-flight scenario unwinds before /stop returns. abort() also calls
      // this, but calling it first ensures the rejection runs before the
      // listener is closed (closing the listener doesn't wake waiters).
      if (typeof state.fuzzer.cancelScenarioWaits === 'function') {
        state.fuzzer.cancelScenarioWaits('Server stopped');
      }
      if (typeof state.fuzzer.stop === 'function') state.fuzzer.stop();
      if (typeof state.fuzzer.abort === 'function') state.fuzzer.abort();
      if (typeof state.fuzzer.close === 'function') state.fuzzer.close();
      state.fuzzer = null;
    }
    // Flush the scenario trace so a mid-run stop leaves the file consistent.
    if (state.tracer) {
      try { state.tracer.close({ status: 'CANCELLED' }); } catch (_) {}
    }
    killWorkers();
    await awaitWorkersExited();
  };

  process.on('SIGINT', async () => {
    console.log('\nAgent received SIGINT. Cleaning up...');
    try { await cleanup(); } catch (_) {}
    setTimeout(() => process.exit(0), 100);
  });
  process.on('SIGTERM', async () => {
    console.log('\nAgent received SIGTERM. Cleaning up...');
    try { await cleanup(); } catch (_) {}
    setTimeout(() => process.exit(0), 100);
  });

  async function handleConfigure(req, res) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const names = payload.scenarios || [];

        // New configuration ⇒ supersede any in-flight scenarios from a prior
        // run. Their post-await mutations will see runId mismatch and exit.
        state.runId++;
        state.config = payload.config || {};
        state.results = [];
        state.debugResults = [];
        state.report = null;
        state.serverStarted = false;
        state.helperPairIds = new Set((payload.helperPairIds || []).map(v => String(v)));
        state.hasExplicitHelperPairs = Array.isArray(payload.helperPairIds);
        
        // Resolve and validate scenarios (try TLS, then H2, then QUIC)
        const resolved = [];
        const unresolved = [];
        for (const name of names) {
          const canonicalName = SCENARIO_ALIASES.get(name) || name;
          let s = getScenario(canonicalName);
          if (!s) s = (require('./http2-scenarios').getHttp2Scenario(name));
          if (!s && canonicalName !== name) s = (require('./http2-scenarios').getHttp2Scenario(canonicalName));
          if (!s) s = (require('./quic-scenarios').getQuicScenario(name));
          if (!s && canonicalName !== name) s = (require('./quic-scenarios').getQuicScenario(canonicalName));
          if (!s) s = (require('./tcp-scenarios').getTcpScenario(name));
          if (!s && canonicalName !== name) s = (require('./tcp-scenarios').getTcpScenario(canonicalName));

          if (s) resolved.push(s);
          else unresolved.push(name);
        }

        // Fail fast on unknown names. Silently shrinking the suite hides
        // typos and stale UI state — the caller should see the typo, not a
        // surprise "ok: true" with a smaller scenarioCount.
        if (unresolved.length > 0) {
          return sendJSON(res, 400, {
            error: `Unknown scenario name(s): ${unresolved.join(', ')}`,
            unresolved,
            requestedCount: names.length,
            resolvedCount: resolved.length,
          });
        }

        // Accept inline PCAP-generated scenarios (serialized via serializePcapScenario).
        // These are full scenario descriptors with pre-evaluated actions, sent as JSON
        // from the controller/CLI when running --ingest-pcap in distributed mode.
        if (payload.pcapScenarios && Array.isArray(payload.pcapScenarios)) {
          const { deserializePcapScenario } = require('./pcap-parser');
          for (const serialized of payload.pcapScenarios) {
            try {
              const scenario = deserializePcapScenario(serialized);
              resolved.push(scenario);
              console.log(`  [pcap] Loaded inline scenario: ${scenario.name}`);
            } catch (err) {
              console.error(`  [pcap] Failed to deserialize scenario: ${err.message}`);
            }
          }
        }

        // Batch scenarios by transport (TCP/TLS → H2 → QUIC) so the agent
        // doesn't bounce between listener types or client engines on every
        // iteration. Stable sort preserves user-specified order within each
        // transport group.
        state.scenarios = groupByTransport(resolved);
        // Name → scenario map so /run-scenario can dispatch by name without
        // depending on the local list ordering. Built from the same resolved
        // set, so the contents are identical to state.scenarios — only the
        // lookup path differs.
        state.scenariosByName = new Map();
        for (const s of state.scenarios) {
          if (s && s.name) state.scenariosByName.set(s.name, s);
        }
        state.status = 'ready';

        // Record scenario fingerprints so the controller can write a run
        // manifest with exact versioning. Fingerprint is a 16-hex hash of
        // the scenario body; stable across runs, changes when actions change.
        state.scenarioFingerprints = state.scenarios.map(s => ({
          name: s.name,
          category: s.category || null,
          side: s.side || null,
          fingerprint: scenarioFingerprint(s),
        }));

        // Optional NDJSON trace per scenario. Controller sets config.traceDir
        // in the agent's local filesystem; every logger event plus scenario
        // bracketing writes to `<traceDir>/<scenario>.<role>.ndjson`.
        if (state.tracer) { try { state.tracer.close(); } catch (_) {} state.tracer = null; }
        if (state.config.traceDir) {
          try { state.tracer = new ScenarioTracer(state.config.traceDir, role); }
          catch (err) { state.tracer = null; logger.error(`Tracer init failed: ${err.message}`); }
        }

        broadcastEvent({ type: 'status', role, status: 'ready', scenarioCount: resolved.length });

        sendJSON(res, 200, {
          ok: true,
          status: 'ready',
          scenarioCount: resolved.length,
          scenarios: state.scenarioFingerprints,
          agent: {
            role,
            node: process.version,
            platform: process.platform,
            arch: process.arch,
            pid: process.pid,
          },
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

  async function handleStop(req, res) {
    // Bump *before* the awaited cleanup so any scenario currently between
    // its `await runScenario(...)` and its post-result publication sees the
    // new runId and drops its result.
    state.runId++;
    try {
      await cleanup();
    } catch (err) {
      // Don't let a cleanup error mask the stop — we still want state reset.
      console.error(`Cleanup error during /stop: ${err.message}`);
    }
    state.scenarios = [];
    state.results = [];
    state.debugResults = [];
    state.report = null;
    state.currentScenarioName = null;
    state.currentPairId = null;
    state.currentScenarioRunId = null;
    state.currentAction = null;
    state.helperPairIds = new Set();
    state.hasExplicitHelperPairs = false;
    broadcastEvent({ type: 'status', role, status: 'idle' });
    sendJSON(res, 200, { ok: true, status: 'idle' });
  }

  // Controller calls this to abort a specific peer's in-flight scenario without
  // tearing down the whole agent. Used by `peer-done` so one side can release
  // the other's outstanding recv as soon as it's itself finished. The fuzzer's
  // action loop polls _scenarioAborted and bails out of awaits when set.
  //
  // Gated on the scenario name from the payload: a stale peer-done from
  // scenario N can otherwise abort scenario N+1 if it arrives during the
  // gap between runs (controller stop/restart, slow event delivery).
  function handleAbortScenario(req, res) {
    let body = '';
    req.on('data', (c) => { body += c.toString(); });
    req.on('end', () => {
      let payload = {};
      try { payload = JSON.parse(body || '{}'); } catch (_) {}
      const requested = payload.scenario || null;
      const requestedPairId = payload.pairId !== undefined && payload.pairId !== null ? String(payload.pairId) : null;
      const requestedRunId = payload.runId !== undefined && payload.runId !== null ? Number(payload.runId) : null;
      const current = state.currentScenarioName;
      const currentPairId = state.currentPairId !== undefined && state.currentPairId !== null ? String(state.currentPairId) : null;
      const currentRunId = state.currentScenarioRunId !== undefined && state.currentScenarioRunId !== null ? Number(state.currentScenarioRunId) : null;

      // Drop stale aborts whose scenario name doesn't match the running one.
      // If the caller didn't tell us the scenario (legacy behavior) we still
      // honor the abort to avoid breaking older controllers.
      if (requested && current && requested !== current) {
        return sendJSON(res, 200, { ok: true, aborted: false, reason: 'scenario name mismatch', requested, current });
      }
      if (requestedPairId && currentPairId && requestedPairId !== currentPairId) {
        return sendJSON(res, 200, {
          ok: true,
          aborted: false,
          reason: 'pair id mismatch',
          requestedPairId,
          currentPairId,
        });
      }
      if (requestedRunId !== null && currentRunId !== null && requestedRunId !== currentRunId) {
        return sendJSON(res, 200, {
          ok: true,
          aborted: false,
          reason: 'run id mismatch',
          requestedRunId,
          currentRunId,
        });
      }

      if (state.fuzzer && typeof state.fuzzer._scenarioAborted !== 'undefined') {
        state.fuzzer._scenarioAborted = true;
        // Also flush any pending barrier waiter so the action loop resumes and
        // hits the _scenarioAborted check instead of timing out on the barrier.
        if (state.fuzzer.barrier) state.fuzzer.barrier.releaseAll('peer done');
        // And wake any in-flight server-side accept-wait. Without this, a
        // server scenario blocked on _waitForTcpConnection would hold the
        // run hostage until accept-timeout (up to 60s) before unwinding.
        if (typeof state.fuzzer.cancelScenarioWaits === 'function') {
          state.fuzzer.cancelScenarioWaits('Scenario aborted by peer-done');
        }
      }
      sendJSON(res, 200, { ok: true, aborted: true });
    });
  }

  // Controller calls this after it has confirmed the peer also reached the
  // same (scenario, label). `reason` — when non-null — means the rendezvous
  // failed (e.g. safety timeout, peer crash) and the barrier should reject.
  function handleReleaseBarrier(req, res) {
    let body = '';
    req.on('data', (c) => { body += c.toString(); });
    req.on('end', () => {
      let payload = {};
      try { payload = JSON.parse(body || '{}'); } catch (_) {}
      const label = payload.label;
      const scenario = payload.scenario || null;
      const reason = payload.reason || null;
      const pairId = payload.pairId !== undefined && payload.pairId !== null ? String(payload.pairId) : null;
      const runId = payload.runId !== undefined && payload.runId !== null ? Number(payload.runId) : null;
      if (state.fuzzer && state.fuzzer.barrier) {
        const released = state.fuzzer.barrier.release(
          scenario,
          label,
          reason,
          { pairId, runId },
        );
        return sendJSON(res, 200, { ok: true, released });
      }
      sendJSON(res, 200, { ok: true, released: false });
    });
  }

  // --- Step-by-step orchestration endpoints ---
  // Used by controller.runStepped() to run one scenario at a time.

  async function ensureServerStarted() {
    if (state.serverStarted) return;
    const { config } = state;
    const protocol = config.protocol || 'tls';
    const port = config.port;
    const timeout = parseInt(config.timeout) || 10000;
    const delay = parseInt(config.delay) || 100;

    if (!state.fuzzer) {
      state.fuzzer = new UnifiedServer({ port, hostname: config.hostname || config.host, bindAddress: config.bindAddress, timeout, delay, logger, serverConfig: state.config });
    }

    const server = state.fuzzer;
    if (protocol === 'h2') await server.startH2();
    else if (protocol === 'quic') await server.startQuic();
    else await server.startTcp();

    state.serverStarted = true;
  }

  async function ensureClientCreated() {
    if (state.fuzzer) return;
    const { config } = state;
    const host = config.host;
    const port = config.port;
    const timeout = parseInt(config.timeout) || 5000;
    const delay = parseInt(config.delay) || 100;
    const dut = config.dut || null;
    const pcapFile = config.pcapFile || null;
    const mergePcap = config.mergePcap || false;
    state.fuzzer = new UnifiedClient({ host, port, timeout, delay, logger, dut, pcapFile, mergePcap });
  }

  function handleRunScenario(req, res) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const pairId = payload.pairId !== undefined && payload.pairId !== null ? String(payload.pairId) : null;
        // Capture the run-generation token at entry. After every await below,
        // we re-check `myRunId === state.runId`; if not, a /stop or /configure
        // has superseded this scenario and any state mutation here would leak
        // into a different run.
        const myRunId = state.runId;

        // Two dispatch modes are supported:
        //   1. By name (preferred — controller-owned pair plan):
        //        { pairId, scenarioName }
        //      Looks up scenariosByName so independent agent-local
        //      reordering can't desync the pair.
        //   2. By index (legacy callers): { index, expectedName? }
        //      Validated when expectedName is supplied. Kept for
        //      backwards compatibility with older clients.
        let scenario = null;
        let displayIndex = null;
        if (typeof payload.scenarioName === 'string') {
          scenario = state.scenariosByName ? state.scenariosByName.get(payload.scenarioName) : null;
          if (!scenario) {
            return sendJSON(res, 404, {
              error: `Scenario not found on this agent: ${payload.scenarioName}`,
              pairId,
              scenarioName: payload.scenarioName,
              knownCount: state.scenarios.length,
            });
          }
          displayIndex = state.scenarios.indexOf(scenario);
        } else {
          const index = payload.index;
          if (typeof index !== 'number' || index < 0 || index >= state.scenarios.length) {
            return sendJSON(res, 400, { error: `Invalid scenario index: ${index} (have ${state.scenarios.length} scenarios)` });
          }
          scenario = state.scenarios[index];
          displayIndex = index;
          const expectedName = payload.expectedName || null;
          if (expectedName && expectedName !== scenario.name) {
            return sendJSON(res, 409, {
              error: 'Scenario index/name mismatch — agents reordered independently',
              index,
              expectedName,
              actualName: scenario.name,
            });
          }
        }

        // Stale check before we even start: if /stop or /configure ran while
        // this request was in-flight on the wire, the run we'd be feeding is
        // gone. Tell the controller and exit cleanly.
        if (myRunId !== state.runId) {
          return sendJSON(res, 200, { ok: true, stale: true, reason: 'run superseded before start', myRunId, currentRunId: state.runId });
        }

        state.status = 'running';
        state.currentScenarioName = scenario.name;
        state.currentPairId = pairId;
        state.currentScenarioRunId = myRunId;
        state.currentAction = null;
        broadcastEvent({ type: 'progress', scenario: scenario.name, pairId, current: displayIndex + 1, total: state.scenarios.length });

        // Bracket the scenario in the NDJSON trace so a single file captures
        // every event from this agent's perspective. scenario-start/end
        // records wrap whatever the fuzzer emits while running.
        if (state.tracer) state.tracer.open(scenario.name, { runId: myRunId, pairId });

        let result;
        try {
          if (role === 'server') {
            await ensureServerStarted();
            const server = state.fuzzer;
            server._distributedRunId = myRunId;
            server._distributedPairId = pairId;
            if (server._cleanupBetweenScenarios) server._cleanupBetweenScenarios();
            result = await server.runScenario(scenario);
          } else {
            await ensureClientCreated();
            const client = state.fuzzer;
            client._distributedRunId = myRunId;
            client._distributedPairId = pairId;
            result = await client.runScenario(scenario);
          }
        } finally {
          if (state.fuzzer) {
            state.fuzzer._distributedRunId = null;
            state.fuzzer._distributedPairId = null;
          }
          if (state.tracer) state.tracer.close({ status: result ? result.status : null });
          state.currentScenarioName = null;
          state.currentPairId = null;
          state.currentScenarioRunId = null;
          state.currentAction = null;
        }

        // Stale check after the awaited scenario — this is the critical
        // gate. If /stop or /configure ran during the run, the scenario we
        // just finished belongs to a superseded generation; pushing into
        // state.results or broadcasting a `result` event would mix it into
        // the next run's stream. Drop it silently.
        if (myRunId !== state.runId) {
          return sendJSON(res, 200, { ok: true, stale: true, reason: 'run superseded during scenario', result, myRunId, currentRunId: state.runId });
        }

        // Helpers are renderer-assigned counterparts. New controllers mark
        // helper pair IDs explicitly so helper-looking baseline names can also
        // be selected as real tests; the name fallback keeps older controllers
        // compatible.
        const helperName = result && result.scenario;
        const isLegacyHelperName = !!helperName && (
          helperName.startsWith('well-behaved-') ||
          helperName.startsWith('srv-quic-well-behaved-') ||
          helperName.startsWith('fv-tls-well-behaved-') ||
          /-well-behaved(-server)?$/.test(helperName)
        );
        const isHelperPair = pairId !== null && state.helperPairIds && state.helperPairIds.has(String(pairId));
        const isHelperResult = state.hasExplicitHelperPairs ? isHelperPair : isLegacyHelperName;
        if (!isHelperResult) {
          state.results.push(result);
          // pairId/side let the main-process bridge correlate this with the
          // peer's helper result so server-fuzz rows can show what the helper
          // client actually observed instead of "Handler executed (...)".
          broadcastEvent({ type: 'result', result, pairId, side: scenario.side || null });
        } else {
          state.debugResults.push({ ts: new Date().toISOString(), helper: true, result });
          if (state.debugResults.length > 50) state.debugResults.shift();
          broadcastEvent({ type: 'debug-result', helper: true, result, pairId, side: scenario.side || null });
        }

        sendJSON(res, 200, { ok: true, result });
      } catch (err) {
        sendJSON(res, 500, { error: err.message });
      }
    });
  }

  async function handleFinish(req, res) {
    try {
      state.report = computeOverallGrade(state.results);
      logger.summary(state.results, state.report);
      broadcastEvent({ type: 'report', report: state.report });
    } catch (e) {
      broadcastEvent({ type: 'error', message: `Report generation failed: ${e.message}` });
    }
    try { await cleanup(); } catch (_) {}
    state.status = 'done';
    broadcastEvent({ type: 'done', role });
    sendJSON(res, 200, { ok: true, status: 'done', resultCount: state.results.length });
  }

  async function runScenarios() {
    const { scenarios, config } = state;
    const protocol = config.protocol || 'tls';

    if (role === 'client') {
      // Small delay to allow server agent to start listening
      await sleep(500);
    }

    // Use a single worker for all operations to ensure reliable synchronization.
    const workers = 1;
    const host = config.host;
    const port = config.port;

    if (role === 'server') {
      // --- SERVER ROLE LOGIC ---
      const timeout = parseInt(config.timeout) || 10000;
      const delay = parseInt(config.delay) || 100;
      const server = new UnifiedServer({ port, hostname: config.hostname || config.host, bindAddress: config.bindAddress, timeout, delay, logger });
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
                    if (worker.connected) {
                      try { worker.send({ type: 'ack' }); } catch (_) {}
                    }
                  } else if (msg.type === 'error') {
                    broadcastEvent({ type: 'error', message: msg.message });
                  }
                } catch (err) {
                  console.error(`Error handling worker message: ${err.message}`);
                  if (msg.type === 'result' && worker.connected) {
                    try { worker.send({ type: 'ack' }); } catch (_) {}
                  }
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

      // Sequential server logic (fallback) — pre-start the server so it's
      // listening before the client agent begins connecting.
      if (protocol === 'h2') await server.startH2();
      else if (protocol === 'quic') await server.startQuic();
      else await server.startTcp();

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
      }
      try { await cleanup(); } catch (_) {}
      state.status = 'done';
      broadcastEvent({ type: 'done', role });
    } else {
      // --- CLIENT ROLE LOGIC ---
      if (workers > 1) {
        // Reusable worker pool — fork N long-lived workers, feed scenarios via IPC.
        // Previous fork-per-scenario model leaked FDs after ~1100 cycles.
        const queue = scenarios.map(s => s.name);
        const total = queue.length;
        let completed = 0;
        const numWorkers = Math.min(workers, queue.length);
        let abortedWorkers = false;

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
                    if (worker.connected) {
                      try { worker.send({ cmd: 'abort' }); } catch (_) {}
                    }
                    return;
                  }
                  const scenarioName = queue.shift();
                  broadcastEvent({ type: 'progress', scenario: scenarioName, current: completed + 1, total, activeWorkerCount: state.activeWorkers.size });
                  if (worker.connected) {
                    try { worker.send({ cmd: 'run', scenarioName, protocol: config.protocol, baseline: config.baseline }); } catch (_) {}
                  } else {
                    // Worker died between ready and run — put scenario back and let exit handler handle it
                    queue.unshift(scenarioName);
                  }
                } else if (msg.type === 'logger') {
                  broadcastEvent({ type: 'logger', event: msg.event });
                } else if (msg.type === 'result') {
                  state.results.push(msg.result);
                  broadcastEvent({ type: 'result', result: msg.result });
                  completed++;
                  broadcastEvent({ type: 'progress', current: completed, total, scenario: msg.result.scenario, activeWorkerCount: state.activeWorkers.size });
                  if (completed >= total && !abortedWorkers) {
                    abortedWorkers = true;
                    // All done — kill remaining workers
                    for (const w of state.activeWorkers) {
                      try {
                        if (w.connected && !w.killed) {
                          w.send({ cmd: 'abort' }, (err) => { /* ignore EPIPE */ });
                        }
                      } catch (_) {}
                    }

                    // Send final shutdown signal to fuzzer server
                    const closer = new UnifiedClient({ host, port, logger, timeout: parseInt(config.timeout) || 5000, delay: parseInt(config.delay) || 100 });
                    closer.shutdown(protocol).then(() => closer.close()).catch(() => {});
                  }
                } else if (msg.type === 'error') {
                  broadcastEvent({ type: 'error', message: msg.message });
                }
              } catch (err) {
                console.error(`Error handling worker message: ${err.message}`);
              }
            });

            worker.on('exit', async () => {
              state.activeWorkers.delete(worker);
              activeCount--;

              // If the worker exited without finishing its assigned scenario,
              // we must count it as completed (failed) to avoid hanging the whole batch.
              // Note: we don't know the scenario name here easily, but we know one was shifted.
              // If completed < total and all workers are gone, we must finish.
              if (state.status === 'running' && !abortedWorkers && activeCount === 0 && completed < total) {
                completed = total; // Force completion
              }

              if (activeCount === 0) {
                try {
                  state.report = computeOverallGrade(state.results);
                  logger.summary(state.results, state.report);
                  broadcastEvent({ type: 'report', report: state.report });
                } catch (e) {
                  broadcastEvent({ type: 'error', message: `Report generation failed: ${e.message}` });
                } finally {
                  try { await cleanup(); } catch (_) {}
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
              mergePcap: config.mergePcap || false,
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
      const mergePcap = config.mergePcap || false;
      const keylogFile = config.keylogFile || null;
      const client = new UnifiedClient({ host, port, timeout, delay, logger, dut, pcapFile, mergePcap, keylogFile });
      state.fuzzer = client;

      for (let i = 0; i < scenarios.length; i++) {
        if (client.aborted) break;
        broadcastEvent({ type: 'progress', scenario: scenarios[i].name, current: i + 1, total: scenarios.length });

        // Agent-level watchdog: force-resolve if scenario hangs beyond 200s.
        // The UnifiedClient has a 180s safety timeout, but if the event loop is
        // overwhelmed by accumulated zombie callbacks, setTimeout may not fire.
        const scenarioStart = Date.now();
        let scenarioDone = false;
        const watchdog = setInterval(() => {
          if (scenarioDone) return;
          const elapsed = Math.round((Date.now() - scenarioStart) / 1000);
          if (elapsed > 30) {
            console.log(`[agent-watchdog] Scenario ${scenarios[i].name} (${i+1}/${scenarios.length}) running for ${elapsed}s, activeSockets=${client.activeSockets.size}`);
          }
        }, 10000);

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
        scenarioDone = true;
        clearInterval(watchdog);
        await sleep(config.delay || 100);
      }

      try {
        state.report = computeOverallGrade(state.results);
        logger.summary(state.results, state.report);
        broadcastEvent({ type: 'report', report: state.report });
      } catch (e) {
        broadcastEvent({ type: 'error', message: `Report generation failed: ${e.message}` });
      } finally {
        if (client && client.shutdown) {
          await client.shutdown(protocol);
        }
        try { await cleanup(); } catch (_) {}
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
    console.log(`  WireStrike — ${role === 'client' ? 'Client' : 'Server'} Agent`);
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
