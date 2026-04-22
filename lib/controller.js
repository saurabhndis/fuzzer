// Controller — HTTP client for orchestrating remote agents from the Electron UI
// Connects to remote client/server agents, pushes configuration, triggers execution,
// and streams results back via NDJSON event streams.

const http = require('http');

class Controller {
  constructor() {
    this.agents = {};        // { client: { host, port, token }, server: { host, port, token } }
    this.eventStreams = {};   // { client: IncomingMessage, server: IncomingMessage }
    this.listeners = [];     // (role, event) => void
    this._stopped = false;   // set by stopAll() to break out of runStepped loop
    // Cross-peer barrier rendezvous table. Shape:
    //   Map<scenario, Map<label, { arrivals: Set<role>, timer }>>
    // First peer to arrive creates an entry and a 10s safety timer; second
    // arrival triggers a simultaneous /release-barrier POST to both agents.
    this._barriers = new Map();
    this._httpAgent = new http.Agent({
      keepAlive: true,
      keepAliveMsecs: 500,
      maxSockets: 4,
    });
  }

  /**
   * Connect to a remote agent — verify it's reachable and matches expected role
   */
  async connect(role, host, port, token) {
    const status = await this._request(host, port, 'GET', '/status', null, token);
    if (status.role && status.role !== role) {
      throw new Error(`Agent at ${host}:${port} is a ${status.role} agent, expected ${role}`);
    }
    this.agents[role] = { host, port, token };
    return status;
  }

  /**
   * Configure a single agent with scenarios and config. Caches the response
   * (agent metadata + scenario fingerprints) so writeRunManifest() can emit a
   * complete manifest without a second round-trip.
   */
  async configure(role, scenarioNames, config, pcapScenarios = undefined) {
    const agent = this.agents[role];
    if (!agent) throw new Error(`No ${role} agent connected`);

    const payload = {
      scenarios: scenarioNames || [],
      config,
    };
    if (pcapScenarios) payload.pcapScenarios = pcapScenarios;

    const resp = await this._request(agent.host, agent.port, 'POST', '/configure', payload, agent.token);
    this._lastConfigResponses = this._lastConfigResponses || {};
    this._lastConfigResponses[role] = { response: resp, config };
    return resp;
  }

  /**
   * Configure both agents in parallel
   */
  async configureAll(clientScenarios, serverScenarios, clientConfig, serverConfig, clientPcapScenarios, serverPcapScenarios) {
    const promises = [];
    const configured = { client: false, server: false };
    
    const hasClientWork = (clientScenarios && clientScenarios.length > 0) || (clientPcapScenarios && clientPcapScenarios.length > 0);
    if (hasClientWork && this.agents.client) {
      promises.push(this.configure('client', clientScenarios, clientConfig, clientPcapScenarios).then(() => { configured.client = true; }));
    }
    
    const hasServerWork = (serverScenarios && serverScenarios.length > 0) || (serverPcapScenarios && serverPcapScenarios.length > 0);
    if (hasServerWork && this.agents.server) {
      promises.push(this.configure('server', serverScenarios, serverConfig, serverPcapScenarios).then(() => { configured.server = true; }));
    }
    
    await Promise.all(promises);
    return configured;
  }

  /**
   * Start event streams and then trigger execution on all connected agents
   */
  async runAll() {
    // Start event streams first so we don't miss early events
    for (const role of Object.keys(this.agents)) {
      this._startEventStream(role);
    }

    // Trigger execution on all agents simultaneously
    const promises = [];
    for (const role of Object.keys(this.agents)) {
      const agent = this.agents[role];
      promises.push(this._request(agent.host, agent.port, 'POST', '/run'));
    }
    return Promise.all(promises);
  }

  /**
   * Stop a specific agent
   */
  async stop(role) {
    const agent = this.agents[role];
    if (!agent) return;
    return this._request(agent.host, agent.port, 'POST', '/stop', null, agent.token);
  }

  /**
   * Stop all agents and wait until both agents report idle. Agents' /stop handler
   * now awaits cleanup (workers exited, fuzzer aborted) before responding, so by
   * the time the /stop promises resolve the per-run state on each agent is gone.
   * We then poll /status once to confirm idle — cheap insurance against races
   * where an exit callback was in flight when /stop returned.
   */
  async stopAll() {
    // Set the stop flag *before* posting /stop so that any in-flight runStepped
    // loop sees it on the next iteration check and bails out immediately.
    this._stopped = true;
    const promises = [];
    for (const role of Object.keys(this.agents)) {
      promises.push(this.stop(role).catch(() => null));
    }
    await Promise.all(promises);

    // Drop any lingering event streams so the next run starts fresh. New streams
    // are (re)opened by runStepped() / runAll() at the top of each run.
    this._closeEventStreams();

    // Clear controller-side per-run state.
    this._rejectOpenBarriers('controller stopped');

    // Wait for each agent to report idle so a follow-up run doesn't race a
    // still-winding-down prior run. Bounded by 3s — degrades to proceed anyway.
    const idlePromises = [];
    for (const role of Object.keys(this.agents)) {
      idlePromises.push(this._waitForIdle(role, 3000));
    }
    await Promise.all(idlePromises);
  }

  /**
   * Get status of a specific agent
   */
  async getStatus(role) {
    const agent = this.agents[role];
    if (!agent) return null;
    return this._request(agent.host, agent.port, 'GET', '/status', null, agent.token);
  }

  /**
   * Get results from a specific agent
   */
  async getResults(role) {
    const agent = this.agents[role];
    if (!agent) return null;
    return this._request(agent.host, agent.port, 'GET', '/results', null, agent.token);
  }

  /**
   * Register event listener — receives (role, event) for every event from any agent
   */
  onEvent(callback) {
    this.listeners.push(callback);
    return () => { this.listeners = this.listeners.filter(l => l !== callback); };
  }

  /**
   * Run scenarios step-by-step — one pair at a time.
   * The controller sends each scenario index to both agents sequentially,
   * waits for both to complete, then moves to the next pair.
   * This eliminates all synchronization issues between agents.
   */
  async runStepped(totalPairs) {
    // Reset the stop flag — a fresh run should not inherit a previous Stop click.
    this._stopped = false;

    // Reset per-run state. If a prior run was cancelled mid-flight, ensure
    // event streams and barrier tables from that run are fully torn down
    // before we start so leftover events can't leak into the new run.
    this._closeEventStreams();
    this._rejectOpenBarriers('new run starting');

    // Start event streams first so we don't miss early events
    for (const role of Object.keys(this.agents)) {
      this._startEventStream(role);
    }

    const hasServer = !!this.agents.server;
    const hasClient = !!this.agents.client;

    for (let i = 0; i < totalPairs; i++) {
      // Bail out as soon as the user clicks Stop. Without this check, the loop
      // would continue dispatching /run-scenario calls after stopAll() — and if
      // the user starts a new run before this loop drains, the leftover
      // iterations execute against the agent's *new* scenarios array, surfacing
      // as "cancelled tests reappearing in the next run".
      if (this._stopped) break;

      const promises = [];

      // Start server first so it's listening when client connects
      if (hasServer) {
        const sa = this.agents.server;
        promises.push(
          this._request(sa.host, sa.port, 'POST', '/run-scenario', { index: i }, sa.token, 120000)
            .catch(err => ({ error: err.message, role: 'server', index: i }))
        );

        // Wait for the server agent's /ready endpoint to return { ready: true }
        // before dispatching the client. Replaces a fixed 300ms sleep that
        // races under load / on the first scenario of a fresh agent.
        await this._waitForReady('server', 5000);
      }

      if (this._stopped) break;

      if (hasClient) {
        const ca = this.agents.client;
        promises.push(
          this._request(ca.host, ca.port, 'POST', '/run-scenario', { index: i }, ca.token, 120000)
            .catch(err => ({ error: err.message, role: 'client', index: i }))
        );
      }

      // Wait for both to finish this pair
      await Promise.allSettled(promises);
    }

    // If the run was stopped, skip /finish — the agents have already been
    // cleaned up by stopAll() and any report would be computed against a
    // half-drained results array.
    if (this._stopped) return;

    // Signal both agents to compute grades and emit done
    const finishPromises = [];
    if (hasServer) {
      const sa = this.agents.server;
      finishPromises.push(
        this._request(sa.host, sa.port, 'POST', '/finish', null, sa.token, 30000)
          .catch(err => ({ error: err.message }))
      );
    }
    if (hasClient) {
      const ca = this.agents.client;
      finishPromises.push(
        this._request(ca.host, ca.port, 'POST', '/finish', null, ca.token, 30000)
          .catch(err => ({ error: err.message }))
      );
    }
    await Promise.allSettled(finishPromises);
  }

  /**
   * Poll the agent's /ready endpoint until it returns { ready: true } or the
   * total budget expires. Degrades to a no-op after the budget so we don't
   * deadlock when an older agent build (no /ready) is on the other end.
   */
  async _waitForReady(role, budgetMs) {
    const agent = this.agents[role];
    if (!agent) return;
    const deadline = Date.now() + budgetMs;
    while (Date.now() < deadline) {
      if (this._stopped) return;
      try {
        const r = await this._request(agent.host, agent.port, 'GET', '/ready', null, agent.token, 1000);
        if (r && r.ready) return;
      } catch (_) {
        // agent not responding yet — keep polling until budget
      }
      await new Promise(r => setTimeout(r, 50));
    }
  }

  /**
   * Poll /status until the agent reports `status === 'idle'` or the budget
   * elapses. Used after stopAll() to confirm the prior run's workers exited
   * and the fuzzer was torn down before a fresh run is dispatched.
   */
  async _waitForIdle(role, budgetMs) {
    const agent = this.agents[role];
    if (!agent) return;
    const deadline = Date.now() + budgetMs;
    while (Date.now() < deadline) {
      try {
        const s = await this._request(agent.host, agent.port, 'GET', '/status', null, agent.token, 1000);
        if (s && s.status === 'idle') return;
      } catch (_) {
        // agent momentarily unavailable (e.g. mid-cleanup) — keep polling
      }
      await new Promise(r => setTimeout(r, 50));
    }
  }

  /**
   * Tear down all NDJSON event streams. Safe to call multiple times.
   */
  _closeEventStreams() {
    for (const role of Object.keys(this.eventStreams)) {
      const stream = this.eventStreams[role];
      if (stream && !stream.destroyed) {
        try { stream.destroy(); } catch (_) {}
      }
    }
    this.eventStreams = {};
  }

  /**
   * Clear the controller-side barrier table. Any lingering arrivals from the
   * previous run are forgotten and their safety timers cancelled — the agents'
   * own waiters will time out or be released by their /release-barrier
   * handlers when a /stop arrives. Called when a new run starts or on
   * disconnect so a stale rendezvous can't match against the next run.
   */
  _rejectOpenBarriers(_reason) {
    if (!this._barriers || this._barriers.size === 0) return;
    for (const labelMap of this._barriers.values()) {
      for (const entry of labelMap.values()) {
        try { if (entry.timer) clearTimeout(entry.timer); } catch (_) {}
      }
    }
    this._barriers = new Map();
  }

  /**
   * Write a run manifest to `outPath`. Combines:
   *   - the cached /configure response from each agent (fingerprints + node/platform/pid)
   *   - git SHA + dirty flag from the controller process's working tree
   *   - caller-supplied seed + dut fields
   * Must be called after configureAll() so fingerprints are available. Returns
   * the written manifest object.
   */
  writeRunManifest(outPath, { seed, dut, runId } = {}) {
    const { writeManifest } = require('./run-manifest');
    const configResponses = this._lastConfigResponses || {};
    const agents = [];
    const scenarios = [];
    let config = null;
    for (const role of Object.keys(configResponses)) {
      const { response, config: cfg } = configResponses[role];
      const a = this.agents[role] || {};
      agents.push({
        role,
        host: a.host,
        port: a.port,
        node: response.agent && response.agent.node,
        platform: response.agent && response.agent.platform,
        arch: response.agent && response.agent.arch,
        pid: response.agent && response.agent.pid,
        scenarioCount: response.scenarioCount || 0,
      });
      if (Array.isArray(response.scenarios)) {
        for (const s of response.scenarios) {
          scenarios.push({ ...s, role });
        }
      }
      // Last config wins; both sides are usually the same protocol/host anyway.
      if (cfg && !config) config = cfg;
    }
    return writeManifest(outPath, { runId, seed, dut, config, agents, scenarios });
  }

  /**
   * Clean up all connections and event streams
   */
  disconnect() {
    this._closeEventStreams();
    this._rejectOpenBarriers('controller disconnect');
    this.agents = {};
    this.listeners = [];
    if (this._httpAgent) { this._httpAgent.destroy(); this._httpAgent = null; }
  }

  /**
   * Start NDJSON event stream from an agent
   */
  _startEventStream(role) {
    const agent = this.agents[role];
    if (!agent) return;

    // Close existing stream if any
    if (this.eventStreams[role]) {
      this.eventStreams[role].destroy();
    }

    const headers = { 'Accept': 'application/x-ndjson' };
    if (agent.token) {
      headers['Authorization'] = `Bearer ${agent.token}`;
    }

    const req = http.request({
      hostname: agent.host,
      port: agent.port,
      path: '/events',
      method: 'GET',
      headers,
      agent: this._httpAgent,
    }, (res) => {
      this.eventStreams[role] = res;
      let buffer = '';

      res.on('data', (chunk) => {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        // Keep the last incomplete line in the buffer
        buffer = lines.pop();

        for (const line of lines) {
          if (line.trim()) {
            try {
              const event = JSON.parse(line);
              this._emitEvent(role, event);
            } catch (_) {
              // Skip malformed lines
            }
          }
        }
      });

      res.on('end', () => {
        // Process any remaining data in buffer
        if (buffer.trim()) {
          try {
            const event = JSON.parse(buffer);
            this._emitEvent(role, event);
          } catch (_) {}
        }
        delete this.eventStreams[role];
      });

      res.on('error', () => {
        delete this.eventStreams[role];
      });
    });

    req.on('error', (err) => {
      this._emitEvent(role, { type: 'error', message: `Event stream error: ${err.message}` });
    });

    req.end();
  }

  /**
   * Dispatch event to all registered listeners. Before user listeners fire,
   * the controller handles cross-peer sync events itself (barrier rendezvous
   * matching and peer-done propagation) — these are protocol-level, not UI.
   */
  _emitEvent(role, event) {
    try {
      if (event && event.type === 'barrier-arrived') {
        this._handleBarrierArrived(role, event);
      } else if (event && event.type === 'peer-done') {
        this._handlePeerDone(role, event);
      }
    } catch (_) {}
    for (const fn of this.listeners) {
      try { fn(role, event); } catch (_) {}
    }
  }

  /**
   * Record that `role` reached `label` in `scenario`. When both roles have
   * arrived, POST /release-barrier to both agents so their fuzzers resume.
   * A 10s safety timer rejects the rendezvous if only one side shows up.
   */
  _handleBarrierArrived(role, event) {
    const scenarioKey = event.scenario || '';
    const label = event.label || '';
    if (!label) return;

    if (!this._barriers.has(scenarioKey)) this._barriers.set(scenarioKey, new Map());
    const labelMap = this._barriers.get(scenarioKey);
    if (!labelMap.has(label)) labelMap.set(label, { arrivals: new Set(), timer: null });
    const entry = labelMap.get(label);

    entry.arrivals.add(role);

    // Start a one-shot safety timer on the first arrival.
    if (!entry.timer && entry.arrivals.size === 1) {
      entry.timer = setTimeout(() => {
        // Only one side showed up — reject that side's waiter and clear.
        const alone = Array.from(entry.arrivals)[0];
        if (alone) this._postReleaseBarrier(alone, label, `barrier '${label}' safety timeout (peer not arrived)`);
        labelMap.delete(label);
      }, 10000);
    }

    const bothSides = entry.arrivals.has('client') && entry.arrivals.has('server');
    if (bothSides) {
      clearTimeout(entry.timer);
      labelMap.delete(label);
      // Release both peers simultaneously.
      this._postReleaseBarrier('client', label, null);
      this._postReleaseBarrier('server', label, null);
    }
  }

  /**
   * Fire-and-forget POST /release-barrier to the given role's agent.
   */
  _postReleaseBarrier(role, label, reason) {
    const agent = this.agents[role];
    if (!agent) return;
    this._request(agent.host, agent.port, 'POST', '/release-barrier', { label, reason }, agent.token, 2000)
      .catch(() => {});
  }

  /**
   * One side finished its action list and signalled peer-done. Tell the peer
   * agent to abort its in-flight scenario so its outstanding recv releases.
   */
  _handlePeerDone(role, event) {
    const peerRole = role === 'client' ? 'server' : 'client';
    const peer = this.agents[peerRole];
    if (!peer) return;
    this._request(peer.host, peer.port, 'POST', '/abort-scenario', { scenario: event.scenario }, peer.token, 2000)
      .catch(() => {});
  }

  /**
   * Generic HTTP request helper
   */
  _request(host, port, method, path, body, token, timeout = 10000) {
    return new Promise((resolve, reject) => {
      const opts = {
        hostname: host,
        port,
        path,
        method,
        timeout,
        headers: {},
        agent: this._httpAgent,
      };

      if (token) {
        opts.headers['Authorization'] = `Bearer ${token}`;
      }

      let payload;
      if (body) {
        payload = JSON.stringify(body);
        opts.headers['Content-Type'] = 'application/json';
        opts.headers['Content-Length'] = Buffer.byteLength(payload);
      }

      const req = http.request(opts, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (res.statusCode >= 400) {
              reject(new Error(parsed.error || `HTTP ${res.statusCode}`));
            } else {
              resolve(parsed);
            }
          } catch (_) {
            reject(new Error(`Invalid response from agent: ${data.slice(0, 200)}`));
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request to ${host}:${port}${path} timed out`));
      });

      req.on('error', (err) => {
        reject(new Error(`Cannot reach agent at ${host}:${port}: ${err.message}`));
      });

      if (payload) req.write(payload);
      req.end();
    });
  }
}

module.exports = { Controller };
