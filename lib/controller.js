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
   * Configure both agents in parallel and build the controller-owned pair
   * plan that stepped execution will follow.
   *
   * Each agent applies its own `groupByTransport` reordering locally, so the
   * controller cannot rely on `index i` meaning the same scenario on both
   * sides. Instead, the controller fixes the pairing here — by name — and
   * `runStepped()` dispatches by name. Agents look up scenarios in a
   * name → scenario map at execution time.
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

    // Build the pair plan from the *requested* name lists, not from each
    // agent's reordered response. Pad missing names with null so a client-
    // only or server-only scenario still has a row.
    const clientNames = (clientScenarios || []).slice();
    const serverNames = (serverScenarios || []).slice();
    // Inline PCAP scenarios add a single name per side; include them so
    // distributed PCAP runs also follow the plan.
    if (Array.isArray(clientPcapScenarios)) {
      for (const s of clientPcapScenarios) if (s && s.name) clientNames.push(s.name);
    }
    if (Array.isArray(serverPcapScenarios)) {
      for (const s of serverPcapScenarios) if (s && s.name) serverNames.push(s.name);
    }
    const pairCount = Math.max(clientNames.length, serverNames.length);
    this._stepPlan = [];
    for (let i = 0; i < pairCount; i++) {
      this._stepPlan.push({
        pairId: String(i),
        clientName: clientNames[i] || null,
        serverName: serverNames[i] || null,
      });
    }

    return configured;
  }

  /**
   * Returns the controller-owned pair plan computed by configureAll.
   * Empty array if configureAll() has not been called.
   */
  get stepPlan() {
    return (this._stepPlan || []).slice();
  }

  /**
   * Opt in to one-sided rows in distributed stepped mode. Default is false:
   * a pair without both a clientName and a serverName is rejected before the
   * run starts, because the typical outcome is one side waiting on a peer
   * that will never connect. Set to true only when one-sided rows are
   * deliberate (e.g. server idle-behavior probes with no client).
   */
  set allowUnpairedDistributedRows(v) { this._allowUnpairedDistributedRows = !!v; }
  get allowUnpairedDistributedRows() { return !!this._allowUnpairedDistributedRows; }

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
    // Clear per-run failure tracking; populated by the loop below when an
    // agent returns 4xx/5xx for a pair.
    this._stepFailures = [];

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

    // Use the controller-owned pair plan when present (built by
    // configureAll). Falls back to a numeric loop for legacy callers, but
    // those won't get the cross-agent name validation.
    const plan = this._stepPlan && this._stepPlan.length > 0 ? this._stepPlan : null;
    const pairCount = plan ? plan.length : totalPairs;

    // Pairability check: when both agents are connected and the operator
    // expected a paired distributed run, every plan row must have *both* a
    // clientName and a serverName. A unpaired row would dispatch only one
    // side, leaving the peer waiting on a never-arriving connection and
    // producing exactly the "looks like a hang" symptom this design fixes.
    //
    // The opt-in escape hatch (`allowUnpairedDistributedRows`) is for the
    // rare case where the caller deliberately wants one-sided rows in a
    // distributed setup (e.g. probing a server's idle behavior with no
    // client). Default behavior is to reject and fail fast.
    if (plan && hasClient && hasServer && !this._allowUnpairedDistributedRows) {
      const unpaired = plan.filter(p => !p.clientName || !p.serverName);
      if (unpaired.length > 0) {
        const sample = unpaired.slice(0, 3).map(p => `pair ${p.pairId}: client=${p.clientName || '∅'}, server=${p.serverName || '∅'}`);
        throw new Error(
          `Distributed stepped mode requires both client and server scenarios in every pair, ` +
          `but ${unpaired.length} of ${plan.length} row(s) are unpaired:\n  ${sample.join('\n  ')}` +
          (unpaired.length > 3 ? `\n  ... and ${unpaired.length - 3} more` : '') +
          `\nFix the scenario lists, or set controller.allowUnpairedDistributedRows = true to opt in.`
        );
      }
    }

    for (let i = 0; i < pairCount; i++) {
      // Bail out as soon as the user clicks Stop. Without this check, the loop
      // would continue dispatching /run-scenario calls after stopAll() — and if
      // the user starts a new run before this loop drains, the leftover
      // iterations execute against the agent's *new* scenarios array, surfacing
      // as "cancelled tests reappearing in the next run".
      if (this._stopped) break;

      const promises = [];

      // Authoritative pairing: the controller decided what client name and
      // server name belong together at this row. Agents run scenarios by
      // name (not by their local index) so independent reordering on each
      // side cannot desync the pair.
      const entry = plan ? plan[i] : { pairId: String(i), clientName: null, serverName: null };
      const pairId = entry.pairId;
      const clientName = entry.clientName;
      const serverName = entry.serverName;

      // Start server first so it's listening when client connects
      if (hasServer && serverName) {
        const sa = this.agents.server;
        promises.push(
          this._request(sa.host, sa.port, 'POST', '/run-scenario', { pairId, scenarioName: serverName }, sa.token, 120000)
            .catch(err => ({ error: err.message, role: 'server', pairId, scenarioName: serverName }))
        );

        // Wait for the server agent's /ready endpoint to return { ready: true }
        // before dispatching the client. Replaces a fixed 300ms sleep that
        // races under load / on the first scenario of a fresh agent.
        await this._waitForReady('server', 5000);
      }

      if (this._stopped) break;

      if (hasClient && clientName) {
        const ca = this.agents.client;
        promises.push(
          this._request(ca.host, ca.port, 'POST', '/run-scenario', { pairId, scenarioName: clientName }, ca.token, 120000)
            .catch(err => ({ error: err.message, role: 'client', pairId, scenarioName: clientName }))
        );
      }

      // Wait for both to finish this pair, then surface any failures.
      const settled = await Promise.allSettled(promises);
      const failures = [];
      for (const r of settled) {
        if (r.status === 'rejected') {
          failures.push({ error: r.reason && r.reason.message ? r.reason.message : String(r.reason) });
        } else if (r.value && r.value.error) {
          failures.push(r.value);
        }
      }
      if (failures.length > 0) {
        // Record per-pair failures on the controller so callers can inspect.
        this._stepFailures = this._stepFailures || [];
        for (const f of failures) {
          this._stepFailures.push({ pairId, ...f });
          // Surface as an event too, so UI listeners see the failure.
          this._emitEvent('controller', { type: 'error', message: `Pair ${pairId} failed: ${JSON.stringify(f)}` });
        }
      }
    }

    // If the run was stopped, skip /finish — the agents have already been
    // cleaned up by stopAll() and any report would be computed against a
    // half-drained results array.
    if (this._stopped) {
      // Caller still needs a structured result so a stop doesn't silently
      // look like a clean run. Surface any failures collected before the stop.
      return this._stepFailures.length > 0
        ? { ok: false, failures: this._stepFailures.slice(), stopped: true }
        : { ok: true, failures: [], stopped: true };
    }

    // Signal both agents to compute grades and emit done
    const finishPromises = [];
    if (hasServer) {
      const sa = this.agents.server;
      finishPromises.push(
        this._request(sa.host, sa.port, 'POST', '/finish', null, sa.token, 30000)
          .catch(err => ({ error: err.message, role: 'server' }))
      );
    }
    if (hasClient) {
      const ca = this.agents.client;
      finishPromises.push(
        this._request(ca.host, ca.port, 'POST', '/finish', null, ca.token, 30000)
          .catch(err => ({ error: err.message, role: 'client' }))
      );
    }
    const finishSettled = await Promise.allSettled(finishPromises);
    for (const r of finishSettled) {
      if (r.status === 'rejected') {
        this._stepFailures.push({ phase: 'finish', error: r.reason && r.reason.message ? r.reason.message : String(r.reason) });
      } else if (r.value && r.value.error) {
        this._stepFailures.push({ phase: 'finish', ...r.value });
      }
    }

    // Return the structured result so the IPC boundary can't bury failures
    // under a blanket { ok: true }. Empty failures means a clean run.
    return this._stepFailures.length > 0
      ? { ok: false, failures: this._stepFailures.slice() }
      : { ok: true, failures: [] };
  }

  /**
   * Returns the failures recorded during the most recent runStepped() call.
   * Empty array when the run completed cleanly.
   */
  get stepFailures() {
    return this._stepFailures || [];
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
    const configByRole = {};
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
      // Preserve every role's config — distributed runs differ on bindAddress,
      // target host/port, and traceDir, and merging into one object loses the
      // information needed to replay the exact run.
      if (cfg) configByRole[role] = cfg;
    }
    // Single `config` field kept for back-compat with v1 manifest readers:
    // prefer the client's config (the side initiating traffic), else server.
    const config = configByRole.client || configByRole.server || null;
    return writeManifest(outPath, { runId, seed, dut, config, configByRole, agents, scenarios });
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
        if (alone) this._postReleaseBarrier(alone, scenarioKey, label, `barrier '${label}' safety timeout (peer not arrived)`);
        labelMap.delete(label);
      }, 10000);
    }

    const bothSides = entry.arrivals.has('client') && entry.arrivals.has('server');
    if (bothSides) {
      clearTimeout(entry.timer);
      labelMap.delete(label);
      // Release both peers simultaneously.
      this._postReleaseBarrier('client', scenarioKey, label, null);
      this._postReleaseBarrier('server', scenarioKey, label, null);
    }
  }

  /**
   * Fire-and-forget POST /release-barrier to the given role's agent. Sends
   * the scenario name so the agent's barrier table releases the matching
   * waiter only — a delayed release from a previous scenario can't fire a
   * same-label waiter in the next one.
   */
  _postReleaseBarrier(role, scenario, label, reason) {
    const agent = this.agents[role];
    if (!agent) return;
    this._request(agent.host, agent.port, 'POST', '/release-barrier', { scenario, label, reason }, agent.token, 2000)
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
