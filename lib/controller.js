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
   * Configure a single agent with scenarios and config
   */
  async configure(role, scenarioNames, config, pcapScenarios = undefined) {
    const agent = this.agents[role];
    if (!agent) throw new Error(`No ${role} agent connected`);
    
    const payload = {
      scenarios: scenarioNames || [],
      config,
    };
    if (pcapScenarios) payload.pcapScenarios = pcapScenarios;

    return this._request(agent.host, agent.port, 'POST', '/configure', payload, agent.token);
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
   * Stop all agents
   */
  async stopAll() {
    // Set the stop flag *before* posting /stop so that any in-flight runStepped
    // loop sees it on the next iteration check and bails out immediately.
    this._stopped = true;
    const promises = [];
    for (const role of Object.keys(this.agents)) {
      promises.push(this.stop(role));
    }
    return Promise.all(promises);
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
      }

      // Small delay to let server start listening
      await new Promise(r => setTimeout(r, 300));

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
   * Clean up all connections and event streams
   */
  disconnect() {
    for (const role of Object.keys(this.eventStreams)) {
      const stream = this.eventStreams[role];
      if (stream && !stream.destroyed) {
        stream.destroy();
      }
    }
    this.eventStreams = {};
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
   * Dispatch event to all registered listeners
   */
  _emitEvent(role, event) {
    for (const fn of this.listeners) {
      try { fn(role, event); } catch (_) {}
    }
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
