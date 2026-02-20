// Controller — HTTP client for orchestrating remote agents from the Electron UI
// Connects to remote client/server agents, pushes configuration, triggers execution,
// and streams results back via NDJSON event streams.

const http = require('http');

class Controller {
  constructor() {
    this.agents = {};        // { client: { host, port }, server: { host, port } }
    this.eventStreams = {};   // { client: IncomingMessage, server: IncomingMessage }
    this.listeners = [];     // (role, event) => void
  }

  /**
   * Connect to a remote agent — verify it's reachable and matches expected role
   */
  async connect(role, host, port) {
    const status = await this._request(host, port, 'GET', '/status');
    if (status.role && status.role !== role) {
      throw new Error(`Agent at ${host}:${port} is a ${status.role} agent, expected ${role}`);
    }
    this.agents[role] = { host, port };
    return status;
  }

  /**
   * Configure a single agent with scenarios and config
   */
  async configure(role, scenarioNames, config) {
    const agent = this.agents[role];
    if (!agent) throw new Error(`No ${role} agent connected`);
    return this._request(agent.host, agent.port, 'POST', '/configure', {
      scenarios: scenarioNames,
      config,
    });
  }

  /**
   * Configure both agents in parallel
   */
  async configureAll(clientScenarios, serverScenarios, clientConfig, serverConfig) {
    const promises = [];
    if (clientScenarios && clientScenarios.length > 0 && this.agents.client) {
      promises.push(this.configure('client', clientScenarios, clientConfig));
    }
    if (serverScenarios && serverScenarios.length > 0 && this.agents.server) {
      promises.push(this.configure('server', serverScenarios, serverConfig));
    }
    return Promise.all(promises);
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
    return this._request(agent.host, agent.port, 'POST', '/stop');
  }

  /**
   * Stop all agents
   */
  async stopAll() {
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
    return this._request(agent.host, agent.port, 'GET', '/status');
  }

  /**
   * Get results from a specific agent
   */
  async getResults(role) {
    const agent = this.agents[role];
    if (!agent) return null;
    return this._request(agent.host, agent.port, 'GET', '/results');
  }

  /**
   * Register event listener — receives (role, event) for every event from any agent
   */
  onEvent(callback) {
    this.listeners.push(callback);
    return () => { this.listeners = this.listeners.filter(l => l !== callback); };
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

    const req = http.request({
      hostname: agent.host,
      port: agent.port,
      path: '/events',
      method: 'GET',
      headers: { 'Accept': 'application/x-ndjson' },
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
  _request(host, port, method, path, body) {
    return new Promise((resolve, reject) => {
      const opts = {
        hostname: host,
        port,
        path,
        method,
        timeout: 10000,
        headers: {},
      };

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
