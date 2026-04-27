// Per-scenario NDJSON tracer.
//
// When hang-debugging a fuzz run, the question is almost always "what was the
// state machine doing for the 30 seconds before it timed out?" The broadcast
// event stream answers that question once you reconstruct it by hand from a
// merged log. This tracer answers it directly: one NDJSON file per scenario
// per agent-role, timestamped with monotonic t (ms since scenario start) and
// wall-clock.
//
// Output path defaults to `<dir>/<scenario>.<role>.ndjson`. When run/pair
// metadata is available, traces are partitioned under
// `<dir>/run-<runId>/pair-<pairId>.<scenario>.<role>.ndjson` so repeated
// selections do not merge into one flat file.

const fs = require('fs');
const path = require('path');

function sanitize(name) {
  return String(name || 'unknown').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 160);
}

class ScenarioTracer {
  constructor(dir, role) {
    this.dir = dir;
    this.role = role || 'unknown';
    this.fd = null;
    this.scenario = null;
    this.meta = {};
    this.startNs = 0n;
    try { fs.mkdirSync(dir, { recursive: true }); } catch (_) {}
  }

  // Open a new trace file for `scenarioName`. Closes any prior open scenario.
  open(scenarioName, meta = {}) {
    this.close();
    this.scenario = scenarioName;
    this.meta = meta || {};
    this.startNs = process.hrtime.bigint();
    let traceDir = this.dir;
    if (this.meta.runId !== undefined && this.meta.runId !== null) {
      traceDir = path.join(this.dir, `run-${sanitize(this.meta.runId)}`);
      try { fs.mkdirSync(traceDir, { recursive: true }); } catch (_) {}
    }
    const prefix = this.meta.pairId !== undefined && this.meta.pairId !== null
      ? `pair-${sanitize(this.meta.pairId)}.`
      : '';
    const file = path.join(traceDir, `${prefix}${sanitize(scenarioName)}.${this.role}.ndjson`);
    try {
      this.fd = fs.openSync(file, 'a');
    } catch (_) {
      this.fd = null;
    }
    this.record('scenario-start', { pid: process.pid });
  }

  // Flush a scenario-end record and close the file.
  close(extra) {
    if (this.fd) {
      try { this.record('scenario-end', extra || {}); } catch (_) {}
      try { fs.closeSync(this.fd); } catch (_) {}
      this.fd = null;
    }
    this.scenario = null;
    this.meta = {};
  }

  // Write one NDJSON record. `event` is a short tag (e.g. 'action-start',
  // 'socket-data', 'barrier-arrived'); `data` is an arbitrary object merged
  // into the line. Silently drops if the file couldn't be opened.
  record(event, data) {
    if (!this.fd) return;
    const tNs = process.hrtime.bigint() - this.startNs;
    const tMs = Number(tNs) / 1e6;
    const line = JSON.stringify({
      t: Math.round(tMs * 100) / 100,
      wall: new Date().toISOString(),
      role: this.role,
      scenario: this.scenario,
      runId: this.meta.runId !== undefined ? this.meta.runId : undefined,
      pairId: this.meta.pairId !== undefined ? this.meta.pairId : undefined,
      event,
      ...(data || {}),
    }) + '\n';
    try { fs.writeSync(this.fd, line); } catch (_) {}
  }
}

module.exports = { ScenarioTracer, sanitize };
