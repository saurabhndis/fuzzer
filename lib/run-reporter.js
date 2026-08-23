// Reports a run's lifecycle (start → heartbeat → finish) to the attestation
// server so the operator console can show it as an in-progress test. Entirely
// best-effort and self-contained: it owns its own heartbeat timer, and every
// network call is swallowed, so nothing here can affect the actual run.
//
// A no-op unless the user is signed in. Callers wrap a run with:
//   const reporter = startReporting({runId, protocol, ...});
//   try { ...run... } finally { reporter.stop(); }

const HEARTBEAT_MS = 15000;

function startReporting(meta = {}) {
  let stopped = false;
  let timer = null;
  const remote = require('./attestation-remote');

  if (!meta.runId || !remote.isSignedIn()) {
    return { stop() {} };
  }

  // Fire-and-forget start, then heartbeat on an interval that never keeps the
  // process alive on its own (unref) — the run's own work does that.
  remote.reportRunStart(meta).catch(() => {});
  timer = setInterval(() => { remote.reportRunHeartbeat(meta.runId).catch(() => {}); }, HEARTBEAT_MS);
  if (timer.unref) timer.unref();

  return {
    stop() {
      if (stopped) return;
      stopped = true;
      if (timer) clearInterval(timer);
      remote.reportRunFinish(meta.runId).catch(() => {});
    },
  };
}

module.exports = { startReporting, HEARTBEAT_MS };
