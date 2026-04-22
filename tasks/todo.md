# Tasks

## In Progress — Fixes for Sync / Hang / Close-vs-Alert Issues

Three categories of fixes from the design review. Each entry lists file:line, the
exact change, and the regression to watch for.

### 1. Readiness Handshake (replaces 300ms sleep)
- [ ] `lib/agent.js` — add a `GET /ready` endpoint returning `{ ready: boolean }`.
      Server role returns true only after `ensureServerStarted()` has resolved
      (track with `state.serverListening = true` set in the resolve branch of
      `startTcp/startH2/startQuic`). Client role always returns true.
- [ ] `lib/controller.js:142–188` — replace `await new Promise(r => setTimeout(r, 300))`
      with a polling loop: call `/ready` on the server every 50ms up to 5s, then
      proceed. On timeout, emit an event and proceed anyway (preserves current
      degradation behavior, not worse than the sleep).
- [ ] Regression to watch: in-process / local mode where client and server share
      the same agent — the ready probe still works because it's an HTTP call.

### 2. Queued TCP Hang (unified-server.js:372)
- [ ] Wrap the queued-connection `once('data')` in a timer identical to the
      non-queued path at line 391 (`timeoutMs`, default 60s).
- [ ] Register `'end'` and `'close'` listeners alongside `'data'` — any of them
      resolves the promise. If close fires first with no data, resolve with the
      socket so the scenario can observe the empty read and grade accordingly.
- [ ] Regression to watch: scenarios that intentionally test pre-connect +
      immediate-FIN must still see `lastResponse = 'Connection closed'`.

### 3. Drain Before Close Finalizes (alert capture)
- [ ] `lib/unified-client.js:1596` (`_waitForData`) — before `done()` resolves
      after the 1s grace, check `recvBuffer`/`buf` and include any bytes that
      arrived during grace. Already done structurally, but add an explicit
      post-close drain: if `connectionClosed` is true AND buf is empty, give one
      extra `setImmediate` tick for any pending 'data' events queued in Node's
      internal buffer.
- [ ] `lib/unified-client.js:367` — when `recv` sees `connectionClosed` with no
      data, inspect the pre-close `recvBuffer` (captured by global listener at
      line 307) — if non-empty and contains a valid Alert record, set
      `status = 'tls-alert-server'` instead of `DROPPED`.
- [ ] `lib/unified-server.js:1897` (`_waitForData`) — same drain fix mirroring
      the client. 4s grace is already there; add the post-close tick.
- [ ] `lib/quic-fuzzer-client.js:116` — `recv` action: after timeout, check if
      the UDP socket received a CONNECTION_CLOSE between handler-registration
      and timer fire (the socket.on('message') handler is async).
- [ ] Regression to watch: scenarios relying on `status='DROPPED'` for
      pre-close silent drops must not flip to `tls-alert-server` just because
      the peer sent a Close_Notify. Check: require `AlertLevel.FATAL` and
      non-close_notify description.

### 4. Explicit UDP Bind (quic-fuzzer-client.js:84)
- [ ] Call `socket.bind(0, '0.0.0.0')` explicitly, await a `listening` event or
      promise-wrap bind. Propagate bind errors (EADDRINUSE, permission) via
      scenario result `status='ERROR'`, `response='UDP bind failed: <err>'`.

### 5. TLS Connect Timeout (unified-client.js _connectTLS)
- [ ] Add `const connectTimer = setTimeout(() => { socket.destroy(); reject(new Error('TLS connect timeout')); }, this.timeout)` before `tls.connect`.
- [ ] Clear the timer in `secureConnect` and `error` handlers.
- [ ] Regression to watch: scenarios that legitimately take >this.timeout to
      complete ServerHello (fragmented handshakes). Current `this.timeout` is
      ~5000ms — should be sufficient.

### 6. Shutdown Signal (unified-client.js:2084)
- [ ] Replace the silent `socket.on('error', () => {})` with an info-level log.
- [ ] Replace the fixed 500ms sleep with either: wait for 'end' event OR 2s
      timeout, whichever first. Destroy socket in finally block.

## Verification Before Marking Complete
- [ ] Run `node test-h2-distributed.js` and confirm no hangs on a cold start
      with `--distributed`.
- [ ] Run `node test-quic-distributed.js` and confirm QUIC CONNECTION_CLOSE
      scenarios surface `status='DROPPED'` with a descriptive response.
- [ ] Run TLS alert scenarios and confirm they're not masked as
      `Connection closed`.
- [ ] Diff results against `gold.log` / `final_tls_distributed_report.log`.

## Review

Implemented in this session:

- **controller.js**: replaced 300ms sleep with `_waitForReady('server', 5000)` polling `/ready` every 50ms. Degrades gracefully on older agents (timeout = proceed).
- **agent.js**: added `GET /ready` endpoint. Server-role ready iff `state.serverStarted && tcpServer.listening || h2Server.listening || quicServer`.
- **unified-server.js `_waitForTcpConnection`**: queued and new-connection paths both share an `attachReadiness` helper with a single timer + `end`/`close`/`error` listeners. A silent pre-connect no longer hangs.
- **unified-client.js `recv`** and **unified-server.js `recv`**: added `setImmediate` drain tick so data queued behind `close` is captured. Preserve prior `tls-alert-*` status — don't clobber with `DROPPED` when a later empty recv just sees FIN.
- **quic-fuzzer-client.js**: explicit `socket.bind(0, ...)` before first send, with error rejection so EADDRINUSE surfaces instead of hanging.
- **unified-client.js shutdown**: replaced silent `on('error')` + fixed 500ms sleep with a bounded 2s safety timeout, `end`/`close` listeners, and an info log on error.

Implemented for professional-feel cancellation and cross-peer sync:

- **agent.js `cleanup()`**: now async; `awaitWorkersExited()` polls until workers are gone (2s grace). All seven call sites updated to `await cleanup()` — `/stop` no longer returns until workers have exited and the fuzzer is torn down.
- **controller.js `stopAll()`**: awaits each `/stop`, tears down event streams, rejects open barriers, then polls `/status` on both agents until idle (3s budget). Guarantees the next run starts against clean agents.
- **controller.js `runStepped()`**: resets barrier table and event streams at the top so a prior cancelled run cannot leak events or waiters into the new one.
- **lib/barrier.js** (new): shared `Barrier` helper used by both fuzzers. `wait(scenario, label, timeout)` blocks; `release(label)` or `releaseAll(reason)` unblocks. Emits `logger.barrierArrived` so the controller can match peers.
- **unified-client.js / unified-server.js**: `barrier` and `peer-done` actions wired into the TLS action loop. Both honor `_scenarioAborted` at each iteration. `runScenario` resets abort flag and rejects stale barriers at start.
- **agent.js**: new endpoints `POST /abort-scenario` (sets `_scenarioAborted`, flushes barriers) and `POST /release-barrier` (resolves the named waiter). New logger methods `barrierArrived` / `peerDone` broadcast the corresponding events over the existing NDJSON stream.
- **controller.js**: `_emitEvent` intercepts `barrier-arrived` and `peer-done` events; `_handleBarrierArrived` matches pairs and POSTs `/release-barrier` to both agents on second arrival (10s safety timeout rejects stuck rendezvous); `_handlePeerDone` POSTs `/abort-scenario` to the peer.

Tests added:
- **test-barrier.js**: four unit tests covering two-way rendezvous, safety timeout, releaseAll, and controller matching against mock agents. All passing.
- **test-cancel-restart.js**: end-to-end regression for the cancel-and-restart "professional feel" flow. Asserts the agent reports idle immediately after `stopAll()` returns and Run 2 produces only its own results with zero stale-run leak. Passing.
- **test-manifest-tracer.js**: unit + integration. Fingerprint stability/sensitivity, manifest schema round-trip, tracer NDJSON format and filename sanitization, plus distributed integration that runs a real scenario and verifies the trace file contains scenario-start, protocol events (sent/received/FIN), and scenario-end. All passing.

Reproducibility and observability (new modules):

- **lib/run-manifest.js** (new): `gitInfo()` (sha, dirty, branch), `scenarioFingerprint(scenario)` (16-hex stable hash of name + description + side + actions source), `writeManifest(path, data)` (schema v1 with runId, startedAt, node/platform/arch, git, seed, config, agents, scenarios, dut).
- **lib/tracer.js** (new): `ScenarioTracer(dir, role)` writes per-scenario NDJSON to `<dir>/<scenario>.<role>.ndjson`. Each record carries monotonic `t` (ms since scenario start) and wall-clock timestamp. Filesystem-safe filename sanitization built in.
- **agent.js**: `/configure` now accepts `config.traceDir` and creates a tracer; every logger method (info, error, sent, received, tcpEvent, barrier-arrived, peer-done, …) fans out to the tracer when open. `/run-scenario` brackets each scenario with tracer.open/close. `/configure` response now includes per-scenario fingerprints and agent metadata (node, platform, arch, pid). Cleanup flushes an open tracer with `status: 'CANCELLED'`.
- **controller.js**: `configure()` caches the response per role; `writeRunManifest(outPath, { seed, dut, runId })` assembles git info + cached agent metadata + fingerprints and writes manifest.json. Call after `configureAll()`.

Skipped:
- Task 5 (TLS connect timeout): `_connectTLSOnce` already has `socket.setTimeout(this.timeout)` + `on('timeout')` handler. `_runTLSPost` same. Subagent finding was overstated.

Deferred to a future phase (design doc `plans/cross-peer-sync.md` retains the plan):
- Recv enrichment (`expect: { tlsRecords, minBytes, minCount }`) — Phase 2 of the design.
- PCAP interleaved action lists with auto-inserted direction-change barriers — Phase 4.
- 4s server grace period is still a magic constant.

## Completed
- [x] Fixed PCAP functionality bugs causing empty files and Wireshark parsing errors.
- [x] Fixed missing handshake packets in PCAP files.
- [x] Verified PCAP correctness with `tshark` for both TLS and QUIC.
- [x] Fixed NAT-split streams in PCAP ingestion (`--ingest-pcap`).
- [x] Added distributed mode for PCAP-ingested scenarios.
- [x] Added PCAP test category with full lifecycle management.
