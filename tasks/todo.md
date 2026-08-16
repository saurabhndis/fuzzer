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

## Completed — TCP Reassembly for PCAP Ingestion (2026-06-06)

PCAP ingestion used to do `Buffer.concat(stream.packets.filter(dir).map(payload))` at
every parse site — packets were concatenated in capture-arrival order with no TCP
layer.  Retransmits, partial overlaps, and out-of-order delivery silently corrupted
TLS parsing.

Goal: sequence-number-aware reassembly so each unique byte appears exactly once in
both the parsed stream (used to extract handshake messages) and the replay (used to
emit `send` actions).  No mimicking of captured retransmits — duplicating bytes at
the Node socket layer becomes new TCP sequence numbers and breaks the DUT's TLS
parser.

- [x] `lib/pcap-parser.js:readPcap` — extract TCP `seq` (offset +4 in TCP header),
      store on each packet alongside `tcpFlags`.
- [x] `lib/pcap-parser.js` — add `reassembleTcpStream(packets, direction)` returning
      `{ reassembled, retransmits, partialOverlaps, gaps, segmentCount }`. Sort by
      `(seq - base) | 0` for 32-bit wrap safety; drop fully-covered segments; trim
      partial-overlap tails on the left; report gaps.  SYN/FIN flags consume one
      seq number each in the cursor math so they don't get reported as 1-byte data
      gaps.
- [x] `lib/pcap-parser.js:groupStreams` — Pass 3 after NAT merge attaches `c2sFull`
      / `s2cFull` and `c2sReassembly` / `s2cReassembly` to each stream.  UDP falls
      back to arrival-order concat (no seq numbers to use).
- [x] Replaced all `Buffer.concat(stream.packets.filter(dir).map(payload))` sites:
      `analyzeFullHandshake`, `buildHandshakeAnalysis`, `extractPostHandshakeActions`,
      `findPartnerStream` (one-sided concat → non-empty direction's reassembly),
      `parsePcapToScenario` (clientAbortedBeforeCKE check), `analyzeStream`.
- [x] `lib/pcap-parser.js:generateReplayScenario` — walks packets in arrival order
      but tracks a per-direction `dirCursor` so retransmits drop and partial
      overlaps trim.  Direction-change semantics preserved for raw HTTP-style
      replays.
- [x] `pcapParams.reassembly` records per-direction `{ bytes, segments, retransmits,
      partialOverlaps, gapCount, gapBytes }` so saved scenarios show whether dedup
      fired.  `--list-streams` shows a yellow `[N retransmits, M gaps]` tag only
      when non-zero (clean captures stay quiet).
- [x] Verified: 12-case unit test covering clean / full-retransmit / partial-overlap
      / gap / FIN / out-of-order delivery all pass.  Live `--ingest-pcap` on
      `dist-tls-wb.pcap` (stream 5) shows zero retransmits / zero gaps and a
      runnable scenario.  Pre-existing off-by-one in `lib/pcap-writer.js` that
      added a stray +1 to seq on a non-flag packet surfaces as a real `[2 gaps]`
      tag on the raw-tcp stream — caught by the new reassembler.

Files: `lib/pcap-parser.js` (+~230 lines, removed ~12 lines of duplicated concat).

Pre-existing bug surfaced for future cleanup:
  - `lib/pcap-writer.js` seq tracking applies a +1 somewhere it shouldn't, causing
    the writer's own PCAPs to have 1-byte gaps in each direction on the raw-tcp
    `[0]` stream of `dist-tls-wb.pcap`.  Not in scope here; the new reassembler
    correctly detects and reports it.

## Completed — PCAP Test Cases as Committable .js Files (2026-06-06)

Saved PCAP tests used to live as `pcap-tests/<name>.json` — opaque blob, not editable
in source control, no way for a user to write a test case by hand and commit it.
Replaced with `pcap-test-cases/<name>.js` — one self-contained Node.js module per
test, with all captured Buffers as inline `Buffer.from('hex', 'hex')` literals.

Goal: each ingested PCAP produces a standalone, diff-friendly, commit-ready test file.
A user can read it, edit it, write their own from scratch, or delete it.  No companion
fixtures, no cross-file dependencies between tests.

- [x] `lib/pcap-code-gen.js` (new) — `generateScenarioSource(scenario, opts)` walks a
      scenario object and emits valid Node.js.  Buffers → `Buffer.from('hex', 'hex')`,
      strings via `JSON.stringify`, plain objects with bare-identifier keys when
      safe, action closures resolved to concrete arrays before serialization.
- [x] `lib/pcap-test-cases.js` (new, replaces `lib/pcap-scenarios.js`) — loader for
      `pcap-test-cases/*.js`.  No pending/verified lifecycle — if the file's there,
      it's saved.  `require.cache` is invalidated on every load so in-place edits
      take effect on the next list/run.  API matches the old `pcap-scenarios.js`
      surface so `lib/scenarios.js` integration was a one-line require change.
- [x] `lib/scenarios.js` — `PCAP_CATEGORY` (`'PCAP'`) → `PCAP_CATEGORY` constant
      (`'PCAP-CASE'`) imported from the new module.  Category display label
      `'PCAP Test Cases'`.  Still in `CATEGORY_DEFAULT_DISABLED` so saved tests
      are opt-in via `--category PCAP-CASE` or `--scenario <name>`.
- [x] `cli.js` — added `promptName(default)` that uses readline only when stdin is
      a TTY (CI/non-interactive runs keep the auto-name path).  `--ingest-pcap`
      save call switched to `saveTestCase`.  Command renames:
      - `pcap-tests` → `pcap-test-cases` (alias kept for one cycle)
      - `delete-pcap-test` → `delete-pcap-test-case` (alias kept)
      - `verify-pcap-test` removed (no lifecycle in code form — commit *is* verify)
      - `migrate-pcap-tests` added (one-shot legacy JSON → .js conversion)
- [x] `main.js` + `renderer/app.js` — IPC `save-pcap-test` handler points at the
      new code-gen path.  Toast updated to mention the generated .js file path.
      Renderer category-id strings `'PCAP'` → `'PCAP-CASE'` (two callsites).
- [x] `lib/pcap-scenarios.js` removed.
- [x] Verified end-to-end: `--ingest-pcap dist-tls-wb.pcap --pcap-stream 5 --pcap-name
      my-test-case-1` produces a 6.1KB / 184-line .js file that loads via `require()`,
      registers under `PCAP-CASE`, and runs via `--scenario my-test-case-1`.
      Migration of 8 legacy JSON tests all converted cleanly.

Files: `lib/pcap-code-gen.js` (+170), `lib/pcap-test-cases.js` (+200), `lib/scenarios.js`
(small edits), `cli.js` (~+100 −60), `main.js` (~+10 −20), `renderer/app.js`
(toast + two id strings).  `lib/pcap-scenarios.js` removed.

Legacy `pcap-tests/` directory left in place after migration so users can review the
generated `.js` files before deleting the JSON.

---

## Run History + Comparison Feature

Persist the last 10 outcomes of each suite's test execution and let the user
diff any two runs of the same suite. Plan: `~/.claude/plans/proud-conjuring-dahl.md`.

- [x] `lib/run-history.js` — `saveRun` / `listRuns` / `loadRun` / `setTag`, one
      JSON file per run under `<userData>/run-history/<protocol>/`, pruned to 10
- [x] `lib/run-compare.js` — `compareRuns(prev, curr)` with per-scenario dedupe
      (worst occurrence wins) and match / regressed / improved / status-changed /
      new / removed classification
- [x] `test-run-history.js` — 12 unit tests: retention, ordering, tagging,
      corrupt-file skip, unknown-protocol guard, all classifications, dedupe
- [x] `main.js` — 5 IPC handlers (`history-save|list|load|tag|compare`) with
      protocol/UUID validation before any filesystem access
- [x] `preload.js` — 5 `window.fuzzer` aliases
- [x] `renderer/app.js` — capture hook at the end of `showSummary()` (the one
      completion path shared by local, distributed and cert-verify runs),
      result slimming, auto-compare banner
- [x] UI — History dropdown in `.result-actions`, comparison modal, tagging, CSS

### Verification

- `node test-run-history.js` — 12/12 passing.
- Three Playwright/Electron E2E passes against a live TLS target, all green:
  history file written per run, button enable/disable, auto-compare banner only
  from the second run on, dropdown listing, comparison modal (headline, base
  switcher, show-unchanged toggle), tag persisted to disk and shown in the
  dropdown, `new`/`removed` rows when the scenario selection changes,
  `regressed` rows when the target goes down, per-suite isolation (HTTP/2 tab
  empty while TLS is populated), retention capped at 10, survival across an app
  restart, empty run saving nothing, and STOP-ed runs flagged `aborted`.

### Notes

- A run stopped between scenarios emits no `ABORTED` rows, so the STOP button
  sets a `runStopped` flag that marks the record partial. Without it a truncated
  run would diff as "everything removed" against a full one.
- Heavy fields (`packets`, `probe`, `response`, baseline/firewall/helper data)
  are stripped before persisting — real run files land around 1.5 KB.
- Pre-existing, unrelated: LOCAL TARGET mode cannot start its TLS server inside
  Electron ("Failed to set ECDH curve") because Electron's BoringSSL lacks the
  PQC named groups `WellBehavedServer` requests; the same server starts fine
  under plain Node. E2E therefore ran in client mode against an external target.

---

## Fix: LOCAL TARGET mode failed inside Electron ("Failed to set ECDH curve")

**Root cause.** `getOpenSSLGroups()` shelled out to the `openssl` binary on PATH
to discover named groups, then handed that list to `tls.createSecureContext()`
— but the CLI and the TLS library compiled into the running process are
different implementations. Electron links BoringSSL, which accepts
`X25519MLKEM768` and `MLKEM1024` but rejects `SecP256r1MLKEM768`,
`SecP384r1MLKEM1024`, `MLKEM768` and `MLKEM512`. `ecdhCurve` validates the
colon-joined list as a unit, so one unsupported name rejected the whole list
and the local server never started.

**Why distributed mode was unaffected.** Its servers run in agent processes
started with `node client.js --agent` / `node server.js --agent` (locally or
over SSH), i.e. plain Node linked against OpenSSL — the same family as the CLI
being probed, so the two lists agreed. Only local mode builds its server inside
the Electron main process (`main.js:315`, `new WellBehavedServer(...)`), which
is where the two disagreed. The fix also hardens agents on remote hosts whose
`openssl` CLI is newer than their `node`.

- [x] `lib/tls-groups.js` (new) — `getNodeTlsGroups()` probes the *running*
      TLS stack by attempting each candidate group, verifies the joined list,
      falls back to classical curves, and caches. No subprocess. Also exports
      `hasPqcSupport()`.
- [x] `lib/well-behaved-server.js`, `lib/unified-server.js` — use it in place
      of their local CLI-probing copies (both feed `tls.createSecureContext`)
- [x] `lib/scan-scenarios.js` — same fix for `WELL_BEHAVED_GROUPS`, which
      predicts what the Node server can negotiate and so drives scan
      `expected` verdicts. Its comment already said "Node TLS server"; it was
      probing the CLI.
- [x] `lib/baseline.js`, `lib/openssl-peer.js` — intentionally left alone:
      they pass `-groups` to a spawned `openssl` binary, so probing the CLI is
      correct there.
- [x] `test-tls-groups.js` (new) — 8 tests, green under both plain Node and
      Electron (`ELECTRON_RUN_AS_NODE=1`).

### Verification

- Groups resolved: Node → all 10 candidates; Electron → the 6 BoringSSL
  accepts. PQC retained in both.
- GUI: LOCAL TARGET run of a classical and a PQC ClientHello scenario now
  completes (previously "Failed to start local server"), both graded PASS.
- Regression sweep in Electron: LOCAL TARGET works on all four tabs — TLS,
  HTTP/2, QUIC, Raw TCP — each recording to its own history directory.
- Scan `expected` verdicts identical before and after in both runtimes
  (18 DROPPED / 6 PASSED for PQC rows).

---

## Fix: a run where nothing executed was graded "A — all tests passed"

**Root cause.** `gradeResult()` returned `INFO` for two unrelated outcomes:
"the scenario ran but had no expected value to assert against", and "the
scenario never ran at all" (ERROR/ABORTED). `computeOverallGrade()` picks a
letter from fails and warns only, so a run where every scenario failed to
connect had zero fails, zero warns → fell through to the final `else` →
Grade A, "All tests passed — robust TLS implementation". The CLI already
exited 1 on errors; only the grade lied.

**Design.** A grade is a claim about the target's security posture, and that
claim is only meaningful if tests produced verdicts. Errors are evidence
neither for the target (not A) nor against it (not D/F) — grading them as
failures would report a phantom vulnerability when someone simply typo'd a
port, and would put connection failures in the CLI's "Security Findings"
list. The honest third answer is *inconclusive*.

- [x] `lib/grader.js` — `ERROR` is now its own per-scenario finding grade,
      distinct from `INFO`. `stats` gains `error`. New overall grade `I`
      when nothing executed or more than half the scenarios errored.
      Precedence: hostDown → F and critical → F are both checked *before*
      the inconclusive test, since a crash makes every later scenario error
      and must not be softened. The warn ratio is now measured against
      scenarios that actually ran, and an A-grade label discloses skipped
      tests instead of claiming all passed.
- [x] `lib/grader.js` — hostDown is now checked before critical severity.
      hostDown always produces a critical finding, so the "Target crashed
      during testing" branch was unreachable; a crash is more specific than
      "critical vulnerability".
- [x] `lib/run-compare.js` — `ERROR` ranked between INFO and WARN, plus an
      explicit rule that a scenario which stopped running is a regression
      whatever it reported before (FAIL outranks ERROR, so the rank
      comparison alone would have called losing coverage an improvement).
- [x] `lib/logger.js`, `renderer/app.js`, `renderer/styles.css` — grey `I`
      badge (`.grade-I`), `.finding-ERROR` style, and a "DID NOT RUN: n"
      count in both the GUI summary bar and the CLI banner.
- [x] `test-grader.js` (new) — 13 tests, plus 2 added to
      `test-run-history.js` for the ERROR transitions.

### Verification

- 13 grader tests green, covering: ERROR vs INFO separation, all-errored →
  I, empty run → I, majority-errored → I, minority errors → still A with a
  disclosing label, clean run → unchanged A label, crash → F not I,
  critical → F despite errors, errors excluded from `findings[]`, warn ratio
  over executed scenarios.
- All unit suites green under both plain Node and the Electron runtime.
- GUI: a run against a dead port now shows a grey `I`, "Inconclusive — 2 of 2
  scenarios did not run", `DID NOT RUN: 2`, and ERROR findings; a healthy run
  still shows `A` with the original label and no did-not-run count. Comparing
  the two reads as "2 improved".
- CLI: `OVERALL GRADE: I` with the same label; exit code still 1.
- Four-suite LOCAL TARGET sweep still green.

---

## Fix: distributed runs graded "Inconclusive — no scenarios ran"

Reported after the grading change: a TLS category-A distributed run against
local agents showed every scenario passing in the table, but the banner read
`Inconclusive — no scenarios ran` with `PASS: 0`.

**Root cause — a latent bug the grading change exposed.** In distributed mode
each agent computes `computeOverallGrade(state.results)` over *its own* half
and broadcasts a `report` event; `main.js` forwarded both verbatim and the
renderer's `onReport` handler did `lastReport = report`, so whichever agent
finished last won. In a client-fuzz run the server agent is only the
well-behaved helper — its results are broadcast as `debug-result` and merged
into the client's rows, so its own `state.results` is empty. When that empty
report landed second, the UI displayed a grade computed from zero scenarios.
It previously rendered as a green `A` ("All tests passed"), which looked
plausible and hid the bug; grading an empty set as `I` made it visible.

There is a second reason an agent's own report can't be trusted: `tryMerge()`
in `main.js` re-grades server-fuzz rows after merging in the helper's
observation, so the agent's grade for those rows is stale by construction.

**Fix.** `main.js` now grades the set it actually forwarded to the renderer.
Every displayed row passes through `emitFuzz()` or `tryMerge()`, so both
accumulate into `distributedResults`; the `report` event emits
`computeOverallGrade(distributedResults)` instead of the agent's partial
report, and the drain re-emits after `flushPendingRows()` so late-merged rows
are counted. The array is per-subscription, and `subscribeDistributedEvents()`
runs at the start of every distributed run, so it resets naturally.

- [x] `main.js` — accumulate forwarded rows; emit a merged report on the
      agent `report` event and again after the post-run drain.

### Verification

Reproduced and fixed both directions with the same GUI driver, two local
agents (`node client.js`, `node server.js`) and 3 category-A scenarios:

- With the fix reverted: 3 rows, all `TLS-ALERT-SERVER`, grade
  `I — Inconclusive — no scenarios ran`, `PASS: 0` — matching the report.
- With the fix: same 3 rows, grade `A — All tests passed`, `PASS: 3`, and the
  history record stores grade `A`.
- Graded count now equals the row count shown in the table (3 of 3).
- Unit suites and the local-mode grading checks still green.

---

## Rework: run history UX (save prompt + Compare)

Feedback: the history/comparison UI was not intuitive — saving was invisible
(runs were stored silently), naming was buried inside the comparison modal,
and the button said "History" while the feature people wanted was comparison.

- [x] **Save prompt after every run.** New `#saveRunOverlay` modal shows a
      one-line summary (suite · scenario count · grade · unexpected count ·
      whether it was stopped early), a name field, and SAVE / DON'T SAVE.
      Enter saves, Escape dismisses.
- [x] **The run is written to disk before the prompt appears**, and the
      prompt only names it or deletes it. A dismissed dialog, a crash, or a
      stray click therefore cannot lose a run, and the auto-comparison
      always has a baseline. DON'T SAVE calls the new delete path.
- [x] **"History" renamed "Compare"** (`#compareBtn` / `#compareMenu`).
- [x] **Menu now leads with the comparison people want**: a
      "Compare current run with" section listing the other saved runs, then
      "Compare any two saved runs…" for picking both sides. When there is no
      current run (e.g. straight after launch) it falls back to a plain
      "Saved runs" list.
- [x] **Comparison modal takes two selectors** (`base → target`) instead of a
      fixed current-run side, so any two saved runs can be diffed without
      reopening. Both entry points now open the same view and differ only in
      what they preselect. Same run on both sides shows "Pick two different
      runs to compare." rather than an empty diff.
- [x] **Named runs lead with their name** in the menu, the selectors and the
      modal subtitle; unnamed ones fall back to their timestamp. The modal
      footer relabelled "Rename left run" / SAVE NAME.
- [x] `lib/run-history.js` `deleteRun()`, `history-delete` IPC handler,
      `historyDelete` preload alias, `.history-menu-heading` style.

### Verification

- `test-run-history.js` extended with a `deleteRun` test (removes only the
  named run, reports false on a second delete); the corrupt-file test was
  made order-independent since deletion changes the run count.
- 18-check GUI driver, all green: prompt appears after each run and
  summarises it; the run is on disk *before* the prompt; the entered name is
  persisted; Compare enables after the first save; the menu shows both the
  "current run" section and the any-two entry; run names appear in the menu
  and both selectors with the current run flagged; the diff renders; swapping
  a selector re-runs the comparison; DON'T SAVE removes that run and leaves
  the named ones intact.
- Unit suites and the four-suite LOCAL TARGET sweep still green (that driver
  now dismisses the new prompt between suites).
