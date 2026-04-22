# Lessons Learned

## PCAP File Generation
- **String and Array Payloads**: Always safely coerce inputs to `Buffer` before interacting with raw byte manipulation.
- **Protocol Encapsulation**: Wrap lower-level protocol payloads in the complete suite of underlying headers (IP + UDP) using an explicit protocol encapsulator.
- **Direction Aliasing**: Mapping UI-friendly terms like 'sent' and 'received' to networking terms like 'outbound' and 'inbound' must be consistent across all writer methods.
- **Handshake Interception**: Node.js `tls.connect` abstracts the handshake; capturing it requires intercepting the raw `net.Socket` before or during the `tls.Socket` construction.
- **UDP vs TCP Handshakes**: Synthetic TCP SYN/ACK sequences are useful for TLS-over-TCP analysis but confusing and irrelevant for UDP-based protocols like QUIC.
- **Timing of Capture Calls**: Handshake simulation (like `writeTCPHandshake`) must be called *before* the asynchronous connection logic starts to ensure proper ordering in the PCAP file.

## PCAP Ingestion & NAT Handling
- **NAT Breaks 5-Tuple Grouping**: When a NAT device rewrites the client IP, the standard 5-tuple (proto, srcIp, srcPort, dstIp, dstPort) won't match the forward and reverse directions. The client→server packet uses the pre-NAT IP while the server→client response uses the post-NAT IP, creating two separate one-sided streams instead of one bidirectional stream.
- **Two-Pass Stream Grouping**: Use exact 5-tuple matching first (fast, handles the common case), then a NAT-aware merge pass that joins one-sided streams sharing the same server IP:port and client transport port. NAT devices typically preserve the client port even when rewriting the IP.
- **Complementary Handshake Detection**: When merging NAT-split streams, verify that one side has a TLS ClientHello and the other has a ServerHello. This prevents false merges of unrelated one-sided streams.
- **Timestamp Guards**: NAT-merged streams must have overlapping timestamps (within 30 seconds) to avoid merging streams from different sessions that happen to share the same ports.
- **Direction Re-labeling**: After merging, packets from the ClientHello side become `c2s` and packets from the ServerHello side become `s2c`, regardless of what `groupStreams` originally assigned based on first-packet heuristics.

## PCAP Distributed Mode
- **Scenario Serialization**: PCAP-generated scenarios contain Buffers and closure functions that can't be sent as JSON. The solution is to evaluate the action functions eagerly and convert all Buffers to `{ _hex: '...' }` markers, then reconstruct them on the receiving end.
- **Agent Inline Scenarios**: The agent's `/configure` endpoint was designed for named scenarios resolved from the scenario registry. Adding a `pcapScenarios` array parameter allows injecting pre-built scenario objects without requiring them to be registered by name.
- **Stepped Orchestration**: For PCAP replay, the server must start listening before the client connects. Using the controller's `runStepped()` pattern (POST `/run-scenario` to server first, wait, then POST to client) ensures correct ordering.
- **Side Swapping**: A single PCAP scenario generates both client and server actions. When pushing to agents, the same serialized scenario is sent to both, but the `side` field is set to match the agent's role so each agent knows which action set to execute.

## Cancel-and-Restart (Professional-Feel Cleanup)
- **`/stop` must await cleanup**: If the handler returns before workers have actually exited and the fuzzer has torn down, the controller will hand the agent a new `/configure` that races stale state. Make cleanup async and poll `activeWorkers.size === 0` (short grace, ~2s) before resolving.
- **Controller side needs its own reset**: Even a perfect agent /stop doesn't save you if the controller carries event streams or barrier waiters from the cancelled run into the next one. On new-run entry, destroy existing NDJSON streams and clear the barrier table; on stopAll, also poll each agent's `/status` until `idle` so the next run sees a confirmed-clean surface.
- **Two checkpoints for "clean cancel"**: (1) agent returns idle from `/status` right after /stop resolves, (2) run 2's `/results` contains only run 2's scenarios. A regression test that asserts both is the fastest way to keep the UX honest as the code evolves.

## Reproducibility and Observability
- **Log the trace, not just the stream**: The agent's NDJSON event stream is for UI; a per-scenario NDJSON file on disk is for debugging. Fan out every logger call into a `ScenarioTracer.record(event, data)` so the same stream exists in a form you can `jq` and `grep` offline. Monotonic `t` from `process.hrtime.bigint()` is far more useful than wall-clock for "what happened in the last 300 ms before the hang."
- **Fingerprint scenarios by body, not name**: `scenarioFingerprint()` hashes the stringified actions function (plus name/description/side/category). This catches the case where a scenario keeps the same name but its actions were edited — the manifest will show a different fingerprint, and a "reproduction" run will be marked as actually running different code. Hashing the function source is trivially stable in Node: `fn.toString()` is deterministic.
- **Manifests must carry git dirty flag**: "Works on my machine" is almost always an uncommitted change. A manifest that records `git.dirty: true` tells you immediately that a reported result may not correspond to any commit. Emit it even when null (when git isn't available) so downstream tooling can distinguish "unknown" from "clean".
- **Don't rely on the fuzzer class calling your logger**: Scenarios with `useNodeTLS: true` / `clientHandler` bypass the action loop entirely — so `logger.sent`/`received` never fires, and the trace will show only scenario-start/end. Pick a scenario with explicit `send`/`recv` actions when writing integration tests for the tracer; document which scenario families use which code path.

## Cross-Peer Sync via Control Plane
- **Sync traffic must never touch the fuzz socket**: Sending barrier/peer-done data over the socket being fuzzed would change the bytes on the wire that detection engines see. Route all coordination over the existing agent HTTP control plane (NDJSON events up, POST endpoints down) so the data plane is untouched.
- **Piggyback on existing event streams**: The controller already maintains an NDJSON stream per agent. Emitting `barrier-arrived` / `peer-done` events through `broadcastEvent` and matching them in `_emitEvent` is far cheaper than standing up a new inbound HTTP listener on the controller.
- **Every waiter needs a safety timer**: Controller-side barrier entries get a 10s one-shot timer on first arrival so a crashed peer can't deadlock its counterpart. The agent-side `Barrier` also owns a per-waiter timer — defense-in-depth so a dropped /release-barrier POST doesn't hang the action loop.
- **peer-done is `/abort-scenario` at the controller**: One side declares it's finished; controller POSTs `/abort-scenario` to the peer, which sets `_scenarioAborted` and flushes pending barriers. The peer's action loop picks up the flag at its next iteration check. No data-plane chatter.
- **Reset barrier state on every scenario start**: `runScenario` calls `barrier.releaseAll('new scenario start')` so a stale waiter from the previous (possibly aborted) scenario can't match against the new run. Same for `_scenarioAborted`.

## Distributed-Mode Sync, Hangs, and Alert Races
- **Readiness, not sleep**: Replace fixed delays between "start server" and "connect client" with an HTTP `/ready` probe on the agent. A 300ms sleep races on cold starts and under load; polling a cheap endpoint is both faster (often <50ms) and correct.
- **Socket-readiness must include `end`/`close`**: `once('data')` alone hangs if the peer connects and immediately FINs. Always listen for `end`, `close`, and `error` alongside, and share a single settle-once guard so whichever fires first resolves deterministically.
- **Alert-before-close preservation**: When a `recv` sees `connectionClosed && buffer.empty`, DO NOT clobber a previously observed `tls-alert-*` status with `DROPPED`. An earlier recv may have already captured the alert.
- **One `setImmediate` tick after `_waitForData`**: Node can deliver queued `data` events in the same microtask turn as `close`. A single tick lets the tail drain into the buffer before the recv decides it's empty.
- **Explicit UDP bind**: `dgram.createSocket()` + `send()` binds implicitly on first use. Bind errors (EADDRINUSE, permission) then appear as send failures and can hang scenarios. Explicit `bind(0, ...)` with `'error'` rejection surfaces failures cleanly.
- **Bounded teardown timeouts**: Shutdown signals must use a bounded timer (e.g. 2s) + `end`/`close`/`error` listeners rather than a fixed sleep. Fixed sleeps either over-wait on fast paths or under-wait on slow paths, and silent `on('error')` handlers mask bind-collision cascades on the next run.

## PCAP Test Category & Lifecycle
- **Persistent Storage**: PCAP-generated scenarios are serialized to JSON files in `pcap-tests/`. This allows them to survive process restarts and be shared across team members via version control.
- **Pending/Verified Workflow**: New tests start as "pending" — they appear in listings but aren't included in `--scenario all`. After the user runs and reviews results, they mark the test as "verified" to promote it to the permanent suite.
- **Name-Based Resolution**: PCAP tests are resolved by name through the existing `getScenario()` chain (`scenarios.js` → `pcap-scenarios.js`). This means agents can run PCAP tests by name without any special handling — the same `/configure` endpoint works for both named and inline scenarios.
- **Category Registration**: The `PCAP` category is registered in `CATEGORIES` and `CATEGORY_DEFAULT_DISABLED`. This means `--category PCAP` works, `list` shows the category, but `--scenario all` excludes PCAP tests unless explicitly opted in.
- **Buffer Coercion in Action Processing**: When PCAP scenarios are loaded from saved JSON files, Buffer objects may arrive as `{ _hex: '...' }` marker objects if the deserialization didn't fully traverse nested structures. The unified client's action processing loop must defensively coerce `action.data` and `action.clientHello` back to Buffers before passing them to `socket.write()`. This is a safety net on top of the proper `deserializePcapScenario()` function.
