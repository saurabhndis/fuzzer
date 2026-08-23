# Attestation UIs — client login box + operator admin console
Plan: ~/.claude/plans/refactored-forging-dewdrop.md

## Server repo (wirestrike-attest-server)
- [x] 1a: DB — active_runs table + start/heartbeat/finish/listActive/pruneStale, listAllRuns, runCountsByUser
- [x] 1b: Live-tracking endpoints POST /runs/start|heartbeat|finish (mTLS); submit clears active
- [x] 1d: lib/run-compare.js (cross-user pure compare)
- [x] 1c: lib/admin-ops.js (identity status/generate/import, users+stats, active, all runs, compare, verify token)
- [x] test: extend test-attest-server.js (live tracking, listAllRuns); new test-admin-ops.js
- [x] 1e: admin Electron app (admin/main.js, preload.js, renderer/*), package.json script, README

## Fuzzer repo
- [x] 2c: attestation-remote reportRunStart/Heartbeat/Finish
- [x] 2b: lib/run-reporter.js + hooks in cli.js + main.js run-fuzzer
- [x] 2a: client login box — main.js account-* handlers, preload bridge, renderer badge+modal
- [x] test: extend test-attest-client.js (run-reporter)

## Verify
- [x] server test green, admin-ops test green (12), client test green (12 incl live reporter), fuzzer core green
- [x] server repo committed
- [ ] Electron GUIs not launched here (need a display) — verified by syntax-check + headless logic tests; manual smoke documented in READMEs

## Review

Delivered both UIs.

**Fuzzer client login box:** header badge (`Anonymous`/`● username`) + modal (server URL, work email, optional username, choose-cert, Create/Sign in/Sign out) in `renderer/index.html|app.js|styles.css`; `account-*` IPC handlers in `main.js` delegating to `lib/attestation-remote.js`; bridge methods in `preload.js`. Live-run reporting: new `lib/run-reporter.js` (owns a 15s heartbeat, no-op when anonymous, never fatal) + `reportRun{Start,Heartbeat,Finish}` in `attestation-remote.js`, hooked into the CLI client run (`cli.js`) and the GUI `run-fuzzer` handler (`main.js`).

**Operator admin console (private server repo):** new `active_runs` table + `POST /runs/start|heartbeat|finish` (mTLS; submit clears the active row); cross-user DB reads (`listAllRuns`, `runCountsByUser`); pure `lib/run-compare.js` (cross-user); `lib/admin-ops.js` (identity status/generate/import PEM-with-validation, users+stats, live/stale active runs, all runs, run detail, compare-by-serial, token verify + DB cross-check); an Electron app under `admin/` with Identity/Users/Running/Saved/Compare/Verify tabs; `npm run admin`.

**Tests:** server suite extended (live tracking, cross-user) — all green; new `test-admin-ops.js` (12 headless cases incl. import validation, live/stale, cross-user compare, token verify); `test-attest-client.js` extended with a real run-reporter round-trip against a spawned server. All four suites pass; server repo committed.

**Not done:** GUIs not launched in this environment (no display) — covered by parse checks + headless logic tests and the documented manual smoke steps. GUI runs don't auto-*submit* attested receipts yet (they only report live status); submission remains via CLI `--attest`/`submit`. Fuzzer repo changes are staged, not committed.
