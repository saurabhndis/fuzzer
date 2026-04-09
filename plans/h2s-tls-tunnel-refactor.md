# H2S Server-Side TLS Tunnel Refactor

## Status: Planned (not yet implemented)

## Problem

All server-side HTTP/2 fuzzing scenarios (H2S category — ~30+ scenarios) use `writeRawFrame()` in `lib/frame-generator.js:96` which writes to `session._rawSocket` — the **raw TCP socket** captured via the `'connection'` event on `http2.createSecureServer()`. This bypasses TLS entirely.

### What happens on the wire

```
Server writes raw HTTP/2 frame bytes → raw TCP socket → client receives cleartext bytes
Client's TLS layer sees non-TLS data → ERR_SSL_BAD_RECORD_TYPE
```

The client never parses the malformed HTTP/2 frame because the bytes arrive outside the TLS record framing. The client rejects the connection as a TLS error, not as the intended HTTP/2 protocol error (GOAWAY/RST_STREAM/FRAME_SIZE_ERROR).

### Why it can't be fixed within http2.createSecureServer()

Node.js's HTTP/2 implementation makes it impossible to write raw bytes through the TLS socket when an HTTP/2 session is active:

1. **`session.socket.write()`** → `ERR_HTTP2_NO_SOCKET_MANIPULATION` (Node wraps session.socket in a Proxy that blocks direct writes)
2. **`session[Symbol(socket)].write()`** → Native assertion crash (`!current_write_` in `crypto_tls.cc`) — races with HTTP/2 session's TLS write pipeline
3. **Deferred writes via `setImmediate()`/`setTimeout()`** → Same native crash — the HTTP/2 session's `SendPendingData()` is triggered by incoming data and races at the libuv level

This was verified experimentally on Node.js v24.14.0.

## Proven Solution

Use a **raw `tls.createServer()`** instead of `http2.createSecureServer()` for scenarios that need to inject malformed frames. This gives direct access to the TLS socket without any HTTP/2 session interfering.

### Validated experiment

```javascript
const server = tls.createServer({
  key: cert.privateKeyPEM,
  cert: certPEM,
  ALPNProtocols: ['h2'],
}, (tlsSocket) => {
  // Read client HTTP/2 preface (24 bytes)
  // Send server SETTINGS + SETTINGS ACK
  // Send malformed PUSH_PROMISE frame
  tlsSocket.write(frame); // ← Works! No crash, no TLS error
});
```

Result: Frames arrive at the client inside the TLS tunnel. No crashes, no TLS errors. The client's HTTP/2 implementation can parse and reject the malformed frame properly.

## Architecture

```
Current (broken):
  Client ←TLS→ http2.createSecureServer() → session._rawSocket.write(frame) → raw TCP → client TLS rejects

Proposed (fixed):
  Client ←TLS→ tls.createServer() → tlsSocket.write(frame) → TLS encrypted → client HTTP/2 parses
```

### Flow for raw TLS server path

1. Client connects via TLS with ALPN `h2`
2. Server accepts TLS connection, gets `tlsSocket`
3. Server reads client's HTTP/2 connection preface (24 bytes: `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
4. Server sends SETTINGS frame + SETTINGS ACK
5. Server reads client's SETTINGS ACK and HEADERS frame (to get stream ID)
6. Server calls scenario's `serverHandler` with the `tlsSocket` and parsed stream info
7. Scenario writes malformed frame via `tlsSocket.write()`
8. Server reads client's response (GOAWAY/RST_STREAM) to determine pass/fail

## Implementation Plan

### 1. Add `writeRawFrameTLS()` to `lib/frame-generator.js`

```javascript
function writeRawFrameTLS(tlsSocket, frame) {
  if (tlsSocket && !tlsSocket.destroyed) tlsSocket.write(frame);
}
```

### 2. Add `_execH2RawTLS()` method to `lib/unified-server.js`

New execution path for H2S scenarios that use raw frame injection:
- Creates `tls.createServer()` with ALPN `h2`
- Manually handles HTTP/2 connection preface
- Parses incoming frames to detect client's HEADERS request
- Calls scenario's `serverHandler` with mock stream/session providing `tlsSocket`
- Reads client response for pass/fail determination

### 3. Update scenario `serverHandler` signature

Add `tlsSocket` property to the session object passed to handlers:
- `writeRawFrame(session, frame)` — existing API, now writes to `session.tlsSocket` instead of `session._rawSocket`
- Or scenarios can use `session.tlsSocket.write(frame)` directly

### 4. Mark scenarios with `useRawTLS: true`

Add flag to all H2S scenarios that call `writeRawFrame()`. The server dispatcher checks this flag to route to `_execH2RawTLS()`.

### 5. Update `lib/http2-fuzzer-server.js`

Apply same `tls.createServer()` approach to the standalone HTTP/2 fuzzer server.

## Files to Modify

| File | Change |
|------|--------|
| `fuzzer/lib/frame-generator.js` | Add `writeRawFrameTLS()` export, update `writeRawFrame()` to prefer TLS socket |
| `fuzzer/lib/unified-server.js` | Add `_execH2RawTLS()` method, route `useRawTLS` scenarios |
| `fuzzer/lib/http2-fuzzer-server.js` | Add raw TLS server path for writeRawFrame scenarios |
| `fuzzer/lib/http2-scenarios.js` | Add `useRawTLS: true` to all H2S scenarios using `writeRawFrame()` |

## Affected Scenarios

All H2S server-side scenarios that use `writeRawFrame()`:
- `h2-server-push-promise-odd-stream`
- `h2-server-push-promise-padded-truncated` (new)
- `h2-server-push-promise-padded-short-id` (new)
- `h2-server-continuation-no-headers`
- `h2-server-goaway-nonzero-stream`
- `h2-server-uppercase-header`
- `h2-server-connection-header`
- `h2-server-transfer-encoding`
- `h2-server-multiple-status`
- `h2-server-pseudo-after-regular`
- `h2-server-request-pseudoheaders`
- `h2-server-te-non-trailers`
- `h2-server-unknown-frames`
- ... and others in the H2S/AK/AL categories

## Risk Assessment

- **Scope**: Affects all ~30 H2S server-side scenarios
- **Backward compatibility**: Existing scenarios continue to work — `useRawTLS` flag opts in
- **Complexity**: Main complexity is building a minimal HTTP/2 frame parser for the server side
- **Testing**: Raw TLS approach validated experimentally; HTTP/2 preface parsing is straightforward

## Related Changes Already Made

1. Added 4 new PUSH_PROMISE padded truncation scenarios to `lib/http2-scenarios.js`
2. Fixed PCAP generation for HTTP/2 tests in `test-http2-distributed.js` (added `pcapFile` + `mergePcap` to config)
3. Regenerated `docs/test-scenarios.html`
