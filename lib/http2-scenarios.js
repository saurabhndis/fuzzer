// HTTP/2 fuzzing scenarios
// Ported from: http2-fuzzer-core, http2-fuzzer, http2-fuzzer-ui
//
// Client-side scenarios (side: 'client') connect to a target HTTP/2 server and send
// malformed/fuzz frames — testing whether the server rejects protocol violations.
//
// Server-side scenarios (side: 'server') require the fuzzer to run as an HTTP/2 server.
// The fuzzer sends malformed frames to connecting clients — testing whether clients
// enforce RFC 7540 rules on what they receive.
//
// Categories:
//   AA — CVE & Rapid Attack           (critical, client)
//   AB — Flood / Resource Exhaustion  (high,     client)
//   AC — Stream & Flow Control        (high,     client)
//   AD — Frame Structure & Headers    (medium,   client)
//   AE — Stream Abuse Extensions      (high,     client)
//   AF — Extended Frame Attacks       (medium,   client)
//   AG — Flow Control Attacks         (high,     client)
//   AH — Connectivity & TLS Probes   (info,     client)
//   AI — General Frame Mutation       (low,      client)
//   AJ — Server-to-Client Attacks     (high,     server) — malformed responses/frames
//   AK — Server Protocol Violations   (high,     server) — RFC §§4-6 frame/stream rules
//   AL — Server Header Violations     (medium,   server) — RFC §8.1.2 header field rules

const { FrameType, Flag, createFrameHeader, createGoAwayFrame, buildFrame, writeRawFrame } = require('./frame-generator');

// HTTP/2 client connection preface magic (RFC 7540 §3.5)
const H2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');

// Helper — empty SETTINGS as connection preface frame
function prefaceBuffer() {
  return Buffer.concat([H2_PREFACE, createFrameHeader(0, FrameType.SETTINGS, 0, 0)]);
}

// Helper — minimal HEADERS placeholder payload (not HPACK-encoded, just bytes)
const MINIMAL_HEADERS_PAYLOAD = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

// Helper — HPACK-encoded minimal headers (method GET, path /, scheme https, authority localhost)
const HPACK_MINIMAL = Buffer.from([0x82, 0x84, 0x86, 0x41, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74]);

const HTTP2_CATEGORIES = {
  AA: 'HTTP/2 CVE & Rapid Attack',
  AB: 'HTTP/2 Flood / Resource Exhaustion',
  AC: 'HTTP/2 Stream & Flow Control Violations',
  AD: 'HTTP/2 Frame Structure & Header Attacks',
  AE: 'HTTP/2 Stream Abuse Extensions',
  AF: 'HTTP/2 Extended Frame Attacks',
  AG: 'HTTP/2 Flow Control Attacks',
  AH: 'HTTP/2 Connectivity & TLS Probes',
  AI: 'HTTP/2 General Frame Mutation',
  AJ: 'HTTP/2 Server-to-Client Attacks',
  AK: 'HTTP/2 Server Protocol Violations',
  AL: 'HTTP/2 Server Header Violations',
};

const HTTP2_CATEGORY_SEVERITY = {
  AA: 'critical',
  AB: 'high',
  AC: 'high',
  AD: 'medium',
  AE: 'high',
  AF: 'medium',
  AG: 'high',
  AH: 'info',
  AI: 'low',
  AJ: 'high',
  AK: 'high',
  AL: 'medium',
};

// Server-side categories require a connecting client — disabled by default
const HTTP2_CATEGORY_DEFAULT_DISABLED = new Set(['AJ', 'AK', 'AL']);

// Helper — build a non-Huffman HPACK literal header with incremental indexing (new name).
// Both name and value must be < 127 bytes (single-byte length prefix).
function hpackLiteral(name, value) {
  const n = Buffer.from(name);
  const v = Buffer.from(value);
  return Buffer.concat([
    Buffer.from([0x40]),             // incremental indexing, new name
    Buffer.from([n.length & 0x7F]), // H=0, 7-bit length
    n,
    Buffer.from([v.length & 0x7F]), // H=0, 7-bit length
    v,
  ]);
}

const HTTP2_SCENARIOS = [

  // ═══════════════════════════════════════════════════════════════════
  // Category AA: CVE & Rapid Attack
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-rapid-reset-cve-44487',
    category: 'AA',
    description: 'Rapid Reset Attack (CVE-2023-44487) — 100 HEADERS+RST_STREAM pairs in rapid succession',
    side: 'client',
    actions: () => {
      const attackFrames = [];
      let streamId = 1;
      for (let i = 0; i < 100; i++) {
        const headersFrame = Buffer.concat([
          createFrameHeader(MINIMAL_HEADERS_PAYLOAD.length, FrameType.HEADERS, Flag.END_HEADERS, streamId),
          MINIMAL_HEADERS_PAYLOAD,
        ]);
        const rstPayload = Buffer.alloc(4);
        rstPayload.writeUInt32BE(0x08, 0); // CANCEL error code
        const rstFrame = Buffer.concat([
          createFrameHeader(4, FrameType.RST_STREAM, 0, streamId),
          rstPayload,
        ]);
        attackFrames.push(headersFrame, rstFrame);
        streamId += 2;
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(attackFrames), label: '[FUZZ] 100× HEADERS+RST_STREAM (Rapid Reset CVE-2023-44487)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should rate-limit or reject rapid stream resets (CVE-2023-44487)',
  },

  {
    name: 'h2-continuation-flood',
    category: 'AA',
    description: 'CONTINUATION Flood — HEADERS without END_HEADERS followed by 50 CONTINUATION frames',
    side: 'client',
    actions: () => {
      const streamId = 1;
      const initialHeaders = Buffer.concat([
        createFrameHeader(MINIMAL_HEADERS_PAYLOAD.length, FrameType.HEADERS, 0, streamId),
        MINIMAL_HEADERS_PAYLOAD,
      ]);
      const contPayload = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      const contFrames = [];
      for (let i = 0; i < 50; i++) {
        const flags = (i === 49) ? Flag.END_HEADERS : 0;
        contFrames.push(Buffer.concat([
          createFrameHeader(contPayload.length, FrameType.CONTINUATION, flags, streamId),
          contPayload,
        ]));
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: initialHeaders, label: '[FUZZ] HEADERS (no END_HEADERS — forces CONTINUATION state)' },
        { type: 'send', data: Buffer.concat(contFrames), label: '[FUZZ] 50× CONTINUATION frames (flood)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should impose limits on CONTINUATION frame count before END_HEADERS',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AB: Flood Attacks / Resource Exhaustion
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-settings-flood',
    category: 'AB',
    description: 'SETTINGS Flood — sends 50 SETTINGS frames to exhaust server ACK queue',
    side: 'client',
    actions: () => {
      const settingsFrames = [];
      for (let i = 0; i < 50; i++) {
        settingsFrames.push(createFrameHeader(0, FrameType.SETTINGS, 0, 0));
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(settingsFrames), label: '[FUZZ] 50× SETTINGS frames (flood)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should rate-limit SETTINGS frames and not buffer unlimited ACKs',
  },

  {
    name: 'h2-ping-flood',
    category: 'AB',
    description: 'PING Flood — sends 50 PING frames to trigger 50 PING ACK responses',
    side: 'client',
    actions: () => {
      const pingPayload = Buffer.alloc(8);
      const pingFrames = [];
      for (let i = 0; i < 50; i++) {
        pingFrames.push(Buffer.concat([
          createFrameHeader(8, FrameType.PING, 0, 0),
          pingPayload,
        ]));
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(pingFrames), label: '[FUZZ] 50× PING frames (flood)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should rate-limit PING responses to prevent amplification',
  },

  {
    name: 'h2-empty-frames-flood',
    category: 'AB',
    description: 'Empty DATA Frames Flood — 50 zero-length DATA frames on a single stream',
    side: 'client',
    actions: () => {
      const streamId = 1;
      const openStream = Buffer.concat([
        createFrameHeader(MINIMAL_HEADERS_PAYLOAD.length, FrameType.HEADERS, Flag.END_HEADERS, streamId),
        MINIMAL_HEADERS_PAYLOAD,
      ]);
      const dataFrames = [];
      for (let i = 0; i < 50; i++) {
        const flags = (i === 49) ? Flag.END_STREAM : 0;
        dataFrames.push(createFrameHeader(0, FrameType.DATA, flags, streamId));
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: openStream, label: 'HEADERS (open stream 1)' },
        { type: 'send', data: Buffer.concat(dataFrames), label: '[FUZZ] 50× empty DATA frames (flood)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should limit empty DATA frames per stream',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AC: Stream & Flow Control Violations
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-max-concurrent-streams-bypass',
    category: 'AC',
    description: 'Exceeds SETTINGS_MAX_CONCURRENT_STREAMS — opens 110 streams beyond the default limit of 100',
    side: 'client',
    actions: () => {
      const frames = [];
      let streamId = 1;
      for (let i = 0; i < 110; i++) {
        frames.push(Buffer.concat([
          createFrameHeader(MINIMAL_HEADERS_PAYLOAD.length, FrameType.HEADERS, Flag.END_HEADERS, streamId),
          MINIMAL_HEADERS_PAYLOAD,
        ]));
        streamId += 2;
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(frames), label: '[FUZZ] 110× HEADERS (exceeds SETTINGS_MAX_CONCURRENT_STREAMS=100)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must enforce SETTINGS_MAX_CONCURRENT_STREAMS and send RST_STREAM or GOAWAY',
  },

  {
    name: 'h2-erratic-window-update',
    category: 'AC',
    description: 'Erratic WINDOW_UPDATE frames — zero increment, update on closed stream, max increment',
    side: 'client',
    actions: () => {
      const streamId = 1;
      const openStream = Buffer.concat([
        createFrameHeader(MINIMAL_HEADERS_PAYLOAD.length, FrameType.HEADERS, Flag.END_HEADERS, streamId),
        MINIMAL_HEADERS_PAYLOAD,
      ]);
      const wuZeroPayload = Buffer.alloc(4);
      wuZeroPayload.writeUInt32BE(0, 0);
      const wuZero = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, streamId), wuZeroPayload]);
      const rstPayload = Buffer.alloc(4);
      rstPayload.writeUInt32BE(0x08, 0);
      const rst = Buffer.concat([createFrameHeader(4, FrameType.RST_STREAM, 0, streamId), rstPayload]);
      const wuClosedPayload = Buffer.alloc(4);
      wuClosedPayload.writeUInt32BE(100, 0);
      const wuClosed = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, streamId), wuClosedPayload]);
      const wuMaxPayload = Buffer.alloc(4);
      wuMaxPayload.writeUInt32BE(0x7FFFFFFF, 0);
      const wuMax = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, 0), wuMaxPayload]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: openStream, label: 'HEADERS (open stream 1)' },
        { type: 'send', data: wuZero, label: '[FUZZ] WINDOW_UPDATE increment=0 (stream error per RFC §6.9.1)' },
        { type: 'send', data: rst, label: 'RST_STREAM (close stream 1)' },
        { type: 'send', data: wuClosed, label: '[FUZZ] WINDOW_UPDATE on closed stream (violation)' },
        { type: 'send', data: wuMax, label: '[FUZZ] Connection WINDOW_UPDATE increment=0x7FFFFFFF (max)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must reject zero-increment WINDOW_UPDATE and updates on closed streams',
  },

  {
    name: 'h2-flow-control-violation',
    category: 'AC',
    description: 'Flow Control Violation — sends DATA exceeding initial connection flow control window (65535 bytes)',
    side: 'client',
    actions: () => {
      const streamId = 1;
      const initialWindowSize = 65535;
      const openStream = Buffer.concat([
        createFrameHeader(MINIMAL_HEADERS_PAYLOAD.length, FrameType.HEADERS, Flag.END_HEADERS, streamId),
        MINIMAL_HEADERS_PAYLOAD,
      ]);
      const windowFillData = Buffer.alloc(initialWindowSize);
      const windowFillFrame = Buffer.concat([
        createFrameHeader(initialWindowSize, FrameType.DATA, 0, streamId),
        windowFillData,
      ]);
      const extraData = Buffer.from('[FUZZ] beyond-window-data');
      const extraDataFrame = Buffer.concat([
        createFrameHeader(extraData.length, FrameType.DATA, 0, streamId),
        extraData,
      ]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: openStream, label: 'HEADERS (open stream 1)' },
        { type: 'send', data: windowFillFrame, label: `DATA filling initial window (${initialWindowSize} bytes)` },
        { type: 'send', data: extraDataFrame, label: '[FUZZ] DATA exceeding flow control window (FLOW_CONTROL_ERROR)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must send FLOW_CONTROL_ERROR (code 3) when flow control window is exceeded',
  },

  {
    name: 'h2-priority-circular-dependency',
    category: 'AC',
    description: 'PRIORITY frame with circular self-dependency — stream depends on itself (RFC 7540 §5.3.1)',
    side: 'client',
    actions: () => {
      const streamId = 1;
      const openStream = Buffer.concat([
        createFrameHeader(MINIMAL_HEADERS_PAYLOAD.length, FrameType.HEADERS, Flag.END_HEADERS, streamId),
        MINIMAL_HEADERS_PAYLOAD,
      ]);
      const priorityPayload = Buffer.alloc(5);
      priorityPayload.writeUInt32BE(streamId | 0x80000000, 0);
      priorityPayload.writeUInt8(200, 4);
      const priorityFrame = Buffer.concat([
        createFrameHeader(5, FrameType.PRIORITY, 0, streamId),
        priorityPayload,
      ]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: openStream, label: 'HEADERS (open stream 1)' },
        { type: 'send', data: priorityFrame, label: '[FUZZ] PRIORITY with circular self-dependency (stream 1 → stream 1)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must send RST_STREAM PROTOCOL_ERROR for self-dependent PRIORITY (RFC §5.3.1)',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AD: Frame Structure & Header Attacks
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-protocol-violation',
    category: 'AD',
    description: 'Protocol Violations — SETTINGS on non-zero stream, HEADERS on stream 0, stray CONTINUATION, undefined frame type, DATA on idle stream',
    side: 'client',
    actions: () => {
      const settingsNonZeroStream = createFrameHeader(0, FrameType.SETTINGS, 0, 1);
      const headersStream0 = createFrameHeader(0, FrameType.HEADERS, Flag.END_HEADERS, 0);
      const contPayload = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      const strayContination = Buffer.concat([
        createFrameHeader(contPayload.length, FrameType.CONTINUATION, Flag.END_HEADERS, 3),
        contPayload,
      ]);
      const undefinedTypeFrame = createFrameHeader(0, 0xFF, 0, 3);
      const idleData = Buffer.from('idle-stream-data');
      const dataIdleStream = Buffer.concat([
        createFrameHeader(idleData.length, FrameType.DATA, 0, 5),
        idleData,
      ]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: settingsNonZeroStream, label: '[FUZZ] SETTINGS on stream 1 (must be stream 0)' },
        { type: 'send', data: headersStream0, label: '[FUZZ] HEADERS on stream 0 (must be non-zero)' },
        { type: 'send', data: strayContination, label: '[FUZZ] CONTINUATION without preceding HEADERS' },
        { type: 'send', data: undefinedTypeFrame, label: '[FUZZ] Frame with undefined type 0xFF' },
        { type: 'send', data: dataIdleStream, label: '[FUZZ] DATA on idle stream 5 (no prior HEADERS)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must send GOAWAY/connection error for each of these protocol violations',
  },

  {
    name: 'h2-hpack-bomb',
    category: 'AD',
    description: 'HPACK Bomb — 100 unique headers exhausting the HPACK dynamic table',
    side: 'client',
    actions: () => {
      const streamId = 1;
      const parts = [];
      for (let i = 0; i < 100; i++) {
        const name = `x-fuzz-header-${i}`;
        const value = `value-${i}-${'X'.repeat(50)}`;
        const nb = Buffer.alloc(2); nb.writeUInt16BE(name.length, 0);
        const vb = Buffer.alloc(2); vb.writeUInt16BE(value.length, 0);
        parts.push(Buffer.from([0x00]));
        parts.push(nb, Buffer.from(name), vb, Buffer.from(value));
      }
      const headersPayload = Buffer.concat(parts);
      const headersFrame = Buffer.concat([
        createFrameHeader(headersPayload.length, FrameType.HEADERS, Flag.END_HEADERS, streamId),
        headersPayload,
      ]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: headersFrame, label: '[FUZZ] HEADERS with 100 unique entries (HPACK table exhaustion)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should impose limits on HPACK dynamic table size or header count',
  },

  {
    name: 'h2-invalid-header',
    category: 'AD',
    description: 'Invalid Header Fields — pseudo-header after regular header, invalid characters, oversized name',
    side: 'client',
    actions: () => {
      let streamId = 1;
      function headerEntry(name, value) {
        const nb = Buffer.alloc(2); nb.writeUInt16BE(name.length, 0);
        const vb = Buffer.alloc(2); vb.writeUInt16BE(value.length, 0);
        return Buffer.concat([Buffer.from([0x00]), nb, Buffer.from(name), vb, Buffer.from(value)]);
      }
      const p1 = Buffer.concat([headerEntry('x-regular', 'value'), headerEntry(':path', '/')]);
      const hf1 = Buffer.concat([createFrameHeader(p1.length, FrameType.HEADERS, Flag.END_HEADERS, streamId), p1]);
      streamId += 2;
      const p2 = headerEntry('x-header@invalid', 'value');
      const hf2 = Buffer.concat([createFrameHeader(p2.length, FrameType.HEADERS, Flag.END_HEADERS, streamId), p2]);
      streamId += 2;
      const longName = 'x-'.repeat(1000);
      const p3 = headerEntry(longName, 'value');
      const hf3 = Buffer.concat([createFrameHeader(p3.length, FrameType.HEADERS, Flag.END_HEADERS, streamId), p3]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: hf1, label: '[FUZZ] HEADERS with pseudo-header after regular header (ordering violation)' },
        { type: 'send', data: hf2, label: '[FUZZ] HEADERS with @ in header name (invalid token character)' },
        { type: 'send', data: hf3, label: '[FUZZ] HEADERS with 2000-char header name (parser stress)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must reject pseudo-header ordering violations and invalid header field names',
  },

  {
    name: 'h2-invalid-frame-size',
    category: 'AD',
    description: 'Invalid Frame Size — SETTINGS with under-reported length, PING claiming wrong payload size',
    side: 'client',
    actions: () => {
      const settingsPayload = Buffer.alloc(6);
      settingsPayload.writeUInt16BE(0x3, 0);
      settingsPayload.writeUInt32BE(100, 2);
      const settingsSmall = Buffer.concat([
        createFrameHeader(settingsPayload.length - 1, FrameType.SETTINGS, 0, 0),
        settingsPayload,
      ]);
      const pingPayload = Buffer.alloc(8);
      const pingBad = Buffer.concat([
        createFrameHeader(9, FrameType.PING, 0, 0),
        pingPayload,
      ]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: settingsSmall, label: '[FUZZ] SETTINGS with under-reported length (claims 5, payload is 6)' },
        { type: 'send', data: pingBad, label: '[FUZZ] PING claiming 9-byte payload (must be exactly 8)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must send FRAME_SIZE_ERROR for frames with incorrect payload sizes',
  },

  {
    name: 'h2-padding-fuzz',
    category: 'AD',
    description: 'Padding Abuse — HEADERS with PADDED flag where declared length exceeds actual payload',
    side: 'client',
    actions: () => {
      const streamId = 1;
      const padLen = 10;
      const frameBody = Buffer.concat([
        Buffer.from([padLen]),
        Buffer.alloc(0),
        Buffer.alloc(padLen),
      ]);
      const invalidFrame = Buffer.concat([
        createFrameHeader(frameBody.length + 1, FrameType.HEADERS, Flag.END_HEADERS | Flag.PADDED, streamId),
        frameBody,
      ]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: invalidFrame, label: '[FUZZ] HEADERS PADDED with over-reported length (+1 byte, triggers PROTOCOL_ERROR)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must send PROTOCOL_ERROR when padded frame length field is inconsistent',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AE: Stream Abuse Extensions (from http2-fuzzer)
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-reset-flood-cve-9514',
    category: 'AE',
    description: 'Reset Flood (CVE-2019-9514) — DATA after END_STREAM on 50 streams to provoke RST_STREAM cascade',
    side: 'client',
    actions: () => {
      const frames = [];
      for (let i = 0; i < 50; i++) {
        const streamId = 1 + (i * 2);
        const headersFrame = Buffer.concat([
          createFrameHeader(HPACK_MINIMAL.length, FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, streamId),
          HPACK_MINIMAL,
        ]);
        const extraData = Buffer.from('data-after-end-stream');
        const dataFrame = Buffer.concat([
          createFrameHeader(extraData.length, FrameType.DATA, 0, streamId),
          extraData,
        ]);
        frames.push(headersFrame, dataFrame);
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(frames), label: '[FUZZ] 50× HEADERS(END_STREAM) + DATA on closed stream (CVE-2019-9514)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should RST_STREAM or GOAWAY for DATA sent after END_STREAM (CVE-2019-9514)',
  },

  {
    name: 'h2-dependency-cycle',
    category: 'AE',
    description: 'Stream Dependency Cycle — self-referencing PRIORITY on 10 streams and an A↔B cross-cycle',
    side: 'client',
    actions: () => {
      const headerFrames = [];
      const priorityFrames = [];

      // Open 10 streams
      for (let i = 0; i < 10; i++) {
        const streamId = 1 + i * 2;
        headerFrames.push(Buffer.concat([
          createFrameHeader(HPACK_MINIMAL.length, FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, streamId),
          HPACK_MINIMAL,
        ]));
      }

      // Self-dependency PRIORITY for each stream
      for (let i = 0; i < 10; i++) {
        const streamId = 1 + i * 2;
        const payload = Buffer.alloc(5);
        payload.writeUInt32BE(streamId, 0); // depend on self
        payload.writeUInt8(15, 4);
        priorityFrames.push(Buffer.concat([createFrameHeader(5, FrameType.PRIORITY, 0, streamId), payload]));
      }

      // Cross-cycle: stream 1 depends on 3, stream 3 depends on 1
      const payloadAB = Buffer.alloc(5);
      payloadAB.writeUInt32BE(3, 0);
      payloadAB.writeUInt8(15, 4);
      priorityFrames.push(Buffer.concat([createFrameHeader(5, FrameType.PRIORITY, 0, 1), payloadAB]));

      const payloadBA = Buffer.alloc(5);
      payloadBA.writeUInt32BE(1, 0);
      payloadBA.writeUInt8(15, 4);
      priorityFrames.push(Buffer.concat([createFrameHeader(5, FrameType.PRIORITY, 0, 3), payloadBA]));

      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(headerFrames), label: 'HEADERS on 10 streams' },
        { type: 'send', data: Buffer.concat(priorityFrames), label: '[FUZZ] PRIORITY self-deps (10 streams) + A↔B cross-cycle' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should detect circular PRIORITY dependencies and send PROTOCOL_ERROR',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AF: Extended Frame Attacks (from http2-fuzzer)
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-malformed-settings-frame',
    category: 'AF',
    description: 'Malformed SETTINGS — SETTINGS frame with invalid identifier 0xFFFF',
    side: 'client',
    actions: () => {
      const settingsPayload = Buffer.alloc(6);
      settingsPayload.writeUInt16BE(0xFFFF, 0); // invalid identifier (max valid is 0x6)
      settingsPayload.writeUInt32BE(100, 2);
      const malformedSettings = Buffer.concat([
        createFrameHeader(6, FrameType.SETTINGS, 0, 0),
        settingsPayload,
      ]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: malformedSettings, label: '[FUZZ] SETTINGS with invalid identifier 0xFFFF' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should ignore unknown SETTINGS identifiers per RFC 7540 §6.5.2 (MUST ignore)',
  },

  {
    name: 'h2-large-headers-frame',
    category: 'AF',
    description: 'Large HEADERS Frame — ~200KB of header data (200 headers × 1KB each)',
    side: 'client',
    actions: () => {
      const parts = [];
      // Indexed pseudo-headers: :method GET (0x82), :path / (0x84), :scheme https (0x87)
      parts.push(Buffer.from([0x82, 0x84, 0x87]));
      for (let i = 0; i < 200; i++) {
        const name = `header-${i}`;
        const value = 'a'.repeat(1024);
        const nb = Buffer.alloc(2); nb.writeUInt16BE(name.length, 0);
        const vb = Buffer.alloc(2); vb.writeUInt16BE(value.length, 0);
        parts.push(Buffer.from([0x00]), nb, Buffer.from(name), vb, Buffer.from(value));
      }
      const headersPayload = Buffer.concat(parts);
      const headersFrame = Buffer.concat([
        createFrameHeader(headersPayload.length, FrameType.HEADERS, Flag.END_HEADERS, 1),
        headersPayload,
      ]);
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: headersFrame, label: `[FUZZ] HEADERS with ~${Math.round(headersPayload.length / 1024)}KB payload (200 headers × 1KB)` },
        { type: 'recv', timeout: 8000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should enforce SETTINGS_MAX_HEADER_LIST_SIZE and reject oversized HEADERS',
  },

  {
    name: 'h2-zero-length-headers-cve-9516',
    category: 'AF',
    description: 'Zero-Length Headers (CVE-2019-9516) — HEADERS with empty names and empty values',
    side: 'client',
    actions: () => {
      // HPACK: indexed :method GET(0x82), :path /(0x84), :scheme https(0x87)
      // followed by literal headers with zero-length name and value
      const headerBlock = Buffer.from([
        0x82, 0x84, 0x87,
        0x41, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, // :authority localhost
        0x00, 0x00, 0x00, // literal header: zero-length name, zero-length value
        0x00, 0x00, 0x00, // another zero-length pair
      ]);
      const frames = [];
      for (let i = 0; i < 50; i++) {
        const streamId = 1 + i * 2;
        frames.push(Buffer.concat([
          createFrameHeader(headerBlock.length, FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, streamId),
          headerBlock,
        ]));
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(frames), label: '[FUZZ] 50× HEADERS with zero-length names/values (CVE-2019-9516)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must reject zero-length header names per RFC 7540 §8.1.2.6 (CVE-2019-9516)',
  },

  {
    name: 'h2-continuation-flood-1000',
    category: 'AF',
    description: 'Aggressive CONTINUATION Flood (CVE-2024-27316) — HEADERS without END_HEADERS + 1000 CONTINUATION frames',
    side: 'client',
    actions: () => {
      const streamId = 1;
      const hpackMinimal = Buffer.from([0x82, 0x84, 0x87]);
      const initialHeaders = Buffer.concat([
        createFrameHeader(hpackMinimal.length, FrameType.HEADERS, 0, streamId),
        hpackMinimal,
      ]);
      const contPayload = Buffer.from([
        0x40, 0x05, 0x78, 0x2d, 0x70, 0x61, 0x64, // name: "x-pad"
        0x03, 0x41, 0x41, 0x41,                    // value: "AAA"
      ]);
      const contFrames = [];
      for (let i = 0; i < 1000; i++) {
        const flags = (i === 999) ? Flag.END_HEADERS : 0;
        contFrames.push(Buffer.concat([
          createFrameHeader(contPayload.length, FrameType.CONTINUATION, flags, streamId),
          contPayload,
        ]));
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: initialHeaders, label: '[FUZZ] HEADERS without END_HEADERS (locks server into CONTINUATION state)' },
        { type: 'send', data: Buffer.concat(contFrames), label: '[FUZZ] 1000× CONTINUATION frames (CVE-2024-27316 — memory exhaustion)' },
        { type: 'recv', timeout: 8000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must limit CONTINUATION buffering to prevent memory exhaustion (CVE-2024-27316)',
  },

  {
    name: 'h2-invalid-frame-types',
    category: 'AF',
    description: 'Unknown Frame Types — frames with type codes 0x0A, 0x0B, 0x0F, 0x42, 0xFF on streams 0 and 1',
    side: 'client',
    actions: () => {
      const invalidTypes = [0x0A, 0x0B, 0x0F, 0x42, 0xFF];
      const payload = Buffer.from('unknown-frame-payload');
      const frames = [];
      for (const type of invalidTypes) {
        frames.push(Buffer.concat([createFrameHeader(payload.length, type, 0, 0), payload]));
        frames.push(Buffer.concat([createFrameHeader(payload.length, type, 0, 1), payload]));
      }
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(frames), label: '[FUZZ] Unknown frame types 0x0A/0x0B/0x0F/0x42/0xFF on streams 0 and 1' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Per RFC 7540 §4.1, unknown frame types MUST be ignored and connection left open',
  },

  {
    name: 'h2-connection-preface-attack',
    category: 'AF',
    description: 'Malformed Connection Preface — sends a truncated HTTP/2 client preface to test server handshake validation',
    side: 'client',
    actions: () => {
      // Truncated: only 12 of the 24 required bytes
      const truncatedPreface = Buffer.from('PRI * HTTP/2');
      const settingsFrame = createFrameHeader(0, FrameType.SETTINGS, 0, 0);
      return [
        { type: 'send', data: truncatedPreface, label: '[FUZZ] Truncated HTTP/2 connection preface (12/24 bytes)' },
        { type: 'send', data: settingsFrame, label: 'SETTINGS frame after truncated preface' },
        { type: 'recv', timeout: 3000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must reject connections that do not begin with the correct 24-byte preface',
  },

  {
    name: 'h2-goaway-flood',
    category: 'AF',
    description: 'GOAWAY Flood — sends 10 GOAWAY frames with different error codes to test connection shutdown handling',
    side: 'client',
    actions: () => {
      // HTTP/2 error codes: NO_ERROR(0)..ENHANCE_YOUR_CALM(11)
      const errorCodes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 11];
      const debugData = Buffer.from('fuzz-goaway');
      const frames = errorCodes.map(code => createGoAwayFrame(0, code, debugData));
      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat(frames), label: '[FUZZ] 10× GOAWAY with codes: NO_ERROR, PROTOCOL_ERROR, INTERNAL_ERROR ... ENHANCE_YOUR_CALM' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should handle repeated GOAWAY gracefully without crashing',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AG: Flow Control Attacks (from http2-fuzzer)
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-flow-control-manipulation-cve-9517',
    category: 'AG',
    description: 'Flow Control Manipulation (CVE-2019-9517) — maximize connection and stream windows, open 20 streams, never read responses',
    side: 'client',
    actions: () => {
      // Max out the connection-level window (0x7FFFFFFF - 65535 = additional increment)
      const increment = 0x7FFFFFFF - 65535;
      const winPayload = Buffer.alloc(4);
      winPayload.writeUInt32BE(increment, 0);
      const connWindowUpdate = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, 0), winPayload]);

      // Open 20 streams and max their individual windows
      const streamFrames = [];
      for (let i = 0; i < 20; i++) {
        const streamId = 1 + i * 2;
        const headersFrame = Buffer.concat([
          createFrameHeader(HPACK_MINIMAL.length, FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, streamId),
          HPACK_MINIMAL,
        ]);
        const streamWin = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, streamId), winPayload]);
        streamFrames.push(headersFrame, streamWin);
      }

      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: connWindowUpdate, label: '[FUZZ] WINDOW_UPDATE: maximize connection window (CVE-2019-9517)' },
        { type: 'send', data: Buffer.concat(streamFrames), label: '[FUZZ] 20× HEADERS + max WINDOW_UPDATE per stream (force server to buffer responses)' },
        { type: 'recv', timeout: 8000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must not buffer unbounded data when client never reads (CVE-2019-9517)',
  },

  {
    name: 'h2-window-overflow',
    category: 'AG',
    description: 'Window Overflow — two WINDOW_UPDATE increments of 0x7FFFFFFF on connection and stream 1 to exceed 2^31-1',
    side: 'client',
    actions: () => {
      const maxIncrement = 0x7FFFFFFF;
      const payload = Buffer.alloc(4);
      payload.writeUInt32BE(maxIncrement, 0);

      const wu1 = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, 0), payload]);
      const wu2 = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, 0), payload]);

      const openStream = Buffer.concat([
        createFrameHeader(HPACK_MINIMAL.length, FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, 1),
        HPACK_MINIMAL,
      ]);
      const wuStream1 = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, 1), payload]);
      const wuStream2 = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, 1), payload]);

      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: Buffer.concat([wu1, wu2]), label: '[FUZZ] 2× WINDOW_UPDATE 0x7FFFFFFF on connection (overflow > 2^31-1)' },
        { type: 'send', data: openStream, label: 'HEADERS (open stream 1)' },
        { type: 'send', data: Buffer.concat([wuStream1, wuStream2]), label: '[FUZZ] 2× WINDOW_UPDATE 0x7FFFFFFF on stream 1 (overflow)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must send FLOW_CONTROL_ERROR when window size exceeds 2^31-1 (RFC §6.9.1)',
  },

  {
    name: 'h2-zero-window-size-cve-43622',
    category: 'AG',
    description: 'Zero Window Size (CVE-2023-43622) — SETTINGS with INITIAL_WINDOW_SIZE=0, then sends 20 requests server cannot respond to',
    side: 'client',
    actions: () => {
      // SETTINGS_INITIAL_WINDOW_SIZE = 0x4, value = 0
      const settingsPayload = Buffer.alloc(6);
      settingsPayload.writeUInt16BE(0x4, 0); // SETTINGS_INITIAL_WINDOW_SIZE
      settingsPayload.writeUInt32BE(0, 2);   // value = 0
      const zeroWindowSettings = Buffer.concat([
        createFrameHeader(6, FrameType.SETTINGS, 0, 0),
        settingsPayload,
      ]);

      const requestFrames = [];
      for (let i = 0; i < 20; i++) {
        const streamId = 1 + i * 2;
        requestFrames.push(Buffer.concat([
          createFrameHeader(HPACK_MINIMAL.length, FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, streamId),
          HPACK_MINIMAL,
        ]));
      }

      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: zeroWindowSettings, label: '[FUZZ] SETTINGS INITIAL_WINDOW_SIZE=0 (blocks server DATA frames)' },
        { type: 'send', data: Buffer.concat(requestFrames), label: '[FUZZ] 20× GET requests (server must buffer all responses — CVE-2023-43622)' },
        { type: 'recv', timeout: 8000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must enforce response buffering limits when window size is 0 (CVE-2023-43622)',
  },

  {
    name: 'h2-invalid-stream-states',
    category: 'AG',
    description: 'Invalid Stream States — DATA on idle stream, HEADERS on even stream ID, DATA on closed stream, zero-increment WINDOW_UPDATE',
    side: 'client',
    actions: () => {
      // 1. DATA on idle stream 99 (never opened)
      const dataIdle = Buffer.concat([
        createFrameHeader(19, FrameType.DATA, 0, 99),
        Buffer.from('data-on-idle-stream'),
      ]);

      // 2. HEADERS on even stream ID 2 (server-initiated only)
      const headersEven = Buffer.concat([
        createFrameHeader(HPACK_MINIMAL.length, FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, 2),
        HPACK_MINIMAL,
      ]);

      // 3. Open and close stream 1, then send DATA on it
      const openStream1 = Buffer.concat([
        createFrameHeader(HPACK_MINIMAL.length, FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, 1),
        HPACK_MINIMAL,
      ]);
      const dataOnClosed = Buffer.concat([
        createFrameHeader(21, FrameType.DATA, 0, 1),
        Buffer.from('data-on-closed-stream'),
      ]);

      // 4. WINDOW_UPDATE with zero increment (forbidden per RFC §6.9.1)
      const zeroPay = Buffer.alloc(4);
      zeroPay.writeUInt32BE(0, 0);
      const wuZero = Buffer.concat([createFrameHeader(4, FrameType.WINDOW_UPDATE, 0, 0), zeroPay]);

      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: dataIdle, label: '[FUZZ] DATA on idle stream 99 (never opened)' },
        { type: 'send', data: headersEven, label: '[FUZZ] HEADERS on even stream ID 2 (server-initiated only)' },
        { type: 'send', data: openStream1, label: 'HEADERS on stream 1 (open+close with END_STREAM)' },
        { type: 'send', data: dataOnClosed, label: '[FUZZ] DATA on closed stream 1' },
        { type: 'send', data: wuZero, label: '[FUZZ] WINDOW_UPDATE increment=0 on connection (forbidden)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server must send STREAM_CLOSED / PROTOCOL_ERROR for frames on streams in wrong states',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AH: Connectivity & TLS Probes (from http2-fuzzer-ui)
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-ping-tcp',
    category: 'AH',
    description: 'TCP Connectivity Probe — basic TCP connection test to verify host:port is reachable',
    side: 'client',
    isTcpOnly: true,
    actions: () => [{ type: 'probe', label: 'TCP connection test' }],
    expected: 'CONNECTED',
    expectedReason: 'TCP connection should succeed if host is reachable',
  },

  {
    name: 'h2-ping-tls-alpn',
    category: 'AH',
    description: 'TLS + ALPN h2 Connectivity Probe — TLS connection test with ALPN h2 to verify HTTP/2 support',
    side: 'client',
    actions: () => [{ type: 'probe', label: 'TLS+ALPN h2 connection test' }],
    expected: 'CONNECTED',
    expectedReason: 'TLS connection with ALPN h2 should succeed on an HTTP/2 server',
  },

  {
    name: 'h2-alpn-correct',
    category: 'AH',
    description: 'Correct ALPN (h2) — connect with correct h2 ALPN; should succeed',
    side: 'client',
    connectionOptions: { ALPNProtocols: ['h2'] },
    actions: () => [{ type: 'probe', label: 'TLS with ALPN h2 (correct)' }],
    expected: 'CONNECTED',
    expectedReason: 'Server should accept the standard h2 ALPN protocol',
  },

  {
    name: 'h2-alpn-incorrect',
    category: 'AH',
    description: 'Incorrect ALPN (http/1.1) — connect with HTTP/1.1 only ALPN; should fail if server requires h2',
    side: 'client',
    connectionOptions: { ALPNProtocols: ['http/1.1'] },
    actions: () => [{ type: 'probe', label: 'TLS with ALPN http/1.1 (incorrect for H2)' }],
    expected: 'FAILED_CONNECTION',
    expectedReason: 'Server should reject or not negotiate HTTP/2 when ALPN offers only http/1.1',
  },

  {
    name: 'h2-alpn-mixed',
    category: 'AH',
    description: 'Mixed ALPN (h2, http/1.1) — connect with both protocols; should succeed via h2 negotiation',
    side: 'client',
    connectionOptions: { ALPNProtocols: ['h2', 'http/1.1'] },
    actions: () => [{ type: 'probe', label: 'TLS with ALPN [h2, http/1.1] (mixed)' }],
    expected: 'CONNECTED',
    expectedReason: 'Server should select h2 from the offered protocols and accept the connection',
  },

  {
    name: 'h2-alpn-empty',
    category: 'AH',
    description: 'Empty ALPN — connect with an empty ALPN list; should fail for strict HTTP/2 servers',
    side: 'client',
    connectionOptions: { ALPNProtocols: [] },
    actions: () => [{ type: 'probe', label: 'TLS with empty ALPN list' }],
    expected: 'FAILED_CONNECTION',
    expectedReason: 'Server should reject TLS connections with no ALPN when h2 is required',
  },

  {
    name: 'h2-alpn-random',
    category: 'AH',
    description: 'Random/Unknown ALPN — connect with a nonsense ALPN string; should fail',
    side: 'client',
    connectionOptions: { ALPNProtocols: ['fuzz/x-unknown-proto'] },
    actions: () => [{ type: 'probe', label: 'TLS with unknown ALPN "fuzz/x-unknown-proto"' }],
    expected: 'FAILED_CONNECTION',
    expectedReason: 'Server should reject unknown ALPN protocols that are not h2',
  },

  {
    name: 'h2-alpn-missing',
    category: 'AH',
    description: 'Missing ALPN Extension — connect without any ALPN extension; should fail for HTTP/2',
    side: 'client',
    connectionOptions: { ALPNProtocols: undefined },
    actions: () => [{ type: 'probe', label: 'TLS without ALPN extension' }],
    expected: 'FAILED_CONNECTION',
    expectedReason: 'HTTP/2 requires ALPN negotiation per RFC 7540 §3.3; connections without it should fail',
  },

  {
    name: 'h2-tls-v12-only',
    category: 'AH',
    description: 'TLSv1.2 Only — force TLS 1.2; should succeed (HTTP/2 requires TLS 1.2+)',
    side: 'client',
    connectionOptions: { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' },
    actions: () => [{ type: 'probe', label: 'TLS 1.2 forced connection' }],
    expected: 'CONNECTED',
    expectedReason: 'HTTP/2 is defined over TLS 1.2+; a TLS 1.2 connection should be accepted',
  },

  {
    name: 'h2-tls-v13-only',
    category: 'AH',
    description: 'TLSv1.3 Only — force TLS 1.3; should succeed if server supports it',
    side: 'client',
    connectionOptions: { minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' },
    actions: () => [{ type: 'probe', label: 'TLS 1.3 forced connection' }],
    expected: 'CONNECTED',
    expectedReason: 'Modern HTTP/2 servers should support TLS 1.3',
  },

  {
    name: 'h2-tls-v11-only',
    category: 'AH',
    description: 'TLSv1.1 Only — force deprecated TLS 1.1; should fail (HTTP/2 requires 1.2+)',
    side: 'client',
    connectionOptions: { minVersion: 'TLSv1', maxVersion: 'TLSv1.1' },
    actions: () => [{ type: 'probe', label: 'TLS 1.1 forced connection (deprecated)' }],
    expected: 'FAILED_CONNECTION',
    expectedReason: 'HTTP/2 requires TLS 1.2 minimum per RFC 7540 §9.2; TLS 1.1 must be rejected',
  },

  {
    name: 'h2-tls-negotiate',
    category: 'AH',
    description: 'TLS Version Negotiation (1.2→1.3) — allow client and server to negotiate; should succeed',
    side: 'client',
    connectionOptions: { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' },
    actions: () => [{ type: 'probe', label: 'TLS 1.2–1.3 version negotiation' }],
    expected: 'CONNECTED',
    expectedReason: 'Normal TLS negotiation between 1.2 and 1.3 should succeed on any modern server',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AI: General Frame Mutation (from http2-fuzzer-ui)
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-random-frame-mutation',
    category: 'AI',
    description: 'Random Frame Mutation — valid preface then mutated frames: unknown type, over-reported length, all flags set, even stream DATA, random garbage',
    side: 'client',
    actions: () => {
      // Base: DATA frame on stream 1 with 4 bytes payload
      const basePayload = Buffer.from('data');
      const baseFrame = Buffer.concat([createFrameHeader(4, FrameType.DATA, 0, 1), basePayload]);

      // Mutation 1: unknown type (0xFF)
      const m1 = Buffer.from(baseFrame);
      m1[3] = 0xFF;

      // Mutation 2: over-reported length (9999 — parser sees truncated payload)
      const m2 = Buffer.from(baseFrame);
      m2.writeUIntBE(9999, 0, 3);

      // Mutation 3: all flags set (0xFF)
      const m3 = Buffer.from(baseFrame);
      m3[4] = 0xFF;

      // Mutation 4: DATA on even stream ID 2 (server-initiated only)
      const m4 = Buffer.concat([createFrameHeader(4, FrameType.DATA, 0, 2), basePayload]);

      // Mutation 5: random garbage (20 bytes)
      const garbage = Buffer.alloc(20);
      for (let i = 0; i < garbage.length; i++) garbage[i] = (i * 37 + 99) % 256; // deterministic pseudo-random

      // Mutation 6: HEADERS with all-zero payload on stream 0 (protocol error)
      const m6 = Buffer.concat([createFrameHeader(4, FrameType.HEADERS, Flag.END_HEADERS, 0), Buffer.alloc(4)]);

      return [
        { type: 'send', data: prefaceBuffer(), label: 'H2 Connection Preface + SETTINGS' },
        { type: 'send', data: m1, label: '[FUZZ] Mutated frame: type byte → 0xFF (unknown)' },
        { type: 'send', data: m2, label: '[FUZZ] Mutated frame: length field → 9999 (over-reported)' },
        { type: 'send', data: m3, label: '[FUZZ] Mutated frame: flags byte → 0xFF (all flags set)' },
        { type: 'send', data: m4, label: '[FUZZ] DATA on even stream 2 (server-initiated ID)' },
        { type: 'send', data: garbage, label: '[FUZZ] 20 bytes of pseudo-random garbage' },
        { type: 'send', data: m6, label: '[FUZZ] HEADERS on stream 0 with zeroed payload' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should reject or ignore malformed frames without crashing',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AJ: Server-to-Client Attacks (from http2-fuzzer serverStrategies.js)
  // These run in server mode — the fuzzer acts as a malicious HTTP/2 server
  // and sends invalid frames/responses to connecting clients.
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-server-push-flood',
    category: 'AJ',
    description: 'Server Push Flood — server sends 100 PUSH_PROMISE frames for a single client request',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Server Push Flood: Sending 100 PUSH_PROMISE frames...');
      for (let i = 0; i < 100; i++) {
        try {
          stream.pushStream({ ':path': `/push-${i}` }, (err, pushStream) => {
            if (err) return;
            pushStream.respond({ ':status': 200 });
            pushStream.end(`push-data-${i}`);
          });
        } catch (e) {
          log(`Push ${i} failed: ${e.message}`);
          break;
        }
      }
      stream.respond({ ':status': 200 });
      stream.end('response with 100 push promises');
      log('Server Push Flood: 100 PUSH_PROMISE frames sent to client.');
    },
    expected: 'DROPPED',
    expectedReason: 'Client should limit the number of server pushes it accepts and RST_STREAM or GOAWAY',
  },

  {
    name: 'h2-server-malformed-response-headers',
    category: 'AJ',
    description: 'Malformed Response Headers — server sends HEADERS response without required :status pseudo-header',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Malformed Response Headers: Sending response without :status via raw frame...');
      // HPACK: literal header "test: value" — no :status
      const headerBlock = Buffer.from([
        0x40, 0x04, 0x74, 0x65, 0x73, 0x74, // name: "test"
        0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, // value: "value"
      ]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('Malformed Response Headers: Response without :status sent.');
    },
    expected: 'DROPPED',
    expectedReason: 'Client should reject responses missing the :status pseudo-header per RFC 7540 §8.1.2.4',
  },

  {
    name: 'h2-server-oversized-response-headers',
    category: 'AJ',
    description: 'Oversized Response Headers — server sends response with ~200KB of custom headers (200 × 1KB)',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Oversized Response Headers: Sending ~200KB response headers...');
      const responseHeaders = { ':status': 200 };
      for (let i = 0; i < 200; i++) {
        responseHeaders[`x-large-${i}`] = 'B'.repeat(1024);
      }
      try {
        stream.respond(responseHeaders);
        stream.end('oversized-headers-response');
        log('Oversized Response Headers: Sent response with ~200KB of headers.');
      } catch (e) {
        log(`Oversized Response Headers: Error: ${e.message}`);
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Client should enforce SETTINGS_MAX_HEADER_LIST_SIZE and reject oversized responses',
  },

  {
    name: 'h2-server-invalid-status-code',
    category: 'AJ',
    description: 'Invalid Status Code — server sends :status 999 via raw HPACK to test client parsing',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Invalid Status Code: Sending :status 999 via raw frame...');
      // HPACK: 0x48 = :status (indexed name, index 8) + literal value "999"
      const headerBlock = Buffer.from([0x48, 0x03, 0x39, 0x39, 0x39]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('Invalid Status Code: :status 999 sent to client.');
    },
    expected: 'DROPPED',
    expectedReason: 'Client should reject non-standard :status codes and reset the stream',
  },

  {
    name: 'h2-server-goaway-abuse',
    category: 'AJ',
    description: 'Server GOAWAY Abuse — sends GOAWAY with misleading last-stream-id values (0 and 0x7FFFFFFF)',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Server GOAWAY Abuse: Sending GOAWAY with misleading IDs...');
      stream.respond({ ':status': 200 });
      stream.end('goaway-abuse-response');
      try {
        session.goaway(0, 0, Buffer.from('misleading-zero'));
        log('Server GOAWAY Abuse: Sent GOAWAY with last-stream-id 0.');
      } catch (e) {
        log(`GOAWAY first error: ${e.message}`);
      }
      setTimeout(() => {
        try {
          session.goaway(0, 0x7FFFFFFF, Buffer.from('misleading-max'));
          log('Server GOAWAY Abuse: Sent GOAWAY with last-stream-id 0x7FFFFFFF.');
        } catch (e) {
          log(`GOAWAY second error: ${e.message}`);
        }
      }, 500);
    },
    expected: 'DROPPED',
    expectedReason: 'Client should handle misleading GOAWAY last-stream-id values gracefully',
  },

  {
    name: 'h2-server-settings-manipulation',
    category: 'AJ',
    description: 'Server Settings Manipulation — sends extreme SETTINGS: maxConcurrentStreams=0, window limits, disabled HPACK',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Server Settings Manipulation: Sending extreme SETTINGS values...');
      const settingsVariants = [
        { maxConcurrentStreams: 0 },
        { maxFrameSize: 16384 },
        { maxFrameSize: 16777215 },
        { headerTableSize: 0 },
        { initialWindowSize: 0 },
        { initialWindowSize: 2147483647 },
      ];
      for (const settings of settingsVariants) {
        try {
          session.settings(settings, () => {});
          log(`Settings sent: ${JSON.stringify(settings)}`);
        } catch (e) {
          log(`Settings error: ${e.message}`);
        }
      }
      stream.respond({ ':status': 200 });
      stream.end('settings-manipulation-response');
    },
    expected: 'DROPPED',
    expectedReason: 'Client should handle extreme SETTINGS values without crash or undefined behavior',
  },

  {
    name: 'h2-server-rst-stream-flood',
    category: 'AJ',
    description: 'Server RST_STREAM Flood — server immediately RST_STREAMs every incoming request with rotating error codes',
    side: 'server',
    serverHandler: (stream, session, log) => {
      const errorCodes = [1, 2, 7, 8, 11]; // PROTOCOL_ERROR, INTERNAL_ERROR, REFUSED_STREAM, CANCEL, ENHANCE_YOUR_CALM
      const code = errorCodes[Math.floor(Math.random() * errorCodes.length)];
      log(`Server RST_STREAM Flood: Closing stream ${stream.id} with error code ${code}...`);
      try {
        stream.close(code);
        log(`Server RST_STREAM Flood: RST_STREAM sent (code=${code}).`);
      } catch (e) {
        log(`RST_STREAM error: ${e.message}`);
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Client should handle RST_STREAM responses without crashing or hanging',
  },

  {
    name: 'h2-server-continuation-flood',
    category: 'AJ',
    description: 'Server CONTINUATION Flood — server sends fragmented response headers via 500 CONTINUATION frames',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Server CONTINUATION Flood: Sending HEADERS + 500 CONTINUATION frames...');
      const streamId = stream.id;
      // HEADERS without END_HEADERS — :status 200 indexed (0x88)
      writeRawFrame(session, buildFrame(FrameType.HEADERS, 0, streamId, Buffer.from([0x88])));
      const contPayload = Buffer.from([
        0x40, 0x06, 0x78, 0x2d, 0x70, 0x61, 0x64, 0x73, // name: "x-pads"
        0x03, 0x42, 0x42, 0x42,                           // value: "BBB"
      ]);
      const count = 500;
      for (let i = 0; i < count; i++) {
        const isLast = (i === count - 1);
        writeRawFrame(session, buildFrame(
          FrameType.CONTINUATION, isLast ? Flag.END_HEADERS : 0, streamId, contPayload
        ));
      }
      writeRawFrame(session, buildFrame(
        FrameType.DATA, Flag.END_STREAM, streamId, Buffer.from('continuation-flood-response')
      ));
      log(`Server CONTINUATION Flood: Sent HEADERS + ${count} CONTINUATION frames.`);
    },
    expected: 'DROPPED',
    expectedReason: 'Client must limit CONTINUATION buffering to prevent memory exhaustion',
  },

  {
    name: 'h2-server-data-after-end-stream',
    category: 'AJ',
    description: 'Data After END_STREAM — server sends DATA frames after already ending the stream',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Data After END_STREAM: Sending extra DATA after END_STREAM...');
      const streamId = stream.id;
      stream.respond({ ':status': 200 });
      stream.end('normal-response');
      setTimeout(() => {
        for (let i = 0; i < 10; i++) {
          writeRawFrame(session, buildFrame(
            FrameType.DATA, 0, streamId, Buffer.from(`extra-data-after-end-${i}`)
          ));
        }
        log('Data After END_STREAM: Sent 10 DATA frames after END_STREAM.');
      }, 200);
    },
    expected: 'DROPPED',
    expectedReason: 'Client must send RST_STREAM for DATA received after END_STREAM on a closed stream',
  },

  {
    name: 'h2-server-window-manipulation',
    category: 'AJ',
    description: 'Server Window Manipulation — server sends zero-increment and overflow WINDOW_UPDATE frames',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Server Window Manipulation: Sending invalid WINDOW_UPDATEs...');
      const zeroPay = Buffer.alloc(4);
      zeroPay.writeUInt32BE(0, 0);
      writeRawFrame(session, buildFrame(FrameType.WINDOW_UPDATE, 0, 0, zeroPay));
      log('Sent WINDOW_UPDATE increment=0 on connection.');

      const maxPay = Buffer.alloc(4);
      maxPay.writeUInt32BE(0x7FFFFFFF, 0);
      writeRawFrame(session, buildFrame(FrameType.WINDOW_UPDATE, 0, 0, maxPay));
      writeRawFrame(session, buildFrame(FrameType.WINDOW_UPDATE, 0, 0, maxPay));
      log('Sent two max WINDOW_UPDATEs on connection (overflow).');

      writeRawFrame(session, buildFrame(FrameType.WINDOW_UPDATE, 0, stream.id, zeroPay));
      log(`Sent zero-increment WINDOW_UPDATE on stream ${stream.id}.`);

      stream.respond({ ':status': 200 });
      stream.end('window-manipulation-response');
    },
    expected: 'DROPPED',
    expectedReason: 'Client must send FLOW_CONTROL_ERROR for zero or overflowing WINDOW_UPDATE increments',
  },


  // ═══════════════════════════════════════════════════════════════════
  // Category AK: Server Protocol Violations (RFC 7540 §§4.1, 5.1, 6.x)
  // The fuzzer acts as a malicious server and sends frames that violate
  // the HTTP/2 stream-state machine and frame-level protocol rules.
  // Compliant clients MUST send GOAWAY / RST_STREAM in response.
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-server-settings-nonzero-stream',
    category: 'AK',
    description: 'SETTINGS on Non-Zero Stream — server sends SETTINGS on stream 1; RFC §6.5 requires stream 0',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending SETTINGS on stream 1 (must be stream 0)...');
      const payload = Buffer.alloc(6);
      payload.writeUInt16BE(0x3, 0); // SETTINGS_MAX_CONCURRENT_STREAMS
      payload.writeUInt32BE(10, 2);
      writeRawFrame(session, buildFrame(FrameType.SETTINGS, 0, stream.id, payload));
      log('SETTINGS on stream 1 sent — client must respond with GOAWAY PROTOCOL_ERROR.');
      try { stream.respond({ ':status': 200 }); stream.end('ak-settings-nonzero-stream'); } catch (_) {}
    },
    expected: 'DROPPED',
    expectedReason: 'Client must send GOAWAY PROTOCOL_ERROR for SETTINGS on non-zero stream (RFC §6.5)',
  },

  {
    name: 'h2-server-rst-stream-zero',
    category: 'AK',
    description: 'RST_STREAM on Stream 0 — server sends RST_STREAM on connection stream; RFC §6.4 requires stream ID > 0',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending RST_STREAM on stream 0 (connection stream, forbidden)...');
      const payload = Buffer.alloc(4);
      payload.writeUInt32BE(0x2, 0); // INTERNAL_ERROR
      writeRawFrame(session, buildFrame(FrameType.RST_STREAM, 0, 0, payload));
      log('RST_STREAM on stream 0 sent — client must respond with GOAWAY PROTOCOL_ERROR.');
      try { stream.respond({ ':status': 200 }); stream.end('ak-rst-stream-zero'); } catch (_) {}
    },
    expected: 'DROPPED',
    expectedReason: 'Client must send GOAWAY PROTOCOL_ERROR for RST_STREAM on stream 0 (RFC §6.4)',
  },

  {
    name: 'h2-server-data-stream-zero',
    category: 'AK',
    description: 'DATA on Stream 0 — server sends DATA frame on connection stream; only HEADERS/SETTINGS/etc. allowed on stream 0',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending DATA on stream 0 (connection stream, forbidden)...');
      writeRawFrame(session, buildFrame(FrameType.DATA, 0, 0, Buffer.from('data-on-stream-zero')));
      log('DATA on stream 0 sent — client must respond with GOAWAY PROTOCOL_ERROR.');
      try { stream.respond({ ':status': 200 }); stream.end('ak-data-stream-zero'); } catch (_) {}
    },
    expected: 'DROPPED',
    expectedReason: 'Client must send GOAWAY PROTOCOL_ERROR for DATA received on stream 0 (RFC §6.1)',
  },

  {
    name: 'h2-server-headers-stream-zero',
    category: 'AK',
    description: 'HEADERS on Stream 0 — server sends HEADERS on connection stream; only valid on non-zero streams',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending HEADERS on stream 0 (connection stream, forbidden)...');
      // :status 200 indexed (0x88)
      writeRawFrame(session, buildFrame(FrameType.HEADERS, Flag.END_HEADERS, 0, Buffer.from([0x88])));
      log('HEADERS on stream 0 sent — client must respond with GOAWAY PROTOCOL_ERROR.');
      try { stream.respond({ ':status': 200 }); stream.end('ak-headers-stream-zero'); } catch (_) {}
    },
    expected: 'DROPPED',
    expectedReason: 'Client must send GOAWAY PROTOCOL_ERROR for HEADERS on stream 0 (RFC §6.2)',
  },

  {
    name: 'h2-server-ping-nonzero-stream',
    category: 'AK',
    description: 'PING on Non-Zero Stream — server sends PING on stream 1; RFC §6.7 requires stream 0',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending PING on stream 1 (must be stream 0)...');
      writeRawFrame(session, buildFrame(FrameType.PING, 0, stream.id, Buffer.alloc(8)));
      log('PING on stream 1 sent — client must respond with GOAWAY PROTOCOL_ERROR.');
      try { stream.respond({ ':status': 200 }); stream.end('ak-ping-nonzero-stream'); } catch (_) {}
    },
    expected: 'DROPPED',
    expectedReason: 'Client must send GOAWAY PROTOCOL_ERROR for PING received on non-zero stream (RFC §6.7)',
  },

  {
    name: 'h2-server-goaway-nonzero-stream',
    category: 'AK',
    description: 'GOAWAY on Non-Zero Stream — server sends GOAWAY on stream 1; RFC §6.8 requires stream 0',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending GOAWAY on stream 1 (must be stream 0)...');
      const payload = Buffer.alloc(8);
      payload.writeUInt32BE(0, 0); // Last-Stream-ID = 0
      payload.writeUInt32BE(0, 4); // Error code = NO_ERROR
      writeRawFrame(session, buildFrame(FrameType.GOAWAY, 0, stream.id, payload));
      log('GOAWAY on stream 1 sent — client must respond with GOAWAY PROTOCOL_ERROR.');
      try { stream.respond({ ':status': 200 }); stream.end('ak-goaway-nonzero-stream'); } catch (_) {}
    },
    expected: 'DROPPED',
    expectedReason: 'Client must send GOAWAY PROTOCOL_ERROR for GOAWAY on non-zero stream (RFC §6.8)',
  },

  {
    name: 'h2-server-push-promise-odd-stream',
    category: 'AK',
    description: 'PUSH_PROMISE with Odd Promised Stream ID — server promises stream 1 (odd); RFC §6.6 requires even server-initiated IDs',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending PUSH_PROMISE with odd promised stream ID (1)...');
      // PUSH_PROMISE payload: 4-byte promised stream ID + HPACK request headers
      const promisedId = Buffer.alloc(4);
      promisedId.writeUInt32BE(1, 0); // odd stream ID — invalid for server-initiated stream
      const hpackRequest = Buffer.from([0x82, 0x84, 0x87, 0x41, 0x09,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74]); // GET / https localhost
      const ppPayload = Buffer.concat([promisedId, hpackRequest]);
      writeRawFrame(session, buildFrame(FrameType.PUSH_PROMISE, Flag.END_HEADERS, stream.id, ppPayload));
      log('PUSH_PROMISE (promised stream 1) sent — client must reject with PROTOCOL_ERROR.');
      try { stream.respond({ ':status': 200 }); stream.end('ak-push-promise-odd-stream'); } catch (_) {}
    },
    expected: 'DROPPED',
    expectedReason: 'Client must reject PUSH_PROMISE with odd promised stream ID (RFC §6.6 — server streams must be even)',
  },

  {
    name: 'h2-server-continuation-no-headers',
    category: 'AK',
    description: 'Stray CONTINUATION — server sends CONTINUATION without a preceding HEADERS without END_HEADERS (RFC §6.10)',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending CONTINUATION without preceding incomplete HEADERS...');
      const contPayload = Buffer.concat([
        hpackLiteral('x-stray', 'continuation'), // dummy HPACK literal
      ]);
      // CONTINUATION on stream.id without any open header block — PROTOCOL_ERROR
      writeRawFrame(session, buildFrame(FrameType.CONTINUATION, Flag.END_HEADERS, stream.id, contPayload));
      log('Stray CONTINUATION sent — client must send GOAWAY PROTOCOL_ERROR.');
      try { stream.respond({ ':status': 200 }); stream.end('ak-continuation-no-headers'); } catch (_) {}
    },
    expected: 'DROPPED',
    expectedReason: 'Client must treat unexpected CONTINUATION as PROTOCOL_ERROR (RFC §6.10)',
  },

  {
    name: 'h2-server-unknown-frames',
    category: 'AK',
    description: 'Unknown Frame Types from Server — sends frames with undefined types (0x0B, 0x42, 0xFF); RFC §4.1 requires clients to ignore them',
    side: 'server',
    serverHandler: (stream, session, log) => {
      const unknownTypes = [0x0B, 0x42, 0xFF];
      const payload = Buffer.from('unknown-server-frame-payload');
      for (const type of unknownTypes) {
        writeRawFrame(session, buildFrame(type, 0, 0, payload));          // on stream 0
        writeRawFrame(session, buildFrame(type, 0, stream.id, payload)); // on client stream
      }
      log(`Sent ${unknownTypes.length * 2} unknown-type frames — client must ignore and stay connected.`);
      try { stream.respond({ ':status': 200 }); stream.end('ak-unknown-frames'); } catch (_) {}
    },
    expected: 'PASSED',
    expectedReason: 'RFC §4.1 — unknown frame types MUST be ignored; client must keep the connection open',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category AL: Server Response Header Violations (RFC 7540 §8.1.2)
  // The fuzzer acts as a malicious server and sends HTTP/2 responses
  // with header fields that violate RFC 7540 §8.1.2 rules.
  // Compliant clients MUST send RST_STREAM (PROTOCOL_ERROR) in response.
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'h2-server-uppercase-header',
    category: 'AL',
    description: 'Uppercase Header Name — server response contains "X-Custom" (uppercase); HTTP/2 requires all header names to be lowercase',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with uppercase header name "X-Custom"...');
      // HPACK: :status 200 (0x88) + literal "X-Custom: fuzz"
      const headerBlock = Buffer.concat([
        Buffer.from([0x88]),              // :status 200 (indexed)
        hpackLiteral('X-Custom', 'fuzz'), // uppercase X — forbidden in HTTP/2
      ]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('Response with uppercase "X-Custom" header sent.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.6 — header names must be lowercase; uppercase names are a PROTOCOL_ERROR',
  },

  {
    name: 'h2-server-connection-header',
    category: 'AL',
    description: 'Connection Header in Response — server sends "Connection: keep-alive"; connection-specific headers are forbidden in HTTP/2',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with forbidden "Connection: keep-alive" header...');
      const headerBlock = Buffer.concat([
        Buffer.from([0x88]),                              // :status 200
        hpackLiteral('connection', 'keep-alive'),         // forbidden connection-specific header
      ]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('"Connection" header sent — client must RST_STREAM PROTOCOL_ERROR.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.2 — Connection header is connection-specific and forbidden in HTTP/2',
  },

  {
    name: 'h2-server-transfer-encoding',
    category: 'AL',
    description: 'Transfer-Encoding in Response — server sends "Transfer-Encoding: chunked"; forbidden in HTTP/2 (§8.1.2.2)',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with "Transfer-Encoding: chunked" (forbidden in HTTP/2)...');
      const headerBlock = Buffer.concat([
        Buffer.from([0x88]),                              // :status 200
        hpackLiteral('transfer-encoding', 'chunked'),    // forbidden in HTTP/2
      ]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('"Transfer-Encoding: chunked" sent — client must RST_STREAM PROTOCOL_ERROR.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.2 — Transfer-Encoding must not be used in HTTP/2; PROTOCOL_ERROR',
  },

  {
    name: 'h2-server-multiple-status',
    category: 'AL',
    description: 'Multiple :status Pseudo-Headers — server sends ":status 200" then ":status 404" in one HEADERS frame',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with two :status pseudo-headers (200 then 404)...');
      // HPACK: 0x88 = :status 200, 0x8C = :status 404 (both indexed)
      const headerBlock = Buffer.from([0x88, 0x8C]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('Two :status headers sent — client must RST_STREAM PROTOCOL_ERROR.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.4 — responses must contain exactly one :status pseudo-header; duplicates are PROTOCOL_ERROR',
  },

  {
    name: 'h2-server-pseudo-after-regular',
    category: 'AL',
    description: 'Pseudo-Header After Regular Header — server sends a regular header before :status in the response',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with :status after regular header (ordering violation)...');
      const headerBlock = Buffer.concat([
        hpackLiteral('x-regular', 'comes-first'), // regular header first — violation
        Buffer.from([0x88]),                       // :status 200 (pseudo) after regular
      ]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log(':status after regular header sent — client must RST_STREAM PROTOCOL_ERROR.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.1 — pseudo-headers must precede all regular header fields; violation is PROTOCOL_ERROR',
  },

  {
    name: 'h2-server-request-pseudoheaders',
    category: 'AL',
    description: 'Request Pseudo-Headers in Response — server sends :method GET and :path / in a response HEADERS frame',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with request-only :method and :path pseudo-headers...');
      // HPACK: :method GET (0x82), :path / (0x84), :status 200 (0x88)
      const headerBlock = Buffer.from([0x82, 0x84, 0x88]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('Request pseudo-headers in response sent — client must RST_STREAM PROTOCOL_ERROR.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.4 — :method, :path, :scheme are request-only; using them in a response is PROTOCOL_ERROR',
  },

  {
    name: 'h2-server-te-non-trailers',
    category: 'AL',
    description: 'TE: chunked in Response — server sends "TE: chunked"; HTTP/2 only allows "TE: trailers" (RFC §8.1.2.2)',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with "TE: chunked" (only TE: trailers is allowed in HTTP/2)...');
      const headerBlock = Buffer.concat([
        Buffer.from([0x88]),            // :status 200
        hpackLiteral('te', 'chunked'),  // TE: chunked — forbidden (only "trailers" allowed)
      ]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('"TE: chunked" sent — client must RST_STREAM PROTOCOL_ERROR.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.2 — TE header must not be present unless value is exactly "trailers"; PROTOCOL_ERROR',
  },

  {
    name: 'h2-server-empty-status',
    category: 'AL',
    description: 'Empty :status Value — server sends :status with an empty string instead of a 3-digit code',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with :status set to empty string...');
      // HPACK: literal with incremental indexing, indexed name :status (idx 8 = 0x48), empty value (0x00)
      const headerBlock = Buffer.from([0x48, 0x00]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log(':status "" sent — client must RST_STREAM PROTOCOL_ERROR.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.4 — :status must contain a valid 3-digit HTTP status code; empty value is PROTOCOL_ERROR',
  },

  {
    name: 'h2-server-keep-alive-header',
    category: 'AL',
    description: 'Keep-Alive Header in Response — server sends "Keep-Alive: timeout=5"; connection-specific header forbidden in HTTP/2',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log('Sending response with "Keep-Alive: timeout=5" (connection-specific, forbidden)...');
      const headerBlock = Buffer.concat([
        Buffer.from([0x88]),                           // :status 200
        hpackLiteral('keep-alive', 'timeout=5'),       // connection-specific — forbidden
      ]);
      writeRawFrame(session, buildFrame(
        FrameType.HEADERS, Flag.END_HEADERS | Flag.END_STREAM, stream.id, headerBlock
      ));
      log('"Keep-Alive" header sent — client must RST_STREAM PROTOCOL_ERROR.');
    },
    expected: 'DROPPED',
    expectedReason: 'RFC §8.1.2.2 — Keep-Alive is a connection-specific header forbidden in HTTP/2; PROTOCOL_ERROR',
  },

];
  return HTTP2_SCENARIOS.find(s => s.name === name);
}

function getHttp2ScenariosByCategory(cat) {
  return HTTP2_SCENARIOS.filter(s => s.category === cat.toUpperCase());
}

function listHttp2Scenarios() {
  const grouped = {};
  for (const s of HTTP2_SCENARIOS) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return { categories: HTTP2_CATEGORIES, scenarios: grouped, all: HTTP2_SCENARIOS };
}

module.exports = {
  HTTP2_SCENARIOS,
  HTTP2_CATEGORIES,
  HTTP2_CATEGORY_SEVERITY,
  HTTP2_CATEGORY_DEFAULT_DISABLED,
  getHttp2Scenario,
  getHttp2ScenariosByCategory,
  listHttp2Scenarios,
};
