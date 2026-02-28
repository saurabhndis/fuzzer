// QUIC fuzzing scenarios
// Ported from: ../quic/fuzzer.js
const crypto = require('crypto');
const PacketBuilder = require('./quic-packet');
const { buildQuicInitialWithCrypto, buildQuicConnectionClose } = require('./quic-packet');

const QUIC_CATEGORIES = {
  QA: 'QUIC Handshake & Connection Initial',
  QB: 'QUIC Transport Parameters & ALPN',
  QC: 'QUIC Resource Exhaustion & DoS',
  QD: 'QUIC Flow Control & Stream Errors',
  QE: 'QUIC Connection Migration & Path',
  QF: 'QUIC Frame Structure & Mutation',
  QG: 'QUIC-TLS Handshake Order & State',
  QH: 'QUIC-TLS Parameter & Extension Fuzzing',
  QI: 'QUIC-TLS Record & Alert Injection',
  QJ: 'QUIC-TLS Known CVEs & PQC',
  QK: 'QUIC-TLS Certificate Fuzzing',
};

const QUIC_CATEGORY_SEVERITY = {
  QA: 'high',
  QB: 'medium',
  QC: 'critical',
  QD: 'medium',
  QE: 'medium',
  QF: 'low',
  QG: 'high',
  QH: 'medium',
  QI: 'high',
  QJ: 'critical',
  QK: 'medium',
};

const QUIC_CATEGORY_DEFAULT_DISABLED = new Set([]);

const builder = new PacketBuilder();

function longHeader(type, version, dcid, scid) {
  builder.reset();
  builder.buildLongHeader(type, version, dcid, scid);
}

const QUIC_SCENARIOS = [
  // ═══════════════════════════════════════════════════════════════════
  // Category QA: Handshake & Connection Initial
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-0-rtt-fuzz',
    category: 'QA',
    description: '0-RTT Early Data packet with random payload to probe server replay handling',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      longHeader(1, 0x00000001, dcid, scid); // 0-RTT
      const payload = crypto.randomBytes(150);
      builder.writeVarInt(payload.length + 2);
      builder.writeUInt16(1);
      builder.writeBytes(payload);
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC 0-RTT Early Data' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should reject unauthenticated 0-RTT data',
  },
  {
    name: 'quic-pqc-keyshare',
    category: 'QA',
    description: 'QUIC Initial with ML-KEM (Kyber-768) sized CRYPTO frame to test PQC handling',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      longHeader(0, 0x00000001, dcid, scid);
      builder.writeVarInt(0); // Token
      builder.writeVarInt(1200);
      builder.writeUInt16(1);
      builder.writeUInt8(0x06); // CRYPTO
      builder.writeVarInt(0); // Offset
      builder.writeVarInt(1184); // ML-KEM-768 public key size
      builder.writeBytes(crypto.randomBytes(1184));
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC PQC ML-KEM keyshare (1184 bytes)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should reject unrecognized PQC key share or malformed ClientHello',
  },
  {
    name: 'quic-packet-coalescing',
    category: 'QA',
    description: 'Two QUIC Initial packets coalesced into a single UDP datagram',
    side: 'client',
    actions: () => {
      const dcid1 = crypto.randomBytes(8);
      const scid1 = crypto.randomBytes(8);
      longHeader(0, 0x00000001, dcid1, scid1);
      builder.writeVarInt(0);
      const p1payload = crypto.randomBytes(100);
      builder.writeVarInt(p1payload.length + 2);
      builder.writeUInt16(1);
      builder.writeBytes(p1payload);
      const pkt1 = Buffer.from(builder.getBuffer());

      const dcid2 = crypto.randomBytes(8);
      const scid2 = crypto.randomBytes(8);
      longHeader(0, 0x00000001, dcid2, scid2);
      builder.writeVarInt(0);
      builder.writeVarInt(1200);
      builder.writeUInt16(0);
      builder.writeBytes(Buffer.alloc(1198, 0));
      const pkt2 = Buffer.from(builder.getBuffer());

      return [
        { type: 'send', data: Buffer.concat([pkt1, pkt2]), label: 'QUIC coalesced packets (Initial+Initial)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should handle or reject coalesced packets with mismatched CIDs',
  },
  {
    name: 'quic-handshake-initial',
    category: 'QA',
    description: 'Basic QUIC Initial packet with random payload',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      longHeader(0, 0x00000001, dcid, scid); // Initial, V1
      builder.writeVarInt(0); // Token length
      const payload = crypto.randomBytes(100);
      builder.writeVarInt(payload.length + 2); // Length (including PN)
      builder.writeUInt16(1); // Packet Number (2 bytes)
      builder.writeBytes(payload);
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC Initial (v1)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should reject random/malformed Initial packet',
  },
  {
    name: 'quic-version-negotiation',
    category: 'QA',
    description: 'QUIC Version Negotiation trigger — sends version 0',
    side: 'client',
    actions: () => {
      builder.reset();
      builder.writeUInt8(0x80); // Fixed bit
      builder.writeUInt32(0); // Version 0 (Version Negotiation)
      const dcid = crypto.randomBytes(8);
      builder.writeUInt8(dcid.length); builder.writeBytes(dcid);
      const scid = crypto.randomBytes(8);
      builder.writeUInt8(scid.length); builder.writeBytes(scid);
      for(let i=0; i<5; i++) builder.writeUInt32(crypto.randomInt(1, 0xffffffff));
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC Version Negotiation (v0)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should respond with supported versions or close',
  },
  {
    name: 'quic-retry-token-fuzz',
    category: 'QA',
    description: 'QUIC Retry packet with random token and tag',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      longHeader(3, 0x00000001, dcid, scid); // Retry
      builder.writeBytes(crypto.randomBytes(50)); // Token
      builder.writeBytes(crypto.randomBytes(16)); // Integrity Tag
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC Retry (fuzzed token)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category QB: Transport Parameters & ALPN
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-transport-params-corrupt',
    category: 'QB',
    description: 'QUIC Handshake packet with corrupted transport parameters',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      longHeader(2, 0x00000001, dcid, scid); // Handshake
      builder.writeVarInt(64); // Length placeholder
      builder.writeUInt16(2); // PN
      builder.writeUInt8(0x06); // CRYPTO frame
      builder.writeVarInt(0); // Offset
      const tp = Buffer.from([0x01, 0x04, 0xff, 0xff, 0xff, 0xff, 0x04, 0x01, 0xff]); // Corrupted TP (invalid length for param 0x04)
      builder.writeVarInt(tp.length);
      builder.writeBytes(tp);
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC Handshake (corrupt TransportParams)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'TRANSPORT_PARAMETER_ERROR expected for malformed parameters',
  },
  {
    name: 'quic-alpn-sni-fuzz',
    category: 'QB',
    description: 'QUIC Initial with oversized ALPN in TLS extensions',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      longHeader(0, 0x00000001, dcid, scid);
      builder.writeVarInt(0); // Token
      builder.writeVarInt(100); // Length
      builder.writeUInt16(1); // PN
      builder.writeBytes(Buffer.alloc(90, 0x41)); // Oversized "ALPN" garbage
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC Initial (oversized ALPN garbage)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category QC: Resource Exhaustion & DoS
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-crypto-buffer-gaps',
    category: 'QC',
    description: 'QUIC CRYPTO frame with huge offset to test buffer gap handling',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      longHeader(0, 0x00000001, dcid, scid);
      builder.writeVarInt(0);
      builder.writeVarInt(100);
      builder.writeUInt16(1);
      builder.writeUInt8(0x06); // CRYPTO
      builder.writeVarInt(1000000); // Huge offset
      builder.writeVarInt(10); // Length
      builder.writeBytes(crypto.randomBytes(10));
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC CRYPTO frame (1MB offset)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
  },
  {
    name: 'quic-dos-amplification-padding',
    category: 'QC',
    description: 'QUIC Initial with excessive padding to test amplification limits',
    side: 'client',
    actions: () => {
      const dcid = crypto.randomBytes(8);
      const scid = crypto.randomBytes(8);
      longHeader(0, 0x00000001, dcid, scid);
      builder.writeVarInt(0);
      builder.writeVarInt(1200); // Max size
      builder.writeUInt16(0); // PN
      builder.writeBytes(Buffer.alloc(1198, 0)); // Pure padding
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC Initial (full padding)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category QD: Flow Control & Stream Errors
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-ack-range-fuzz',
    category: 'QD',
    description: 'QUIC ACK frame with invalid largest acknowledged and multiple blocks',
    side: 'client',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), 12345);
      builder.writeUInt8(0x02); // ACK
      builder.writeVarInt(1000000); // Largest Acknowledged (likely future)
      builder.writeVarInt(0); // Delay
      builder.writeVarInt(20); // 20 ACK blocks
      for(let i=0; i<20; i++) {
        builder.writeVarInt(1); builder.writeVarInt(1);
      }
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC ACK frame (malformed ranges)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
  },
  {
    name: 'quic-stream-overlap',
    category: 'QD',
    description: 'Multiple STREAM frames with overlapping offsets',
    side: 'client',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), 6789);
      for(let i=0; i<3; i++) {
        builder.writeUInt8(0x08); // STREAM
        builder.writeVarInt(1); // Stream ID 1
        builder.writeVarInt(0); // Offset 0 for all (overlap)
        builder.writeBytes(crypto.randomBytes(20));
      }
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC STREAM overlap (3x offset 0)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category QE: Connection Migration & Path
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-path-validation-fuzz',
    category: 'QE',
    description: 'Spamming PATH_CHALLENGE and PATH_RESPONSE frames',
    side: 'client',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), 1111);
      builder.writeUInt8(0x1a); // PATH_CHALLENGE
      builder.writeBytes(crypto.randomBytes(8));
      builder.writeUInt8(0x1b); // PATH_RESPONSE
      builder.writeBytes(crypto.randomBytes(8));
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC PATH_CHALLENGE + PATH_RESPONSE' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category QD (server): Stream Errors & Connection Teardown
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-stream-reset',
    category: 'QD',
    description: 'RESET_STREAM frame with 0xdeadbeef error code targeting a random stream',
    side: 'server',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), crypto.randomInt(1, 100000));
      builder.writeUInt8(0x04); // RESET_STREAM
      builder.writeVarInt(crypto.randomInt(1, 100)); // Stream ID
      builder.writeVarInt(0xdeadbeef); // Error code
      builder.writeVarInt(1000); // Final size
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC RESET_STREAM (0xdeadbeef)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Peer should emit STREAM_STATE_ERROR or silently drop',
  },
  {
    name: 'quic-stop-sending',
    category: 'QD',
    description: 'STOP_SENDING frame with garbage error code to abort stream mid-transfer',
    side: 'server',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), crypto.randomInt(1, 100000));
      builder.writeUInt8(0x05); // STOP_SENDING
      builder.writeVarInt(crypto.randomInt(1, 100)); // Stream ID
      builder.writeVarInt(0xbadc0de); // Application error code
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC STOP_SENDING (0xbadc0de)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Peer should respond with RESET_STREAM or ignore unknown stream',
  },
  {
    name: 'quic-connection-close',
    category: 'QD',
    description: 'CONNECTION_CLOSE with corrupted UTF-8 in reason phrase',
    side: 'server',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), crypto.randomInt(1, 100000));
      builder.writeUInt8(0x1c); // CONNECTION_CLOSE (QUIC layer)
      builder.writeVarInt(0x01); // INTERNAL_ERROR
      builder.writeVarInt(0x00); // Triggering frame type
      const reason = Buffer.from('Corrupted UTF-8: \xff\xfe\xfd');
      builder.writeVarInt(reason.length);
      builder.writeBytes(reason);
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC CONNECTION_CLOSE (invalid UTF-8 reason)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Peer should handle invalid reason phrase without crashing',
  },
  {
    name: 'quic-flow-control',
    category: 'QD',
    description: 'MAX_DATA and MAX_STREAM_DATA frames with zero-window to exhaust flow control',
    side: 'server',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), crypto.randomInt(1, 100000));
      builder.writeUInt8(0x10); // MAX_DATA
      builder.writeVarInt(0); // Zero connection-level window
      builder.writeUInt8(0x11); // MAX_STREAM_DATA
      builder.writeVarInt(1); // Stream ID 1
      builder.writeVarInt(0); // Zero stream-level window
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC MAX_DATA + MAX_STREAM_DATA (zero window)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Peer should detect FLOW_CONTROL_ERROR or stall gracefully',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category QE (server): Connection Migration & Path
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-cid-migration',
    category: 'QE',
    description: 'PATH_CHALLENGE frame to trigger CID migration probing',
    side: 'server',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), crypto.randomInt(1, 100000));
      builder.writeUInt8(0x1a); // PATH_CHALLENGE
      builder.writeBytes(crypto.randomBytes(8)); // 8-byte opaque data
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC PATH_CHALLENGE (CID migration probe)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Peer should respond with PATH_RESPONSE or ignore unsolicited challenge',
  },

  // ═══════════════════════════════════════════════════════════════════
  // Category QF: Frame Structure & Mutation
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-undefined-frames',
    category: 'QF',
    description: 'QUIC packet containing undefined frame types (0x40-0xff)',
    side: 'client',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), 999);
      for(let i=0; i<5; i++) {
        builder.writeUInt8(crypto.randomInt(0x40, 0xff)); // Undefined range
        builder.writeBytes(crypto.randomBytes(4));
      }
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC undefined frames (0x40+)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
  },
  {
    name: 'quic-middlebox-evasion',
    category: 'QF',
    description: 'GREASE version number in long header to probe middlebox and firewall behavior',
    side: 'server',
    actions: () => {
      builder.reset();
      builder.writeUInt8(0x80 | 0x40 | 0x01); // Long header, type 0
      builder.writeUInt32(0x1a2a3a4a); // GREASE version
      builder.writeBytes(crypto.randomBytes(40)); // Random payload
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC GREASE version (0x1a2a3a4a)' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Middleboxes and servers should drop unrecognized QUIC versions',
  },
  {
    name: 'quic-random-payload',
    category: 'QF',
    description: 'Short-header packet with entirely random payload bytes',
    side: 'server',
    actions: () => {
      builder.reset();
      builder.buildShortHeader(false, false, crypto.randomBytes(8), crypto.randomInt(1, 100000));
      builder.writeBytes(crypto.randomBytes(200));
      return [
        { type: 'send', data: builder.getBuffer(), label: 'QUIC short header + random payload' },
        { type: 'recv', timeout: 2000 }
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should silently discard undecryptable short-header packets',
  },
];

// ── Map TLS categories (A-Y) to QUIC-TLS categories (QG-QK) ──────────────────
const TLS_TO_QUIC_CATEGORY = {
  A: 'QG', B: 'QG', N: 'QG', P: 'QG',          // Handshake order & state
  C: 'QH', H: 'QH', K: 'QH', L: 'QH',          // Parameter & extension fuzzing
  M: 'QH', Q: 'QH', R: 'QH', V: 'QH',
  D: 'QI', E: 'QI', F: 'QI', G: 'QI',          // Record & alert injection
  S: 'QI', T: 'QI', U: 'QI',
  I: 'QJ', J: 'QJ', O: 'QJ',                    // Known CVEs & PQC
  W: 'QK', X: 'QK', Y: 'QK',                    // Certificate fuzzing
};

/**
 * Adapt a single TLS action for QUIC transport.
 * Wraps TLS send data in QUIC Initial packets with CRYPTO frames.
 */
function adaptActionForQUIC(action, pnCounter) {
  switch (action.type) {
    case 'send':
      return {
        type: 'send',
        data: buildQuicInitialWithCrypto(action.data, { packetNumber: pnCounter.next++ }),
        label: action.label ? `[QUIC] ${action.label}` : '[QUIC] TLS data in Initial',
      };

    case 'recv':
      return { type: 'recv', timeout: action.timeout || 2000 };

    case 'delay':
      return { type: 'delay', ms: action.ms };

    case 'fin':
      return {
        type: 'send',
        data: buildQuicConnectionClose(0x00, 'fin'),
        label: '[QUIC] CONNECTION_CLOSE (adapted from TCP FIN)',
      };

    case 'rst':
      return {
        type: 'send',
        data: buildQuicConnectionClose(0x0a, 'rst'),
        label: '[QUIC] CONNECTION_CLOSE (adapted from TCP RST)',
      };

    case 'slowDrip': {
      // Split TLS data across multiple QUIC Initial packets with CRYPTO frame offsets
      const data = action.data;
      const chunkSize = action.bytesPerChunk || 1;
      const delayMs = action.delayMs || 20;
      const quicActions = [];
      let offset = 0;
      while (offset < data.length) {
        const chunk = data.slice(offset, offset + chunkSize);
        quicActions.push({
          type: 'send',
          data: buildQuicInitialWithCrypto(chunk, {
            packetNumber: pnCounter.next++,
            cryptoOffset: offset,
          }),
          label: `[QUIC] CRYPTO drip offset=${offset} (${chunk.length}B)`,
        });
        quicActions.push({ type: 'delay', ms: delayMs });
        offset += chunkSize;
      }
      return quicActions;
    }

    case 'fragment': {
      // Split TLS data across multiple QUIC Initial packets
      const data = action.data;
      const fragments = action.fragments || 5;
      const delayMs = action.delayMs || 20;
      const fragSize = Math.ceil(data.length / fragments);
      const quicActions = [];
      let offset = 0;
      for (let i = 0; i < fragments && offset < data.length; i++) {
        const chunk = data.slice(offset, offset + fragSize);
        quicActions.push({
          type: 'send',
          data: buildQuicInitialWithCrypto(chunk, {
            packetNumber: pnCounter.next++,
            cryptoOffset: offset,
          }),
          label: `[QUIC] CRYPTO fragment ${i + 1}/${fragments} offset=${offset} (${chunk.length}B)`,
        });
        if (delayMs > 0) quicActions.push({ type: 'delay', ms: delayMs });
        offset += fragSize;
      }
      return quicActions;
    }

    default:
      return action;
  }
}

/**
 * Generate QUIC-adapted versions of all TLS client scenarios.
 * Each TLS scenario's actions are wrapped in QUIC Initial packets with CRYPTO frames.
 */
function generateQuicTLSScenarios() {
  // Lazy-load to avoid circular dependency (scenarios.js loads at module init)
  const { getClientScenarios } = require('./scenarios');
  const tlsClientScenarios = getClientScenarios();

  for (const sc of tlsClientScenarios) {
    const quicCategory = TLS_TO_QUIC_CATEGORY[sc.category] || 'QG';

    QUIC_SCENARIOS.push({
      name: 'quic-tls-' + sc.name,
      category: quicCategory,
      description: sc.description + ' [via QUIC Initial]',
      side: 'client',
      expected: 'DROPPED',
      expectedReason: (sc.expectedReason || 'Malformed TLS data') + ' (via QUIC transport)',
      actions: (opts) => {
        const tlsActions = sc.actions(opts);
        const pnCounter = { next: 1 };
        const quicActions = [];
        for (const action of tlsActions) {
          const adapted = adaptActionForQUIC(action, pnCounter);
          if (Array.isArray(adapted)) {
            quicActions.push(...adapted);
          } else {
            quicActions.push(adapted);
          }
        }
        return quicActions;
      },
    });
  }
}

generateQuicTLSScenarios();

function getQuicScenario(name) {
  return QUIC_SCENARIOS.find(s => s.name === name);
}

function getQuicScenariosByCategory(cat) {
  return QUIC_SCENARIOS.filter(s => s.category === cat.toUpperCase());
}

function listQuicScenarios() {
  const grouped = {};
  for (const s of QUIC_SCENARIOS) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return { categories: QUIC_CATEGORIES, scenarios: grouped, all: QUIC_SCENARIOS };
}

module.exports = {
  QUIC_SCENARIOS,
  QUIC_CATEGORIES,
  QUIC_CATEGORY_SEVERITY,
  QUIC_CATEGORY_DEFAULT_DISABLED,
  getQuicScenario,
  getQuicScenariosByCategory,
  listQuicScenarios,
};
