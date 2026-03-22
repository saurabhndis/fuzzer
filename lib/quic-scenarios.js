// QUIC fuzzing scenarios
// Ported from: ../quic/fuzzer.js
const crypto = require('crypto');
const PacketBuilder = require('./quic-packet');
const { buildQuicInitialWithCrypto, buildQuicConnectionClose, encodeVarInt, deriveInitialKeys, protectPacket } = require('./quic-packet');
const hs = require('./handshake');
const { Version, CipherSuite, ExtensionType, HandshakeType, NamedGroup } = require('./constants');

/**
 * Encode a single QUIC transport parameter: id(varint) + length(varint) + value.
 */
function encodeTransportParam(id, value) {
  return Buffer.concat([encodeVarInt(id), encodeVarInt(value.length), value]);
}

/**
 * Build minimal QUIC transport parameters for a compliant ClientHello.
 * @param {Buffer} scid - Source Connection ID (for initial_source_connection_id)
 */
function buildTransportParams(scid) {
  return Buffer.concat([
    encodeTransportParam(0x0f, scid),                  // initial_source_connection_id (required)
    encodeTransportParam(0x04, encodeVarInt(1048576)),  // initial_max_data
    encodeTransportParam(0x05, encodeVarInt(524288)),   // initial_max_stream_data_bidi_local
    encodeTransportParam(0x06, encodeVarInt(524288)),   // initial_max_stream_data_bidi_remote
    encodeTransportParam(0x07, encodeVarInt(524288)),   // initial_max_stream_data_uni
    encodeTransportParam(0x08, encodeVarInt(100)),      // initial_max_streams_bidi
    encodeTransportParam(0x09, encodeVarInt(100)),      // initial_max_streams_uni
    encodeTransportParam(0x01, encodeVarInt(30000)),    // max_idle_timeout (ms)
  ]);
}

const { QUIC_SCAN_CATEGORIES, QUIC_SCAN_SCENARIOS } = require('./quic-scan-scenarios');
const { PAN_SNI_CATEGORIES, getPanSniScenarios } = require('./pan-sni-scenarios');
const { PAN_PQC_CATEGORIES, getPanPqcScenarios } = require('./pan-pqc-evasion');

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
  QL: 'QUIC Server-to-Client Attacks',
  QZ: 'Well-behaved QUIC (Functional Validation)',
  QM: 'QUIC Firewall Detection (EICAR, Malware, SQLi)',
  QN: 'QUIC Sandbox Detection (Exploit Kits, JS Droppers)',
  QO: 'QUIC SNI Evasion & URL Category Probes',
  QS: 'QUIC Server-Side Fuzzing',
  ...QUIC_SCAN_CATEGORIES,
  ...PAN_SNI_CATEGORIES,
  ...PAN_PQC_CATEGORIES,
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
  QL: 'high',
  QM: 'high',
  QN: 'high',
  QO: 'info',
  QS: 'high',
  QSCAN: 'info',
  PAN: 'info',
  'PAN-PQC': 'info',
};

const QUIC_CATEGORY_DEFAULT_DISABLED = new Set(['QS']);

const builder = new PacketBuilder();

function longHeader(type, version, dcid, scid) {
  builder.reset();
  builder.buildLongHeader(type, version, dcid, scid);
}

const { FW_SRV_SCENARIOS } = require('./firewall-scenarios');

const QUIC_SCENARIOS = [
  // ═══════════════════════════════════════════════════════════════════
  // Category QZ: Well-behaved QUIC (Functional Validation)
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-well-behaved-single-get',
    category: 'QZ',
    description: 'Standard HTTP/3 GET request over a single QUIC stream',
    side: 'client',
    isOpenSslBaseline: true, // Use native quiche engine
    streamCount: 1,
    expected: 'PASSED',
  },

  {
    name: 'quic-well-behaved-multi-get-concurrent',
    category: 'QZ',
    description: 'Concurrent HTTP/3 GET requests over 5 QUIC streams',
    side: 'client',
    isOpenSslBaseline: true,
    streamCount: 5,
    expected: 'PASSED',
  },

  {
    name: 'quic-well-behaved-large-post-echo',
    category: 'QZ',
    description: 'Large HTTP/3 POST request (100KB) with echo verification',
    side: 'client',
    isOpenSslBaseline: true,
    clientHandler: async (shim, host, logger, session) => {
      const payload = crypto.randomBytes(102400); // 100KB
      const req = session.request({
        ':method': 'POST',
        ':path': '/echo',
        ':scheme': 'https',
        ':authority': host,
        'content-type': 'application/octet-stream',
        'content-length': payload.length.toString(),
      });
      req.end(payload);

      const resp = await new Promise((resolve) => {
        let buf = Buffer.alloc(0);
        let status = 0;
        req.on('response', (h) => { status = h[':status']; });
        req.on('data', (d) => { buf = Buffer.concat([buf, d]); });
        req.on('end', () => resolve({ status, data: buf }));
        req.on('error', (e) => resolve({ status: 0, error: e.message }));
      });

      if (resp.error) return { status: 'ERROR', response: resp.error };
      if (resp.data.equals(payload)) {
        return { status: 'PASSED', response: `Echo verified: ${resp.data.length} bytes exchanged correctly` };
      }
      return { status: 'FAILED', response: `Data mismatch: sent ${payload.length}B, received ${resp.data.length}B` };
    },
    expected: 'PASSED',
  },

  {
    name: 'quic-well-behaved-multi-stream-sequential',
    category: 'QZ',
    description: 'Sequential HTTP/3 requests over multiple streams in a single connection',
    side: 'client',
    isOpenSslBaseline: true,
    clientHandler: async (shim, host, logger, session) => {
      let totalBytes = 0;
      for (let i = 0; i < 5; i++) {
        const req = session.request({
          ':method': 'GET',
          ':path': `/seq-${i}`,
          ':scheme': 'https',
          ':authority': host,
        });
        req.end();
        const bytes = await new Promise((resolve) => {
          let b = 0;
          req.on('data', (d) => { b += d.length; });
          req.on('end', () => resolve(b));
          req.on('error', () => resolve(b));
        });
        totalBytes += bytes;
        logger.info(`Stream ${i} completed: ${bytes} bytes`);
      }
      return { status: 'PASSED', response: `5 sequential streams completed, ${totalBytes} bytes total` };
    },
    expected: 'PASSED',
  },

  {
    name: 'quic-well-behaved-bidirectional-data',
    category: 'QZ',
    description: 'Full-duplex bidirectional data exchange over a single QUIC stream',
    side: 'client',
    isOpenSslBaseline: true,
    clientHandler: async (shim, host, logger, session) => {
      const stream = session.request({
        ':method': 'POST',
        ':path': '/duplex',
        ':scheme': 'https',
        ':authority': host,
      });

      let received = 0;
      stream.on('data', (d) => { received += d.length; });

      // Send data in chunks with delays to verify multiplexing/streaming
      for (let i = 0; i < 5; i++) {
        stream.write(Buffer.alloc(1024, i));
        await new Promise(r => setTimeout(r, 100));
      }
      stream.end();

      await new Promise(r => stream.on('end', r));
      return { status: 'PASSED', response: `Bidirectional exchange finished: ${received} bytes received` };
    },
    expected: 'PASSED',
  },

  {
    name: 'srv-quic-well-behaved-echo',
    category: 'QZ',
    description: 'Server: Well-behaved HTTP/3 echo server (functional validation)',
    side: 'server',
    isOpenSslBaseline: true, // Run via QuicheServer
    expected: 'PASSED',
  },

  ...FW_SRV_SCENARIOS.filter(s => s.category === 'QS'),

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
    category: 'QS',
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
    category: 'QS',
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
    category: 'QS',
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
    category: 'QS',
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
    category: 'QS',
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
    category: 'QS',
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
    category: 'QS',
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

  // ═══════════════════════════════════════════════════════════════════
  // Category QL: Server-to-Client Attacks
  // These use serverHandler(rinfo, sendFn, log, clientPacket) and run
  // on the QUIC fuzzer server to fuzz connecting QUIC clients.
  // ═══════════════════════════════════════════════════════════════════

  {
    name: 'quic-server-retry-flood',
    category: 'QS',
    description: 'Flood client with 50 Retry packets to overwhelm retry logic',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log, clientPacket) => {
      log('Retry Flood: Sending 50 Retry packets...');
      const dcid = clientPacket.length >= 6 ? clientPacket.slice(6, 14) : crypto.randomBytes(8);
      for (let i = 0; i < 50; i++) {
        const b = new PacketBuilder();
        b.buildLongHeader(3, 0x00000001, dcid, crypto.randomBytes(8)); // Retry
        b.writeBytes(crypto.randomBytes(32 + (i % 20))); // Random token
        b.writeBytes(crypto.randomBytes(16)); // Integrity tag
        await sendFn(b.getBuffer(), `Retry packet ${i + 1}/50`);
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Client should limit Retry processing and detect flood',
  },
  {
    name: 'quic-server-version-negotiation-invalid',
    category: 'QS',
    description: 'Version Negotiation listing only invalid/unknown versions',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log, clientPacket) => {
      log('Version Negotiation with invalid versions only');
      const b = new PacketBuilder();
      b.writeUInt8(0x80); // Long header form
      b.writeUInt32(0x00000000); // Version 0 (Version Negotiation)
      const dcid = clientPacket.length >= 6 ? clientPacket.slice(6, 14) : crypto.randomBytes(8);
      b.writeUInt8(dcid.length);
      b.writeBytes(dcid);
      b.writeUInt8(8);
      b.writeBytes(crypto.randomBytes(8)); // Random SCID
      // List only invalid versions
      b.writeUInt32(0xdeadbeef);
      b.writeUInt32(0xcafebabe);
      b.writeUInt32(0x0a0a0a0a); // GREASE
      b.writeUInt32(0xffffffff);
      await sendFn(b.getBuffer(), 'Version Negotiation (invalid versions only)');
    },
    expected: 'DROPPED',
    expectedReason: 'Client should abort when no supported version is offered',
  },
  {
    name: 'quic-server-initial-flood',
    category: 'QS',
    description: 'Flood client with Initial packets containing garbage ServerHello',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log) => {
      log('Initial Flood: Sending 30 Initial packets with garbage CRYPTO...');
      for (let i = 0; i < 30; i++) {
        const garbageServerHello = crypto.randomBytes(200 + (i * 10));
        const pkt = buildQuicInitialWithCrypto(garbageServerHello, {
          packetNumber: i + 1,
          dcid: crypto.randomBytes(8),
          scid: crypto.randomBytes(8),
        });
        await sendFn(pkt, `Initial with garbage ServerHello ${i + 1}/30`);
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Client should reject malformed ServerHello in CRYPTO frame',
  },
  {
    name: 'quic-server-handshake-invalid-cert',
    category: 'QS',
    description: 'Handshake packet with corrupt certificate data in CRYPTO frame',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log) => {
      log('Sending Handshake with corrupt certificate in CRYPTO frame');
      // Build a Handshake packet (type 2) with garbage certificate
      const b = new PacketBuilder();
      b.buildLongHeader(2, 0x00000001, crypto.randomBytes(8), crypto.randomBytes(8));
      // Payload: PN + CRYPTO frame with corrupt cert
      const fakeCert = Buffer.alloc(500);
      fakeCert[0] = 0x0b; // Certificate handshake type
      fakeCert.writeUIntBE(490, 1, 3); // Length
      crypto.randomBytes(490).copy(fakeCert, 4); // Garbage cert data
      const cryptoFrame = Buffer.concat([
        Buffer.from([0x06]), // CRYPTO frame type
        Buffer.from([0x00]), // Offset 0
        Buffer.from([0x43, 0xf4]), // Length varint (500)
        fakeCert,
      ]);
      const payload = Buffer.concat([Buffer.from([0x00, 0x01]), cryptoFrame]); // PN + frame
      b.writeVarInt(payload.length);
      b.writeBytes(payload);
      await sendFn(b.getBuffer(), 'Handshake with corrupt certificate');
    },
    expected: 'DROPPED',
    expectedReason: 'Client should reject malformed certificate and close connection',
  },
  {
    name: 'quic-server-connection-close-abuse',
    category: 'QS',
    description: 'Rapid CONNECTION_CLOSE frames with misleading error codes',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log) => {
      log('CONNECTION_CLOSE abuse: Sending 20 with different error codes...');
      const errorCodes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0xdeadbeef, 0xffffffff,
      ];
      for (let i = 0; i < errorCodes.length; i++) {
        const pkt = buildQuicConnectionClose(errorCodes[i], `error-${i}`);
        await sendFn(pkt, `CONNECTION_CLOSE error=0x${errorCodes[i].toString(16)}`);
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Client should handle rapid CONNECTION_CLOSE without crashing',
  },
  {
    name: 'quic-server-stateless-reset-flood',
    category: 'QS',
    description: 'Flood with packets resembling Stateless Reset tokens',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log) => {
      log('Stateless Reset flood: Sending 40 reset-like packets...');
      for (let i = 0; i < 40; i++) {
        // Stateless Reset: unpredictable bytes followed by 16-byte token
        // Must be at least 21 bytes and look like a short header
        const randomPrefix = crypto.randomBytes(5 + (i % 30));
        randomPrefix[0] = (randomPrefix[0] & 0x7f) | 0x40; // Short header form
        const resetToken = crypto.randomBytes(16);
        const pkt = Buffer.concat([randomPrefix, resetToken]);
        await sendFn(pkt, `Stateless Reset ${i + 1}/40`);
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Client should validate Stateless Reset tokens and not crash on flood',
  },
  {
    name: 'quic-server-malformed-transport-params',
    category: 'QS',
    description: 'Initial response with corrupt transport parameters in CRYPTO frame',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log) => {
      log('Sending Initial with malformed transport parameters');
      // Construct a fake ServerHello with corrupt transport params extension
      const fakeServerHello = Buffer.alloc(300);
      fakeServerHello[0] = 0x02; // ServerHello handshake type
      fakeServerHello.writeUIntBE(296, 1, 3); // Length
      fakeServerHello.writeUInt16BE(0x0303, 4); // TLS 1.2 legacy version
      crypto.randomBytes(32).copy(fakeServerHello, 6); // Server random
      fakeServerHello[38] = 0x00; // Session ID length 0
      fakeServerHello.writeUInt16BE(0x1301, 39); // Cipher suite
      fakeServerHello[41] = 0x00; // Compression
      // Extensions with corrupt transport params
      fakeServerHello.writeUInt16BE(250, 42); // Extensions length
      fakeServerHello.writeUInt16BE(0x0039, 44); // quic_transport_parameters extension
      fakeServerHello.writeUInt16BE(246, 46); // Extension data length
      // Fill with invalid transport parameter encodings
      for (let i = 48; i < 294; i += 6) {
        fakeServerHello.writeUInt16BE(0xffff, i); // Invalid param ID
        fakeServerHello.writeUInt32BE(0xffffffff, i + 2); // Invalid length
      }
      const pkt = buildQuicInitialWithCrypto(fakeServerHello, {
        packetNumber: 1,
        dcid: crypto.randomBytes(8),
        scid: crypto.randomBytes(8),
      });
      await sendFn(pkt, 'Initial with corrupt transport parameters');
    },
    expected: 'DROPPED',
    expectedReason: 'Client should detect TRANSPORT_PARAMETER_ERROR and close',
  },
  {
    name: 'quic-server-amplification-exploit',
    category: 'QS',
    description: 'Response exceeding 3x client Initial size (violates anti-amplification)',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log, clientPacket) => {
      const clientSize = clientPacket.length;
      const targetSize = clientSize * 5; // 5x amplification (violates 3x limit)
      log(`Amplification attack: client=${clientSize}B, sending ${targetSize}B (5x)`);
      // Send multiple large Initial packets to exceed amplification limit
      let sent = 0;
      let pn = 1;
      while (sent < targetSize) {
        const chunkSize = Math.min(1200, targetSize - sent);
        const payload = crypto.randomBytes(chunkSize > 50 ? chunkSize - 50 : chunkSize);
        const pkt = buildQuicInitialWithCrypto(payload, {
          packetNumber: pn++,
          dcid: crypto.randomBytes(8),
          scid: crypto.randomBytes(8),
        });
        await sendFn(pkt, `Amplification chunk ${pn - 1} (${pkt.length}B)`);
        sent += pkt.length;
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Client should detect server violating anti-amplification limit',
  },
  {
    name: 'quic-server-zero-length-cid',
    category: 'QS',
    description: 'Response packets with zero-length connection IDs',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log) => {
      log('Sending packets with zero-length DCID and SCID');
      // Initial with zero-length CIDs
      const b = new PacketBuilder();
      b.buildLongHeader(0, 0x00000001, Buffer.alloc(0), Buffer.alloc(0));
      b.writeVarInt(0); // Token length
      const payload = crypto.randomBytes(100);
      b.writeVarInt(payload.length + 2);
      b.writeUInt16(1); // PN
      b.writeBytes(payload);
      await sendFn(b.getBuffer(), 'Initial with zero-length CIDs');

      // Also try Handshake with zero-length CIDs
      const b2 = new PacketBuilder();
      b2.buildLongHeader(2, 0x00000001, Buffer.alloc(0), Buffer.alloc(0));
      const payload2 = crypto.randomBytes(50);
      b2.writeVarInt(payload2.length + 2);
      b2.writeUInt16(2);
      b2.writeBytes(payload2);
      await sendFn(b2.getBuffer(), 'Handshake with zero-length CIDs');
    },
    expected: 'DROPPED',
    expectedReason: 'Client should handle zero-length CIDs per RFC 9000 or reject gracefully',
  },
  {
    name: 'quic-server-path-challenge-flood',
    category: 'QS',
    description: 'Flood PATH_CHALLENGE frames to exhaust client resources',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log) => {
      log('PATH_CHALLENGE flood: Sending 100 challenges...');
      for (let i = 0; i < 100; i++) {
        const b = new PacketBuilder();
        b.buildShortHeader(false, false, crypto.randomBytes(8), i + 1);
        b.writeUInt8(0x1a); // PATH_CHALLENGE
        b.writeBytes(crypto.randomBytes(8)); // 8-byte challenge data
        await sendFn(b.getBuffer(), `PATH_CHALLENGE ${i + 1}/100`);
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Client should rate-limit PATH_RESPONSE and not exhaust resources',
  },

  {
    name: 'well-behaved-quic-server',
    category: 'QA',
    description: 'Compliant QUIC server handshake baseline',
    side: 'server',
    serverHandler: async (rinfo, sendFn, log, msg) => {
      log('Well-behaved QUIC server: responding with ServerHello Initial');

      if (!msg || msg.length < 6) { log('Packet too short'); return; }

      const firstByte = msg[0];
      const isLong = (firstByte & 0x80) !== 0;
      if (!isLong) { log('Short header — ignoring'); return; }

      const version = msg.readUInt32BE(1);

      // Version 0 or unknown → respond with Version Negotiation
      if (version === 0x00000000 || version === 0x0a0a0a0a) {
        const dcidLen = msg[5];
        const clientDcid = msg.slice(6, 6 + dcidLen);
        const scidLen = msg[6 + dcidLen];
        const clientScid = msg.slice(7 + dcidLen, 7 + dcidLen + scidLen);

        const vnFirstByte = Buffer.from([0x80 | (crypto.randomBytes(1)[0] & 0x7f)]);
        const versionZero = Buffer.alloc(4, 0);
        const v1 = Buffer.alloc(4); v1.writeUInt32BE(0x00000001, 0);
        const v2 = Buffer.alloc(4); v2.writeUInt32BE(0x6b3343cf, 0);
        const vnPacket = Buffer.concat([
          vnFirstByte, versionZero,
          Buffer.from([clientScid.length]), clientScid,
          Buffer.from([clientDcid.length]), clientDcid,
          v1, v2,
        ]);
        await sendFn(vnPacket, 'Version Negotiation');
        return;
      }

      // Parse DCID and SCID from incoming Initial
      const dcidLen = msg[5];
      const clientDcid = msg.slice(6, 6 + dcidLen);
      const scidLen = msg[6 + dcidLen];
      const clientScid = msg.slice(7 + dcidLen, 7 + dcidLen + scidLen);

      // Build a protected Initial containing a ServerHello
      const serverScid = crypto.randomBytes(8);
      const serverRandom = crypto.randomBytes(32);
      const selectedCipher = CipherSuite.TLS_AES_128_GCM_SHA256;

      // ServerHello body
      const shExts = [];
      // supported_versions: TLS 1.3
      shExts.push(Buffer.concat([
        Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]),
      ]));
      // key_share: X25519 with random public key
      const ksPublic = crypto.randomBytes(32);
      const ksData = Buffer.concat([
        Buffer.from([0x00, 0x1d, 0x00, ksPublic.length]),
        ksPublic,
      ]);
      shExts.push(Buffer.concat([
        Buffer.from([0x00, 0x33, ksData.length >> 8, ksData.length & 0xff]),
        ksData,
      ]));
      const allExts = Buffer.concat(shExts);

      const shBody = Buffer.concat([
        Buffer.from([0x03, 0x03]),
        serverRandom,
        Buffer.from([0x00]),  // session_id_length = 0
        Buffer.from([selectedCipher >> 8, selectedCipher & 0xff]),
        Buffer.from([0x00]),  // compression_method: null
        Buffer.from([allExts.length >> 8, allExts.length & 0xff]),
        allExts,
      ]);

      // TLS Handshake message
      const shMsg = Buffer.concat([
        Buffer.from([HandshakeType.SERVER_HELLO]),
        Buffer.from([0x00, (shBody.length >> 8) & 0xff, shBody.length & 0xff]),
        shBody,
      ]);

      // CRYPTO frame
      const cryptoFrame = Buffer.concat([
        Buffer.from([0x06]),
        encodeVarInt(0),
        encodeVarInt(shMsg.length),
        shMsg,
      ]);

      // Build protected Initial packet
      const pn = 0;
      const pnLen = 2;
      const pnBuf = Buffer.alloc(pnLen);
      pnBuf.writeUInt16BE(pn & 0xffff, 0);

      const hdrFirstByte = Buffer.from([0x80 | 0x40 | (0 << 4) | (pnLen - 1)]);
      const versionBuf = Buffer.alloc(4);
      versionBuf.writeUInt32BE(version, 0);
      const tokenLenEnc = encodeVarInt(0);
      const payloadLen = pnLen + cryptoFrame.length + 16;
      const payloadLenEnc = encodeVarInt(payloadLen);

      const header = Buffer.concat([
        hdrFirstByte, versionBuf,
        Buffer.from([clientScid.length]), clientScid,
        Buffer.from([serverScid.length]), serverScid,
        tokenLenEnc, payloadLenEnc, pnBuf,
      ]);

      // Derive server-side Initial keys
      const QUIC_V1_SALT = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');
      const QUIC_V2_SALT = Buffer.from('0dede3def700a6db819381be6e269dcbf9bd2ed9', 'hex');
      const salt = (version === 0x6b3343cf) ? QUIC_V2_SALT : QUIC_V1_SALT;
      const initialSecret = crypto.createHmac('sha256', salt).update(clientDcid).digest();
      const emptyCtx = Buffer.alloc(0);
      const hkdfExpand = (prk, label, len) => {
        const tlsLabel = Buffer.from('tls13 ' + label, 'ascii');
        const hkdfLabel = Buffer.concat([
          Buffer.from([0, len]), Buffer.from([tlsLabel.length]), tlsLabel,
          Buffer.from([0]),  // empty context
        ]);
        return crypto.createHmac('sha256', prk).update(Buffer.concat([hkdfLabel, Buffer.from([1])])).digest().slice(0, len);
      };
      const serverSecret = hkdfExpand(initialSecret, 'server in', 32);
      const keys = {
        key: hkdfExpand(serverSecret, 'quic key', 16),
        iv:  hkdfExpand(serverSecret, 'quic iv',  12),
        hp:  hkdfExpand(serverSecret, 'quic hp',  16),
      };

      const packet = protectPacket(header, cryptoFrame, pn, pnLen, keys);
      await sendFn(packet, 'QUIC Initial (ServerHello)');
    },
    expected: 'PASSED',
  },

  {
    name: 'well-behaved-quic-client',
    category: 'QA',
    description: 'Compliant QUIC client handshake baseline (via OpenSSL 3.6+)',
    side: 'client',
    isOpenSslBaseline: true, // Flag to indicate runner should route this to QuicBaselineClient
    actions: (opts) => {
      return []; // Handled by QuicBaselineClient
    },
    expected: 'PASSED',
  },

  {
    name: 'well-behaved-quic-client-100-streams',
    category: 'QA',
    description: 'Compliant QUIC client handshake and multiplexes 100 streams (via OpenSSL 3.6+)',
    side: 'client',
    isOpenSslBaseline: true,
    actions: (opts) => {
      return []; // Handled by QuicBaselineClient
    },
    expected: 'PASSED',
  },

  {
    name: 'quic-post-handshake-garbage',
    category: 'QD',
    description: 'Completes QUIC handshake, then floods the 1-RTT stream with 1MB of random binary noise',
    side: 'client',
    isOpenSslBaseline: true,
    actions: () => [],
    expected: 'DROPPED',
    expectedReason: 'Server should disconnect or reset the stream upon receiving malformed application data',
  },

  {
    name: 'quic-post-handshake-slowloris',
    category: 'QC',
    description: 'Completes QUIC handshake, then drip-feeds 1 byte per second to exhaust idle timeouts',
    side: 'client',
    isOpenSslBaseline: true,
    actions: () => [],
    expected: 'TIMEOUT',
    expectedReason: 'Server should enforce an idle timeout and drop the connection',
  },

  {
    name: 'quic-post-handshake-http-smuggling',
    category: 'QF',
    description: 'Completes QUIC handshake, then sends overlapping/malformed HTTP/1.1 syntax over the stream',
    side: 'client',
    isOpenSslBaseline: true,
    actions: () => [],
    expected: 'DROPPED',
    expectedReason: 'HTTP/3 parser should reject the raw HTTP/1.1 syntax and drop the stream',
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
  PAN: 'QO',                                    // SNI / URL probes
  'PAN-PQC': 'QJ',                              // PQC evasion
  FW: 'QM', AN: 'QM',                           // Firewall detection
  SB: 'QN', AO: 'QN',                           // Sandbox detection
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
 * Generate QUIC-adapted versions of TLS client scenarios.
 * Each scenario is wrapped in QUIC transport or routed through the native quiche engine.
 */
function generateAdaptedQuicScenarios() {
  // Lazy-load to avoid circular dependency
  const { getClientScenarios: getTlsClientScenarios } = require('./scenarios');
  const tlsClientScenarios = getTlsClientScenarios();

  // Use TLS client scenarios for adaptation
  const allScenarios = [...tlsClientScenarios];

  for (const sc of allScenarios) {
    // Skip application-layer scenarios (category Z) — tlsPost doesn't apply to QUIC
    if (sc.category === 'Z') continue;
    
    // Scenarios without explicit actions or a clientHandler cannot be easily adapted
    if (typeof sc.actions !== 'function' && typeof sc.clientHandler !== 'function') continue;

    const quicCategory = TLS_TO_QUIC_CATEGORY[sc.category] || 'QG';

    const quicScenario = {
      ...sc, // Inherit properties like useNodeH2
      name: 'quic-tls-' + sc.name,
      category: quicCategory,
      description: sc.description + ' [via QUIC Initial]',
      side: 'client',
      protocol: 'quic',
      expected: sc.expected || 'DROPPED',
      expectedReason: (sc.expectedReason || 'Malformed TLS data') + ' (via QUIC transport)',
    };

    if (typeof sc.actions === 'function') {
      quicScenario.actions = (opts) => {
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
      };
    } else if (typeof sc.clientHandler === 'function') {
      // For scenarios with a clientHandler (like fw-eicar or h2-fw-eicar),
      // run them using the quiche engine.
      quicScenario.isOpenSslBaseline = true;
      quicScenario.clientHandler = sc.clientHandler;
    }

    QUIC_SCENARIOS.push(quicScenario);
  }
}

generateAdaptedQuicScenarios();

// Push PAN QUIC scenarios
QUIC_SCENARIOS.push(...getPanSniScenarios('quic'));

function getQuicScenario(name) {
  return QUIC_SCENARIOS.find(s => s.name === name) || QUIC_SCAN_SCENARIOS.find(s => s.name === name);
}

function getQuicScenariosByCategory(cat) {
  const all = QUIC_SCENARIOS.concat(QUIC_SCAN_SCENARIOS);
  return all.filter(s => s.category === cat.toUpperCase());
}

function listQuicScenarios() {
  const all = QUIC_SCENARIOS.concat(QUIC_SCAN_SCENARIOS);
  const grouped = {};
  for (const s of all) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return { categories: QUIC_CATEGORIES, scenarios: grouped, all };
}

function listQuicClientScenarios() {
  const all = QUIC_SCENARIOS.concat(QUIC_SCAN_SCENARIOS);
  return all.filter(s => s.side === 'client');
}

function listQuicServerScenarios() {
  return QUIC_SCENARIOS.filter(s => s.side === 'server');
}

module.exports = {
  QUIC_SCENARIOS,
  QUIC_CATEGORIES,
  QUIC_CATEGORY_SEVERITY,
  QUIC_CATEGORY_DEFAULT_DISABLED,
  getQuicScenario,
  getQuicScenariosByCategory,
  listQuicScenarios,
  listQuicClientScenarios,
  listQuicServerScenarios,
};
