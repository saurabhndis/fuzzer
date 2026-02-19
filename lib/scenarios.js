// All fuzzing scenarios organized into 13 categories
const { Version, AlertLevel, AlertDescription, ContentType, HandshakeType, CipherSuite, ExtensionType, CompressionMethod, HeartbeatMessageType, NamedGroup } = require('./constants');
const { buildAlert, buildChangeCipherSpec, buildChangeCipherSpecWithPayload, buildRecord, buildOversizedRecord, buildZeroLengthRecord, buildWrongLengthRecord, buildRawGarbage, buildGarbageRecord, buildHeartbeatRequest, buildSSLv2ClientHello } = require('./record');
const hs = require('./handshake');
const crypto = require('crypto');

const CATEGORIES = {
  A: 'Handshake Order Violations (Client)',
  B: 'Handshake Order Violations (Server)',
  C: 'Parameter Mutation',
  D: 'Alert Injection',
  E: 'TCP Manipulation',
  F: 'Record Layer Attacks',
  G: 'ChangeCipherSpec Attacks',
  H: 'Extension Fuzzing',
  I: 'Known Vulnerability Detection (CVEs)',
  J: 'Post-Quantum Cryptography (PQC)',
  K: 'SNI Evasion & Fragmentation',
  L: 'ALPN Protocol Confusion',
  M: 'Extension Malformation & Placement',
  N: 'TCP/TLS Parameter Reneging',
  O: 'TLS 1.3 Early Data & 0-RTT Fuzzing',
  P: 'Advanced Handshake Record Fuzzing',
};

// Severity per category — used by grader to weight pass/fail
const CATEGORY_SEVERITY = {
  A: 'high',     // Handshake order — protocol state machine bypass
  B: 'high',     // Server handshake order — state machine bypass
  C: 'medium',   // Parameter mutation — downgrade / mismatch attacks
  D: 'medium',   // Alert injection — protocol confusion
  E: 'low',      // TCP manipulation — robustness / resilience
  F: 'high',     // Record layer — fundamental protocol violations
  G: 'high',     // CCS attacks — CVE-2014-0224 vector
  H: 'medium',   // Extension fuzzing — parser robustness
  I: 'critical', // CVE detection — known exploitable vulnerabilities
  J: 'low',      // PQC — forward-looking compatibility
  K: 'medium',   // SNI evasion — middlebox bypass / censorship evasion
  L: 'medium',   // ALPN confusion — protocol negotiation attacks
  M: 'medium',   // Extension malformation — parser crash / memory corruption
  N: 'high',     // Parameter reneging — mid-stream downgrade / confusion attacks
  O: 'high',     // TLS 1.3 early data — 0-RTT replay / PSK abuse
  P: 'high',     // Advanced handshake record — parser crash / state machine bypass
};

// Each scenario: { name, category, description, side: 'client'|'server', actions(opts) }
// actions returns an array of action objects:
//   { type: 'send', data: Buffer, label?: string }
//   { type: 'recv', timeout?: number }
//   { type: 'delay', ms: number }
//   { type: 'fin', label?: string }
//   { type: 'rst', label?: string }
//   { type: 'slowDrip', data: Buffer, bytesPerChunk: number, delayMs: number }
//   { type: 'fragment', data: Buffer, fragments: number, delayMs: number }

const SCENARIOS = [
  // ===== Category A: Handshake Order Violations (Client) =====
  {
    name: 'out-of-order-finished-first',
    category: 'A',
    description: 'Send Finished before ClientHello',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildFinished(), label: '[FUZZ] Finished (before ClientHello)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'out-of-order-cke-before-hello',
    category: 'A',
    description: 'Send ClientKeyExchange before ClientHello',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientKeyExchange(), label: '[FUZZ] ClientKeyExchange (before ClientHello)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'duplicate-client-hello',
    category: 'A',
    description: 'Send ClientHello twice',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello #1' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: '[FUZZ] ClientHello #2 (duplicate)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'client-hello-after-finished',
    category: 'A',
    description: 'Send ClientHello, receive ServerHello, then send another ClientHello',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: hs.buildFinished(), label: '[FUZZ] Finished (skipping everything)' },
      { type: 'delay', ms: 100 },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: '[FUZZ] ClientHello (after Finished)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'skip-client-key-exchange',
    category: 'A',
    description: 'ClientHello then jump straight to ChangeCipherSpec + Finished',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildChangeCipherSpec(), label: '[FUZZ] ChangeCipherSpec (skipping CKE)' },
      { type: 'send', data: hs.buildFinished(), label: '[FUZZ] Finished (skipping CKE)' },
      { type: 'recv', timeout: 3000 },
    ],
  },

  // ===== Category B: Handshake Order Violations (Server) =====
  {
    name: 'server-hello-before-client-hello',
    category: 'B',
    description: 'Server sends ServerHello immediately without waiting for ClientHello',
    side: 'server',
    actions: (opts) => [
      { type: 'send', data: hs.buildServerHello(), label: '[FUZZ] ServerHello (before ClientHello)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'duplicate-server-hello',
    category: 'B',
    description: 'Server sends ServerHello twice',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildServerHello(), label: 'ServerHello #1' },
      { type: 'send', data: hs.buildCertificate(), label: 'Certificate' },
      { type: 'send', data: hs.buildServerHelloDone(), label: 'ServerHelloDone' },
      { type: 'delay', ms: 100 },
      { type: 'send', data: hs.buildServerHello(), label: '[FUZZ] ServerHello #2 (duplicate)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'skip-server-hello-done',
    category: 'B',
    description: 'Server omits ServerHelloDone',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildServerHello(), label: 'ServerHello' },
      { type: 'send', data: hs.buildCertificate(), label: 'Certificate' },
      // Deliberately skip ServerHelloDone
      { type: 'send', data: buildChangeCipherSpec(), label: '[FUZZ] CCS (skipping ServerHelloDone)' },
      { type: 'send', data: hs.buildFinished(), label: '[FUZZ] Finished (skipping ServerHelloDone)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'certificate-before-server-hello',
    category: 'B',
    description: 'Server sends Certificate before ServerHello',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildCertificate(), label: '[FUZZ] Certificate (before ServerHello)' },
      { type: 'send', data: hs.buildServerHello(), label: 'ServerHello' },
      { type: 'send', data: hs.buildServerHelloDone(), label: 'ServerHelloDone' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'double-server-hello-done',
    category: 'B',
    description: 'Server sends ServerHelloDone twice',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildServerHello(), label: 'ServerHello' },
      { type: 'send', data: hs.buildCertificate(), label: 'Certificate' },
      { type: 'send', data: hs.buildServerHelloDone(), label: 'ServerHelloDone #1' },
      { type: 'send', data: hs.buildServerHelloDone(), label: '[FUZZ] ServerHelloDone #2 (duplicate)' },
      { type: 'recv', timeout: 3000 },
    ],
  },

  // ===== Category C: Parameter Mutation =====
  {
    name: 'version-downgrade-mid-handshake',
    category: 'C',
    description: 'ClientHello says TLS 1.2, then CKE record header says TLS 1.0',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, version: Version.TLS_1_2 }), label: 'ClientHello (TLS 1.2)' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: hs.buildClientKeyExchange({ recordVersion: Version.TLS_1_0 }), label: '[FUZZ] CKE (record says TLS 1.0)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'cipher-suite-mismatch',
    category: 'C',
    description: 'Server selects a cipher suite not in client\'s offered list',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildServerHello({ cipherSuite: CipherSuite.TLS_RSA_WITH_RC4_128_SHA }), label: '[FUZZ] ServerHello (RC4 - not offered)' },
      { type: 'send', data: hs.buildCertificate(), label: 'Certificate' },
      { type: 'send', data: hs.buildServerHelloDone(), label: 'ServerHelloDone' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'session-id-mutation',
    category: 'C',
    description: 'Change session ID between handshake messages',
    side: 'client',
    actions: (opts) => {
      const sid1 = crypto.randomBytes(32);
      const sid2 = crypto.randomBytes(32);
      return [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, sessionId: sid1 }), label: 'ClientHello (session_id=A)' },
        { type: 'recv', timeout: 3000 },
        { type: 'send', data: hs.buildClientKeyExchange(), label: '[FUZZ] CKE (different session context)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'compression-method-mismatch',
    category: 'C',
    description: 'Server picks DEFLATE compression when client only offered NULL',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildServerHello({ compressionMethod: CompressionMethod.DEFLATE }), label: '[FUZZ] ServerHello (DEFLATE compression)' },
      { type: 'send', data: hs.buildCertificate(), label: 'Certificate' },
      { type: 'send', data: hs.buildServerHelloDone(), label: 'ServerHelloDone' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'sni-mismatch',
    category: 'C',
    description: 'Send ClientHello with SNI "a.com", then another with SNI "b.com"',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: 'legitimate-site.com' }), label: 'ClientHello (SNI=legitimate-site.com)' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: hs.buildClientHello({ hostname: 'malicious-site.com' }), label: '[FUZZ] ClientHello #2 (SNI=malicious-site.com)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'random-overwrite',
    category: 'C',
    description: 'Send identical ClientHello but with different random value',
    side: 'client',
    actions: (opts) => {
      const r1 = crypto.randomBytes(32);
      const r2 = crypto.randomBytes(32);
      return [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, random: r1 }), label: 'ClientHello (random=A)' },
        { type: 'recv', timeout: 3000 },
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, random: r2 }), label: '[FUZZ] ClientHello (random=B, different)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },

  // ===== Category D: Alert Injection =====
  {
    name: 'alert-during-handshake',
    category: 'D',
    description: 'Send warning alert between ClientHello and CKE',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildAlert(AlertLevel.WARNING, AlertDescription.UNEXPECTED_MESSAGE), label: '[FUZZ] Alert(warning, unexpected_message)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'fatal-alert-then-continue',
    category: 'D',
    description: 'Send fatal alert then continue handshake as if nothing happened',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildAlert(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE), label: '[FUZZ] Alert(fatal, handshake_failure)' },
      { type: 'delay', ms: 200 },
      { type: 'send', data: hs.buildClientKeyExchange(), label: '[FUZZ] CKE (after fatal alert)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'close-notify-mid-handshake',
    category: 'D',
    description: 'Send close_notify then continue with more messages',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildAlert(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY), label: '[FUZZ] Alert(close_notify)' },
      { type: 'delay', ms: 200 },
      { type: 'send', data: hs.buildClientKeyExchange(), label: '[FUZZ] CKE (after close_notify)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'unknown-alert-type',
    category: 'D',
    description: 'Send alert with undefined description code (255)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildAlert(AlertLevel.FATAL, 255), label: '[FUZZ] Alert(fatal, UNKNOWN_255)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'alert-flood',
    category: 'D',
    description: 'Rapid-fire 20 warning alerts',
    side: 'client',
    actions: (opts) => {
      const actions = [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
        { type: 'recv', timeout: 3000 },
      ];
      for (let i = 0; i < 20; i++) {
        actions.push({ type: 'send', data: buildAlert(AlertLevel.WARNING, AlertDescription.NO_RENEGOTIATION), label: `[FUZZ] Alert flood #${i + 1}` });
      }
      actions.push({ type: 'recv', timeout: 3000 });
      return actions;
    },
  },
  {
    name: 'alert-wrong-level',
    category: 'D',
    description: 'Send handshake_failure with warning level instead of fatal',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildAlert(AlertLevel.WARNING, AlertDescription.HANDSHAKE_FAILURE), label: '[FUZZ] Alert(WARNING, handshake_failure) - wrong level' },
      { type: 'recv', timeout: 3000 },
    ],
  },

  // ===== Category E: TCP Manipulation =====
  {
    name: 'fin-after-client-hello',
    category: 'E',
    description: 'Send ClientHello, then TCP FIN, then try to continue',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'fin', label: '[FUZZ] TCP FIN after ClientHello' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'fin-after-server-hello',
    category: 'E',
    description: 'Server sends ServerHello then TCP FIN then continues',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildServerHello(), label: 'ServerHello' },
      { type: 'fin', label: '[FUZZ] TCP FIN after ServerHello' },
      { type: 'delay', ms: 200 },
      { type: 'send', data: hs.buildCertificate(), label: '[FUZZ] Certificate (after FIN)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'rst-mid-handshake',
    category: 'E',
    description: 'Send ClientHello, receive response, then TCP RST',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'rst', label: '[FUZZ] TCP RST mid-handshake' },
    ],
  },
  {
    name: 'fin-from-both',
    category: 'E',
    description: 'Server sends FIN immediately after ServerHello, simulating simultaneous FIN',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildServerHello(), label: 'ServerHello' },
      { type: 'send', data: hs.buildCertificate(), label: 'Certificate' },
      { type: 'send', data: hs.buildServerHelloDone(), label: 'ServerHelloDone' },
      { type: 'fin', label: '[FUZZ] TCP FIN from server during handshake' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'half-close-continue',
    category: 'E',
    description: 'Half-close write side then send more TLS records',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'fin', label: '[FUZZ] TCP FIN (half-close)' },
      { type: 'delay', ms: 500 },
      { type: 'send', data: hs.buildClientKeyExchange(), label: '[FUZZ] CKE (after half-close)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'slow-drip-client-hello',
    category: 'E',
    description: 'Send ClientHello 1 byte at a time with delays',
    side: 'client',
    actions: (opts) => [
      { type: 'slowDrip', data: hs.buildClientHello({ hostname: opts.hostname }), bytesPerChunk: 1, delayMs: 20, label: '[FUZZ] ClientHello (slow drip, 1 byte/20ms)' },
      { type: 'recv', timeout: 10000 },
    ],
  },
  {
    name: 'split-record-across-segments',
    category: 'E',
    description: 'Fragment a ClientHello TLS record across 10 TCP segments',
    side: 'client',
    actions: (opts) => [
      { type: 'fragment', data: hs.buildClientHello({ hostname: opts.hostname }), fragments: 10, delayMs: 20, label: '[FUZZ] ClientHello (10 TCP fragments)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // ===== Category F: Record Layer Attacks =====
  {
    name: 'oversized-record',
    category: 'F',
    description: 'Send a TLS record > 16384 bytes',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildOversizedRecord(ContentType.APPLICATION_DATA, Version.TLS_1_2, 20000), label: '[FUZZ] Oversized record (20000 bytes)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'zero-length-record',
    category: 'F',
    description: 'Send a TLS record with empty payload',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildZeroLengthRecord(ContentType.HANDSHAKE), label: '[FUZZ] Zero-length handshake record' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'wrong-content-type',
    category: 'F',
    description: 'Send handshake data with application_data content type',
    side: 'client',
    actions: (opts) => {
      const ch = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsMsg = Buffer.alloc(4 + ch.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = (ch.length >> 16) & 0xff;
      hsMsg[2] = (ch.length >> 8) & 0xff;
      hsMsg[3] = ch.length & 0xff;
      ch.copy(hsMsg, 4);
      const record = buildRecord(ContentType.APPLICATION_DATA, Version.TLS_1_0, hsMsg);
      return [
        { type: 'send', data: record, label: '[FUZZ] ClientHello in ApplicationData content type' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'wrong-record-length',
    category: 'F',
    description: 'TLS record length field doesn\'t match actual payload',
    side: 'client',
    actions: (opts) => {
      const ch = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsMsg = Buffer.alloc(4 + ch.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = (ch.length >> 16) & 0xff;
      hsMsg[2] = (ch.length >> 8) & 0xff;
      hsMsg[3] = ch.length & 0xff;
      ch.copy(hsMsg, 4);
      const record = buildWrongLengthRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg, hsMsg.length + 100);
      return [
        { type: 'send', data: record, label: '[FUZZ] ClientHello with wrong record length (+100)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'interleaved-content-types',
    category: 'F',
    description: 'Mix handshake and application_data records during handshake',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildRecord(ContentType.APPLICATION_DATA, Version.TLS_1_2, Buffer.from('hello')), label: '[FUZZ] ApplicationData mid-handshake' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'record-version-mismatch',
    category: 'F',
    description: 'Record header says TLS 1.0, ClientHello body says TLS 1.2',
    side: 'client',
    actions: (opts) => {
      // This is actually common/valid (record layer uses 1.0 for compat)
      // but we invert it: record says 1.3, body says 1.0
      return [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, version: Version.TLS_1_0, recordVersion: Version.TLS_1_3 }), label: '[FUZZ] Record=TLS1.3, Body=TLS1.0 (inverted)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'multiple-handshakes-one-record',
    category: 'F',
    description: 'Pack ClientHello + ClientKeyExchange in a single TLS record',
    side: 'client',
    actions: (opts) => {
      const record = hs.buildMultiHandshakeRecord([
        { type: HandshakeType.CLIENT_HELLO, body: hs.buildClientHelloBody({ hostname: opts.hostname }) },
        { type: HandshakeType.CLIENT_KEY_EXCHANGE, body: crypto.randomBytes(130) },
      ]);
      return [
        { type: 'send', data: record, label: '[FUZZ] Multi-handshake record (CH+CKE)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'garbage-between-records',
    category: 'F',
    description: 'Random garbage bytes between valid TLS records',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildRawGarbage(64), label: '[FUZZ] 64 bytes random garbage' },
      { type: 'send', data: hs.buildClientKeyExchange(), label: 'CKE (after garbage)' },
      { type: 'recv', timeout: 3000 },
    ],
  },

  // ===== Category G: ChangeCipherSpec Attacks =====
  {
    name: 'early-ccs',
    category: 'G',
    description: 'Send ChangeCipherSpec before receiving ServerHelloDone',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'send', data: buildChangeCipherSpec(), label: '[FUZZ] CCS (immediately after ClientHello)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'multiple-ccs',
    category: 'G',
    description: 'Send ChangeCipherSpec three times in a row',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildChangeCipherSpec(), label: '[FUZZ] CCS #1' },
      { type: 'send', data: buildChangeCipherSpec(), label: '[FUZZ] CCS #2' },
      { type: 'send', data: buildChangeCipherSpec(), label: '[FUZZ] CCS #3' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'ccs-before-client-hello',
    category: 'G',
    description: 'Send ChangeCipherSpec as the very first message',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: buildChangeCipherSpec(), label: '[FUZZ] CCS (before ClientHello)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'ccs-with-payload',
    category: 'G',
    description: 'ChangeCipherSpec record with extra garbage bytes',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildChangeCipherSpecWithPayload(Version.TLS_1_2, 32), label: '[FUZZ] CCS with 32 extra bytes' },
      { type: 'recv', timeout: 3000 },
    ],
  },

  // ===== Category H: Extension Fuzzing =====
  {
    name: 'duplicate-extensions',
    category: 'H',
    description: 'ClientHello with the same extension type twice',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, duplicateExtensions: true }), label: '[FUZZ] ClientHello (duplicate SNI extension)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'unknown-extensions',
    category: 'H',
    description: 'ClientHello with unregistered extension type IDs',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: 0xfeed, data: crypto.randomBytes(16) },
          { type: 0xbeef, data: crypto.randomBytes(32) },
          { type: 0xdead, data: crypto.randomBytes(8) },
        ]
      }), label: '[FUZZ] ClientHello (unknown extensions 0xfeed, 0xbeef, 0xdead)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'oversized-extension',
    category: 'H',
    description: 'ClientHello with a 64KB extension',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: 0xffff, data: crypto.randomBytes(65000) },
        ]
      }), label: '[FUZZ] ClientHello (64KB extension)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'empty-sni',
    category: 'H',
    description: 'ClientHello with empty SNI hostname',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: '' }), label: '[FUZZ] ClientHello (empty SNI)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'malformed-supported-versions',
    category: 'H',
    description: 'ClientHello with garbage data in supported_versions extension',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.SUPPORTED_VERSIONS, data: crypto.randomBytes(37) },
        ]
      }), label: '[FUZZ] ClientHello (malformed supported_versions)' },
      { type: 'recv', timeout: 3000 },
    ],
  },

  // ===== Category I: Known Vulnerability Detection (CVEs) =====

  // --- Heartbleed (CVE-2014-0160) ---
  {
    name: 'heartbleed-cve-2014-0160',
    category: 'I',
    description: 'Heartbleed: send heartbeat with oversized payload_length to leak memory',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          // Heartbeat extension: peer_allowed_to_send (1)
          { type: ExtensionType.HEARTBEAT, data: Buffer.from([0x01]) },
        ],
      }), label: 'ClientHello (with heartbeat extension)' },
      { type: 'recv', timeout: 3000 },
      // Send heartbeat request claiming 16384 bytes but only sending 1
      { type: 'send', data: buildHeartbeatRequest(16384, 1), label: '[CVE-2014-0160] Heartbeat request (claims 16384 bytes, sends 1)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- POODLE / SSLv3 (CVE-2014-3566) ---
  {
    name: 'poodle-sslv3-cve-2014-3566',
    category: 'I',
    description: 'POODLE: attempt SSL 3.0 connection with CBC cipher',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        version: Version.SSL_3_0,
        recordVersion: Version.SSL_3_0,
        cipherSuites: [
          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
        // SSL 3.0 doesn't use supported_versions extension
        includeExtensions: false,
      }), label: '[CVE-2014-3566] ClientHello (SSL 3.0 only)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- CCS Injection (CVE-2014-0224) ---
  {
    name: 'ccs-injection-cve-2014-0224',
    category: 'I',
    description: 'CCS Injection: send CCS before key exchange to force weak keys',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      // Send CCS immediately without waiting for ServerHello
      { type: 'send', data: buildChangeCipherSpec(), label: '[CVE-2014-0224] CCS (before any key exchange)' },
      { type: 'send', data: hs.buildFinished(), label: '[CVE-2014-0224] Finished (with null keys)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- FREAK / Export RSA (CVE-2015-0204) ---
  {
    name: 'freak-export-rsa-cve-2015-0204',
    category: 'I',
    description: 'FREAK: offer only RSA export cipher suites (512-bit keys)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
          CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
          CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
        ],
      }), label: '[CVE-2015-0204] ClientHello (export RSA ciphers only)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- Logjam / Export DHE (CVE-2015-4000) ---
  {
    name: 'logjam-export-dhe-cve-2015-4000',
    category: 'I',
    description: 'Logjam: offer only DHE export cipher suites (512-bit DH)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
          CipherSuite.TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5,
          CipherSuite.TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
        ],
      }), label: '[CVE-2015-4000] ClientHello (export DHE ciphers only)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- DROWN / SSLv2 (CVE-2016-0800) ---
  {
    name: 'drown-sslv2-cve-2016-0800',
    category: 'I',
    description: 'DROWN: send SSLv2 ClientHello to check SSLv2 support',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: buildSSLv2ClientHello(), label: '[CVE-2016-0800] SSLv2 ClientHello' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- Sweet32 / 3DES (CVE-2016-2183) ---
  {
    name: 'sweet32-3des-cve-2016-2183',
    category: 'I',
    description: 'Sweet32: offer only 3DES/64-bit block cipher suites',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
          CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
      }), label: '[CVE-2016-2183] ClientHello (3DES ciphers only)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- CRIME / TLS Compression (CVE-2012-4929) ---
  {
    name: 'crime-compression-cve-2012-4929',
    category: 'I',
    description: 'CRIME: offer DEFLATE TLS compression to check if server accepts',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        compressionMethods: [CompressionMethod.DEFLATE, CompressionMethod.NULL],
      }), label: '[CVE-2012-4929] ClientHello (DEFLATE + NULL compression)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- RC4 Bias attacks (CVE-2013-2566 / CVE-2015-2808) ---
  {
    name: 'rc4-bias-cve-2013-2566',
    category: 'I',
    description: 'RC4 Bias: offer only RC4 cipher suites',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
          CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
        ],
      }), label: '[CVE-2013-2566] ClientHello (RC4 ciphers only)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- BEAST / TLS 1.0 CBC (CVE-2011-3389) ---
  {
    name: 'beast-cbc-tls10-cve-2011-3389',
    category: 'I',
    description: 'BEAST: offer TLS 1.0 with only CBC cipher suites',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        version: Version.TLS_1_0,
        recordVersion: Version.TLS_1_0,
        cipherSuites: [
          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
        // Only advertise TLS 1.0
        extraExtensions: [
          { type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x01]) },
        ],
      }), label: '[CVE-2011-3389] ClientHello (TLS 1.0 + CBC only)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- Insecure Renegotiation (CVE-2009-3555) ---
  {
    name: 'insecure-renegotiation-cve-2009-3555',
    category: 'I',
    description: 'Test for insecure TLS renegotiation by omitting renegotiation_info',
    side: 'client',
    actions: (opts) => {
      // Build ClientHello WITHOUT renegotiation_info extension and without SCSV
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          cipherSuites: [
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
          ],
          // Note: default builder includes renegotiation_info; we rely on server response check
        }), label: '[CVE-2009-3555] ClientHello (checking renegotiation support)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },

  // --- TLS Fallback SCSV (RFC 7507) ---
  {
    name: 'tls-fallback-scsv-downgrade',
    category: 'I',
    description: 'Downgrade detection: send TLS 1.1 ClientHello with TLS_FALLBACK_SCSV',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        version: Version.TLS_1_1,
        recordVersion: Version.TLS_1_0,
        cipherSuites: [
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_FALLBACK_SCSV,
        ],
        extraExtensions: [
          { type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x02]) }, // only TLS 1.1
        ],
      }), label: '[RFC 7507] ClientHello (TLS 1.1 + FALLBACK_SCSV)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- NULL cipher suites ---
  {
    name: 'null-cipher-suites',
    category: 'I',
    description: 'Offer only NULL encryption cipher suites (no encryption)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_RSA_WITH_NULL_SHA,
          CipherSuite.TLS_RSA_WITH_NULL_SHA256,
          CipherSuite.TLS_RSA_WITH_NULL_MD5,
        ],
      }), label: '[VULN] ClientHello (NULL ciphers only — no encryption)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- Anonymous DH (no authentication) ---
  {
    name: 'anon-dh-no-auth',
    category: 'I',
    description: 'Offer only anonymous DH cipher suites (no server authentication)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_DH_ANON_WITH_AES_256_CBC_SHA,
          CipherSuite.TLS_DH_ANON_WITH_RC4_128_MD5,
        ],
      }), label: '[VULN] ClientHello (anonymous DH — no auth)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- DES (weak cipher, 56-bit key) ---
  {
    name: 'des-weak-cipher',
    category: 'I',
    description: 'Offer only DES cipher (56-bit key, trivially breakable)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_RSA_WITH_DES_CBC_SHA,
        ],
      }), label: '[VULN] ClientHello (DES only — 56-bit)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // --- Ticketbleed (CVE-2016-9244) ---
  {
    name: 'ticketbleed-cve-2016-9244',
    category: 'I',
    description: 'Ticketbleed: send session ticket with non-standard length to leak memory',
    side: 'client',
    actions: (opts) => {
      // Send a ClientHello with a 1-byte session ID (non-standard for ticket resumption)
      // then follow up with the actual ticket in extension
      const fakeTicket = crypto.randomBytes(1); // Ticketbleed uses short ticket to leak memory
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          sessionId: fakeTicket, // 1-byte session ID instead of 0 or 32
          extraExtensions: [
            { type: ExtensionType.SESSION_TICKET, data: crypto.randomBytes(128) },
          ],
        }), label: '[CVE-2016-9244] ClientHello (1-byte session ID + session ticket)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },

  // ===== Category J: Post-Quantum Cryptography (PQC) Fuzzing =====

  {
    name: 'pqc-hybrid-x25519-mlkem768',
    category: 'J',
    description: 'Send ClientHello with X25519+ML-KEM-768 hybrid key share (1216 bytes)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.KEY_SHARE, data: hs.buildPQCKeyShareExtension([
            { group: NamedGroup.X25519_MLKEM768, keySize: 1216 }, // 32 X25519 + 1184 ML-KEM-768
          ]) },
          { type: ExtensionType.SUPPORTED_GROUPS, data: (() => {
            const groups = [NamedGroup.X25519_MLKEM768, NamedGroup.X25519, NamedGroup.SECP256R1];
            const buf = Buffer.alloc(2 + groups.length * 2);
            buf.writeUInt16BE(groups.length * 2, 0);
            groups.forEach((g, i) => buf.writeUInt16BE(g, 2 + i * 2));
            return buf;
          })() },
        ],
      }), label: '[PQC] ClientHello (X25519+ML-KEM-768 hybrid, 1216B key share)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'pqc-standalone-mlkem768',
    category: 'J',
    description: 'Send ClientHello with standalone ML-KEM-768 key share (1184 bytes)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.KEY_SHARE, data: hs.buildPQCKeyShareExtension([
            { group: NamedGroup.MLKEM768, keySize: 1184 },
          ]) },
          { type: ExtensionType.SUPPORTED_GROUPS, data: (() => {
            const groups = [NamedGroup.MLKEM768, NamedGroup.X25519, NamedGroup.SECP256R1];
            const buf = Buffer.alloc(2 + groups.length * 2);
            buf.writeUInt16BE(groups.length * 2, 0);
            groups.forEach((g, i) => buf.writeUInt16BE(g, 2 + i * 2));
            return buf;
          })() },
        ],
      }), label: '[PQC] ClientHello (standalone ML-KEM-768, 1184B key share)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'pqc-kyber-draft-chrome',
    category: 'J',
    description: 'Send ClientHello with X25519Kyber768 draft group ID (Chrome experimental)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.KEY_SHARE, data: hs.buildPQCKeyShareExtension([
            { group: NamedGroup.X25519_KYBER768_DRAFT, keySize: 1216 },
          ]) },
          { type: ExtensionType.SUPPORTED_GROUPS, data: (() => {
            const groups = [NamedGroup.X25519_KYBER768_DRAFT, NamedGroup.X25519, NamedGroup.SECP256R1];
            const buf = Buffer.alloc(2 + groups.length * 2);
            buf.writeUInt16BE(groups.length * 2, 0);
            groups.forEach((g, i) => buf.writeUInt16BE(g, 2 + i * 2));
            return buf;
          })() },
        ],
      }), label: '[PQC] ClientHello (X25519Kyber768 draft 0x6399)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'pqc-malformed-key-share',
    category: 'J',
    description: 'Send PQC key share with wrong size (should be 1184, send 100)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.KEY_SHARE, data: hs.buildPQCKeyShareExtension([
            { group: NamedGroup.X25519_MLKEM768, keySize: 100 }, // Should be 1216, sending 100
          ]) },
        ],
      }), label: '[PQC] ClientHello (malformed ML-KEM key share, 100B instead of 1216B)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'pqc-oversized-key-share',
    category: 'J',
    description: 'Send enormously oversized PQC key share (10KB) to test buffer handling',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.KEY_SHARE, data: hs.buildPQCKeyShareExtension([
            { group: NamedGroup.X25519_MLKEM768, keySize: 10000 },
          ]) },
        ],
      }), label: '[PQC] ClientHello (oversized key share, 10KB)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'pqc-multiple-key-shares',
    category: 'J',
    description: 'Send multiple PQC key shares: hybrid + standalone + classical',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.KEY_SHARE, data: hs.buildPQCKeyShareExtension([
            { group: NamedGroup.X25519_MLKEM768, keySize: 1216 },
            { group: NamedGroup.MLKEM768, keySize: 1184 },
            { group: NamedGroup.X25519, keySize: 32 },
            { group: NamedGroup.SECP256R1, keySize: 65 },
          ]) },
          { type: ExtensionType.SUPPORTED_GROUPS, data: (() => {
            const groups = [NamedGroup.X25519_MLKEM768, NamedGroup.MLKEM768, NamedGroup.X25519, NamedGroup.SECP256R1];
            const buf = Buffer.alloc(2 + groups.length * 2);
            buf.writeUInt16BE(groups.length * 2, 0);
            groups.forEach((g, i) => buf.writeUInt16BE(g, 2 + i * 2));
            return buf;
          })() },
        ],
      }), label: '[PQC] ClientHello (4 key shares: hybrid + standalone + classical)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'pqc-unknown-group-ids',
    category: 'J',
    description: 'Advertise only unregistered PQC named group IDs',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.KEY_SHARE, data: hs.buildPQCKeyShareExtension([
            { group: 0xff01, keySize: 800 },  // Unknown group
            { group: 0xff02, keySize: 1568 },  // Unknown group
          ]) },
          { type: ExtensionType.SUPPORTED_GROUPS, data: (() => {
            const groups = [0xff01, 0xff02, 0xff03];
            const buf = Buffer.alloc(2 + groups.length * 2);
            buf.writeUInt16BE(groups.length * 2, 0);
            groups.forEach((g, i) => buf.writeUInt16BE(g, 2 + i * 2));
            return buf;
          })() },
        ],
      }), label: '[PQC] ClientHello (unknown PQC group IDs 0xff01-ff03)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'pqc-mlkem1024-large',
    category: 'J',
    description: 'Send ML-KEM-1024 key share (1568 bytes, highest security level)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.KEY_SHARE, data: hs.buildPQCKeyShareExtension([
            { group: NamedGroup.MLKEM1024, keySize: 1568 },
            { group: NamedGroup.X25519, keySize: 32 },
          ]) },
          { type: ExtensionType.SUPPORTED_GROUPS, data: (() => {
            const groups = [NamedGroup.MLKEM1024, NamedGroup.X25519, NamedGroup.SECP256R1];
            const buf = Buffer.alloc(2 + groups.length * 2);
            buf.writeUInt16BE(groups.length * 2, 0);
            groups.forEach((g, i) => buf.writeUInt16BE(g, 2 + i * 2));
            return buf;
          })() },
        ],
      }), label: '[PQC] ClientHello (ML-KEM-1024, 1568B key share)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // ===== Category K: SNI Evasion & Fragmentation =====

  {
    name: 'sni-not-in-first-packet',
    category: 'K',
    description: 'Fragment ClientHello so SNI hostname is in the 2nd TCP segment',
    side: 'client',
    actions: (opts) => {
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      // Split at byte 50 — record header(5) + hs header(4) + version(2) + partial random
      // SNI is in extensions, well past byte 50
      const frag1 = ch.slice(0, 50);
      const frag2 = ch.slice(50);
      return [
        { type: 'send', data: frag1, label: '[SNI-EVASION] ClientHello fragment 1 (50B, no SNI)' },
        { type: 'delay', ms: 100 },
        { type: 'send', data: frag2, label: '[SNI-EVASION] ClientHello fragment 2 (contains SNI)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'sni-split-at-hostname',
    category: 'K',
    description: 'Split the ClientHello right in the middle of the SNI hostname string',
    side: 'client',
    actions: (opts) => {
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      // Find the hostname bytes in the buffer
      const hostnameBytes = Buffer.from(opts.hostname || 'localhost', 'ascii');
      const hostnameOffset = ch.indexOf(hostnameBytes);
      if (hostnameOffset > 0) {
        // Split right in the middle of the hostname
        const splitPoint = hostnameOffset + Math.floor(hostnameBytes.length / 2);
        const frag1 = ch.slice(0, splitPoint);
        const frag2 = ch.slice(splitPoint);
        return [
          { type: 'send', data: frag1, label: `[SNI-EVASION] Fragment 1 (splits hostname at byte ${splitPoint})` },
          { type: 'delay', ms: 50 },
          { type: 'send', data: frag2, label: '[SNI-EVASION] Fragment 2 (rest of hostname + data)' },
          { type: 'recv', timeout: 5000 },
        ];
      }
      // Fallback: simple fragment
      return [
        { type: 'send', data: ch.slice(0, 80), label: '[SNI-EVASION] Fragment 1' },
        { type: 'delay', ms: 50 },
        { type: 'send', data: ch.slice(80), label: '[SNI-EVASION] Fragment 2' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'sni-tiny-fragments',
    category: 'K',
    description: 'Fragment ClientHello into 1-byte TCP segments to evade SNI inspection',
    side: 'client',
    actions: (opts) => [
      { type: 'slowDrip', data: hs.buildClientHello({ hostname: opts.hostname }), bytesPerChunk: 1, delayMs: 5, label: '[SNI-EVASION] ClientHello (1 byte at a time)' },
      { type: 'recv', timeout: 15000 },
    ],
  },
  {
    name: 'sni-multiple-hostnames',
    category: 'K',
    description: 'SNI extension with multiple server_name entries (different hostnames)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: 'dummy.invalid', // Will be overridden by extraExtensions
        extraExtensions: [
          { type: ExtensionType.SERVER_NAME, data: hs.buildMultiSNIExtension([
            opts.hostname || 'legitimate.com',
            'evil-site.com',
            'another-host.net',
          ]) },
        ],
      }), label: '[SNI-EVASION] ClientHello (3 hostnames in SNI)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'sni-ip-address',
    category: 'K',
    description: 'SNI extension with an IP address instead of hostname',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: '192.168.1.1',
      }), label: '[SNI-EVASION] ClientHello (SNI = 192.168.1.1)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'sni-oversized-hostname',
    category: 'K',
    description: 'SNI with extremely long hostname (500 chars)',
    side: 'client',
    actions: (opts) => {
      const longHost = 'a'.repeat(63) + '.' + 'b'.repeat(63) + '.' + 'c'.repeat(63) + '.' + 'd'.repeat(63) + '.' + 'e'.repeat(63) + '.' + 'f'.repeat(63) + '.' + 'g'.repeat(63) + '.com';
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: longHost,
        }), label: `[SNI-EVASION] ClientHello (SNI hostname ${longHost.length} chars)` },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'sni-record-header-fragment',
    category: 'K',
    description: 'Send only the 5-byte TLS record header first, then the rest',
    side: 'client',
    actions: (opts) => {
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'send', data: ch.slice(0, 5), label: '[SNI-EVASION] TLS record header only (5 bytes)' },
        { type: 'delay', ms: 200 },
        { type: 'send', data: ch.slice(5), label: '[SNI-EVASION] Rest of ClientHello (body with SNI)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'sni-prepend-garbage-record',
    category: 'K',
    description: 'Send a garbage TLS record before the real ClientHello to confuse parsers',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: buildRawGarbage(10), label: '[SNI-EVASION] 10 bytes garbage before ClientHello' },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello (after garbage)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // ===== Category L: ALPN Protocol Confusion =====

  {
    name: 'alpn-mismatch-server',
    category: 'L',
    description: 'Server selects ALPN "h2" when client only offered "http/1.1"',
    side: 'server',
    actions: (opts) => [
      { type: 'recv', timeout: 5000 },
      { type: 'send', data: hs.buildServerHello({
        extraExtensions: [
          { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: hs.buildALPNExtension(['h2']) },
        ],
      }), label: '[ALPN] ServerHello (ALPN=h2, but client offered http/1.1)' },
      { type: 'send', data: hs.buildCertificate(), label: 'Certificate' },
      { type: 'send', data: hs.buildServerHelloDone(), label: 'ServerHelloDone' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'alpn-unknown-protocols',
    category: 'L',
    description: 'ClientHello with ALPN listing unknown/invented protocol IDs',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: hs.buildALPNExtension([
            'quantum-proto/1.0',
            'fake-protocol/2.0',
            'nonexistent/0.1',
          ]) },
        ],
      }), label: '[ALPN] ClientHello (unknown protocols: quantum-proto, fake-protocol, nonexistent)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'alpn-empty-protocol',
    category: 'L',
    description: 'ClientHello with ALPN containing empty protocol string',
    side: 'client',
    actions: (opts) => {
      // Manually build ALPN with empty protocol string
      const alpnData = Buffer.from([0x00, 0x01, 0x00]); // list_len=1, proto_len=0
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: alpnData },
          ],
        }), label: '[ALPN] ClientHello (empty protocol string in ALPN)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'alpn-oversized-list',
    category: 'L',
    description: 'ClientHello with ALPN listing 50 protocol entries',
    side: 'client',
    actions: (opts) => {
      const protocols = [];
      for (let i = 0; i < 50; i++) protocols.push(`proto-${i.toString(36).padStart(3, '0')}`);
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: hs.buildALPNExtension(protocols) },
          ],
        }), label: '[ALPN] ClientHello (50 protocol entries in ALPN)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'alpn-duplicate-protocols',
    category: 'L',
    description: 'ClientHello with ALPN listing "h2" five times',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: hs.buildALPNExtension([
            'h2', 'h2', 'h2', 'h2', 'h2',
          ]) },
        ],
      }), label: '[ALPN] ClientHello (h2 repeated 5 times)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'alpn-very-long-name',
    category: 'L',
    description: 'ClientHello with ALPN protocol name of 255 bytes (max)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: hs.buildALPNExtension([
            'x'.repeat(255),
            'h2',
          ]) },
        ],
      }), label: '[ALPN] ClientHello (255-byte protocol name + h2)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'alpn-wrong-list-length',
    category: 'L',
    description: 'ALPN extension with protocol_name_list length exceeding actual data',
    side: 'client',
    actions: (opts) => {
      // Build ALPN with wrong length: claim 100 bytes but only have 4
      const alpnData = Buffer.alloc(6);
      alpnData.writeUInt16BE(100, 0); // claim 100 bytes
      alpnData[2] = 2;               // proto_len = 2
      alpnData[3] = 0x68; alpnData[4] = 0x32; // "h2"
      alpnData[5] = 0x00; // padding
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: alpnData },
          ],
        }), label: '[ALPN] ClientHello (ALPN list_length=100, actual=4)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },

  // ===== Category M: Extension Malformation & Placement =====

  {
    name: 'ext-sni-wrong-length-short',
    category: 'M',
    description: 'SNI extension with length field shorter than actual data',
    side: 'client',
    actions: (opts) => {
      const hostname = opts.hostname || 'example.com';
      const nameBytes = Buffer.from(hostname, 'ascii');
      // Build SNI but lie about the server_name_list length
      const sniData = Buffer.alloc(2 + 1 + 2 + nameBytes.length);
      sniData.writeUInt16BE(3, 0); // claim only 3 bytes, but sending more
      sniData[2] = 0;
      sniData.writeUInt16BE(nameBytes.length, 3);
      nameBytes.copy(sniData, 5);
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: 'dummy',
          extraExtensions: [
            { type: ExtensionType.SERVER_NAME, data: sniData },
          ],
        }), label: '[MALFORM] ClientHello (SNI inner length too short)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'ext-sni-wrong-length-long',
    category: 'M',
    description: 'SNI extension with length field longer than actual data',
    side: 'client',
    actions: (opts) => {
      const hostname = opts.hostname || 'example.com';
      const nameBytes = Buffer.from(hostname, 'ascii');
      const sniData = Buffer.alloc(2 + 1 + 2 + nameBytes.length);
      sniData.writeUInt16BE(500, 0); // claim 500 bytes, actually much less
      sniData[2] = 0;
      sniData.writeUInt16BE(nameBytes.length, 3);
      nameBytes.copy(sniData, 5);
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: 'dummy',
          extraExtensions: [
            { type: ExtensionType.SERVER_NAME, data: sniData },
          ],
        }), label: '[MALFORM] ClientHello (SNI inner length=500, actual=much less)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'ext-truncated-key-share',
    category: 'M',
    description: 'key_share extension truncated mid-key data',
    side: 'client',
    actions: (opts) => {
      // Build a key_share that claims 32-byte key but only provides 10
      const buf = Buffer.alloc(2 + 2 + 2 + 10);
      buf.writeUInt16BE(2 + 2 + 32, 0); // client_shares length (claims 36 bytes total)
      buf.writeUInt16BE(NamedGroup.X25519, 2);
      buf.writeUInt16BE(32, 4); // key_exchange_length = 32
      crypto.randomBytes(10).copy(buf, 6); // only 10 bytes of key data
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.KEY_SHARE, data: buf },
          ],
        }), label: '[MALFORM] ClientHello (truncated key_share: claims 32B, sends 10B)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'ext-supported-versions-garbage',
    category: 'M',
    description: 'supported_versions with odd-length (invalid version entries)',
    side: 'client',
    actions: (opts) => {
      // versions should be 2 bytes each, but we send 3 bytes (1.5 versions)
      const svData = Buffer.from([0x03, 0x03, 0x03, 0x01]); // length=3, then 3 bytes of "versions"
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.SUPPORTED_VERSIONS, data: svData },
          ],
        }), label: '[MALFORM] ClientHello (supported_versions odd length)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'ext-sig-algs-zero-length',
    category: 'M',
    description: 'signature_algorithms extension with zero algorithms listed',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.SIGNATURE_ALGORITHMS, data: Buffer.from([0x00, 0x00]) }, // 0 algorithms
        ],
      }), label: '[MALFORM] ClientHello (empty signature_algorithms)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'ext-extensions-total-length-mismatch',
    category: 'M',
    description: 'Extensions block with total length not matching actual extension data',
    side: 'client',
    actions: (opts) => {
      // Build a normal ClientHello body, then corrupt the extensions_length field
      const body = hs.buildClientHelloBody({ hostname: opts.hostname });
      // Find extensions_length (2 bytes before the extensions data)
      // It's after: version(2) + random(32) + sid_len(1) + sid(32) + cs_len(2) + cs(N) + comp_len(1) + comp(N)
      // Easier: just corrupt the last 2 bytes before extensions start
      // The extensions_length is at a known offset; let's corrupt it
      const corrupted = Buffer.from(body);
      // Find where extensions start by scanning for the extension length field
      // For simplicity, just add 200 to whatever the extensions_length says
      const extLenOffset = body.length - 2 - (body.readUInt16BE(body.length - 2) > body.length ? 0 : body.readUInt16BE(body.length - body.length));
      // Simpler approach: build record from scratch with wrong length
      const chRecord = hs.buildClientHello({ hostname: opts.hostname });
      const mutated = Buffer.from(chRecord);
      // Corrupt extensions length: add 200 to the 2 bytes at the position
      // The extensions length is right after compression methods
      // Just corrupt 2 bytes near the end of the header region
      // Position: 5(record) + 4(hs) + 2(ver) + 32(rand) + 1+32(sid) + 2+26(cs) + 1+1(comp) = ~106
      // Then 2 bytes = extensions length
      // Let's find it properly by building just the body
      const bodyBuf = hs.buildClientHelloBody({ hostname: opts.hostname });
      // Read the extensions length (last big chunk)
      // Walk: 2(ver) + 32(random) + 1(sid_len) + sid_len + 2(cs_len) + cs_len*2 + 1(comp_len) + comp_len
      let off = 2 + 32;
      const sidLen = bodyBuf[off]; off += 1 + sidLen;
      const csLen = bodyBuf.readUInt16BE(off); off += 2 + csLen;
      const compLen = bodyBuf[off]; off += 1 + compLen;
      // off now points to extensions_length
      const mutBody = Buffer.from(bodyBuf);
      const realExtLen = mutBody.readUInt16BE(off);
      mutBody.writeUInt16BE(realExtLen + 200, off); // claim 200 extra bytes
      const record = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0,
        Buffer.concat([Buffer.from([HandshakeType.CLIENT_HELLO, (mutBody.length >> 16) & 0xff, (mutBody.length >> 8) & 0xff, mutBody.length & 0xff]), mutBody]));
      return [
        { type: 'send', data: record, label: '[MALFORM] ClientHello (extensions_length += 200)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'ext-in-cke-message',
    category: 'M',
    description: 'Embed ClientHello extensions inside a ClientKeyExchange message',
    side: 'client',
    actions: (opts) => {
      // Build a CKE that contains extension-like data after the key material
      const keyData = crypto.randomBytes(128);
      const sniExt = hs.buildExtension(ExtensionType.SERVER_NAME, hs.buildSNIExtension(opts.hostname || 'evil.com'));
      const body = Buffer.concat([
        Buffer.from([(keyData.length >> 8) & 0xff, keyData.length & 0xff]),
        keyData,
        Buffer.from([0x00, sniExt.length >> 8, sniExt.length & 0xff]),
        sniExt,
      ]);
      const record = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2,
        Buffer.concat([Buffer.from([HandshakeType.CLIENT_KEY_EXCHANGE, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]), body]));
      return [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
        { type: 'recv', timeout: 3000 },
        { type: 'send', data: record, label: '[MALFORM] CKE with embedded SNI extension data' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'ext-nested-malformed-sni',
    category: 'M',
    description: 'SNI extension with valid outer length but corrupted inner structure',
    side: 'client',
    actions: (opts) => {
      // Valid outer extension length, but inner data is garbage
      const garbageInner = crypto.randomBytes(30);
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: 'dummy',
          extraExtensions: [
            { type: ExtensionType.SERVER_NAME, data: garbageInner },
          ],
        }), label: '[MALFORM] ClientHello (SNI with garbage inner structure)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'ext-all-unknown-critical',
    category: 'M',
    description: 'ClientHello with only unregistered extension types and no required ones',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        includeExtensions: false,
        extraExtensions: [
          { type: 0xaaaa, data: crypto.randomBytes(10) },
          { type: 0xbbbb, data: crypto.randomBytes(20) },
          { type: 0xcccc, data: crypto.randomBytes(30) },
        ],
      }), label: '[MALFORM] ClientHello (only unknown extension types, no SNI/sig_algs)' },
      { type: 'recv', timeout: 5000 },
    ],
  },
  {
    name: 'ext-groups-mismatch-key-share',
    category: 'M',
    description: 'supported_groups lists X25519 but key_share provides P-384 key',
    side: 'client',
    actions: (opts) => {
      // supported_groups says X25519 only, but key_share sends SECP384R1
      const groupsData = Buffer.alloc(2 + 2);
      groupsData.writeUInt16BE(2, 0);
      groupsData.writeUInt16BE(NamedGroup.X25519, 2);
      const keyShareData = hs.buildPQCKeyShareExtension([
        { group: NamedGroup.SECP384R1, keySize: 97 }, // P-384 uncompressed point
      ]);
      return [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.SUPPORTED_GROUPS, data: groupsData },
            { type: ExtensionType.KEY_SHARE, data: keyShareData },
          ],
        }), label: '[MALFORM] ClientHello (supported_groups=X25519, key_share=P-384)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'ext-encrypt-then-mac-with-aead',
    category: 'M',
    description: 'Send encrypt_then_mac extension while only offering AEAD ciphers',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_AES_128_GCM_SHA256,
          CipherSuite.TLS_AES_256_GCM_SHA384,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        extraExtensions: [
          { type: ExtensionType.ENCRYPT_THEN_MAC, data: Buffer.alloc(0) },
        ],
      }), label: '[MALFORM] ClientHello (encrypt_then_mac with AEAD-only ciphers)' },
      { type: 'recv', timeout: 5000 },
    ],
  },

  // ===== Category N: TCP/TLS Parameter Reneging =====

  {
    name: 'ccs-then-plaintext-handshake',
    category: 'N',
    description: 'Send CCS (signaling cipher activated) then send Finished as plaintext',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildChangeCipherSpec(), label: 'ChangeCipherSpec' },
      { type: 'send', data: hs.buildFinished(), label: '[FUZZ] Finished (plaintext after CCS — should be encrypted)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'renegotiation-downgrade-version',
    category: 'N',
    description: 'ClientHello with TLS 1.2, then renegotiation ClientHello advertising only TLS 1.0',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, version: Version.TLS_1_2 }), label: 'ClientHello (TLS 1.2)' },
      { type: 'recv', timeout: 3000 },
      { type: 'delay', ms: 200 },
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        version: Version.TLS_1_0,
        recordVersion: Version.TLS_1_0,
        extraExtensions: [
          { type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x01]) },
        ],
      }), label: '[FUZZ] Renegotiation ClientHello (downgrade to TLS 1.0)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'renegotiation-downgrade-cipher',
    category: 'N',
    description: 'Initial ClientHello with strong ciphers, renegotiation ClientHello only offering weak/export ciphers',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello (strong ciphers)' },
      { type: 'recv', timeout: 3000 },
      { type: 'delay', ms: 200 },
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
          CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_NULL_SHA,
        ],
      }), label: '[FUZZ] Renegotiation ClientHello (export/NULL ciphers only)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'renegotiation-drop-extensions',
    category: 'N',
    description: 'Initial ClientHello with all extensions, renegotiation strips renegotiation_info and security extensions',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello (full extensions)' },
      { type: 'recv', timeout: 3000 },
      { type: 'delay', ms: 200 },
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        includeExtensions: false,
      }), label: '[FUZZ] Renegotiation ClientHello (no extensions — stripped renegotiation_info)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'supported-groups-change-retry',
    category: 'N',
    description: 'ClientHello lists X25519+P-256, retry ClientHello lists only FFDHE2048',
    side: 'client',
    actions: (opts) => {
      const groupsData = Buffer.alloc(2 + 2);
      groupsData.writeUInt16BE(2, 0);
      groupsData.writeUInt16BE(NamedGroup.FFDHE2048, 2);
      return [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello (X25519 + P-256)' },
        { type: 'recv', timeout: 3000 },
        { type: 'delay', ms: 200 },
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.SUPPORTED_GROUPS, data: groupsData },
          ],
        }), label: '[FUZZ] Retry ClientHello (supported_groups changed to FFDHE2048 only)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'key-share-group-switch',
    category: 'N',
    description: 'First ClientHello key_share offers X25519, second offers P-384 (mismatched groups)',
    side: 'client',
    actions: (opts) => {
      const p384KeyShare = hs.buildPQCKeyShareExtension([
        { group: NamedGroup.SECP384R1, keySize: 97 },
      ]);
      return [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello (key_share=X25519)' },
        { type: 'recv', timeout: 3000 },
        { type: 'delay', ms: 200 },
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.KEY_SHARE, data: p384KeyShare },
          ],
        }), label: '[FUZZ] Retry ClientHello (key_share switched to P-384)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'version-oscillation-across-records',
    category: 'N',
    description: 'Send multiple records alternating version fields (TLS 1.2, TLS 1.0, TLS 1.2, SSL 3.0)',
    side: 'client',
    actions: (opts) => {
      const ch = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsMsg = Buffer.alloc(4 + ch.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = (ch.length >> 16) & 0xff;
      hsMsg[2] = (ch.length >> 8) & 0xff;
      hsMsg[3] = ch.length & 0xff;
      ch.copy(hsMsg, 4);
      const record1 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, hsMsg);
      const record2 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, crypto.randomBytes(10));
      const record3 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, crypto.randomBytes(10));
      const record4 = buildRecord(ContentType.HANDSHAKE, Version.SSL_3_0, crypto.randomBytes(10));
      return [
        { type: 'send', data: record1, label: 'ClientHello record (version=TLS 1.2)' },
        { type: 'send', data: record2, label: '[FUZZ] Handshake record (version=TLS 1.0)' },
        { type: 'send', data: record3, label: '[FUZZ] Handshake record (version=TLS 1.2)' },
        { type: 'send', data: record4, label: '[FUZZ] Handshake record (version=SSL 3.0)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'cipher-suite-set-mutation-retry',
    category: 'N',
    description: 'First ClientHello offers ECDHE+AES ciphers, second offers completely different set (RSA+CBC only)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
          CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ],
      }), label: 'ClientHello (ECDHE+AES ciphers)' },
      { type: 'recv', timeout: 3000 },
      { type: 'delay', ms: 200 },
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
      }), label: '[FUZZ] Retry ClientHello (RSA+CBC only — completely different cipher set)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'record-version-renege-post-hello',
    category: 'N',
    description: 'ClientHello record says TLS 1.0 (normal), all subsequent records say TLS 1.3',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, recordVersion: Version.TLS_1_0 }), label: 'ClientHello (record version=TLS 1.0, normal)' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: hs.buildClientKeyExchange({ recordVersion: Version.TLS_1_3 }), label: '[FUZZ] CKE (record version switched to TLS 1.3)' },
      { type: 'send', data: buildChangeCipherSpec(Version.TLS_1_3), label: '[FUZZ] CCS (record version=TLS 1.3)' },
      { type: 'send', data: hs.buildFinished({ recordVersion: Version.TLS_1_3 }), label: '[FUZZ] Finished (record version=TLS 1.3)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'compression-renege-post-negotiation',
    category: 'N',
    description: 'Offer NULL compression initially, then renegotiation ClientHello offers DEFLATE',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname, compressionMethods: [CompressionMethod.NULL] }), label: 'ClientHello (compression=NULL)' },
      { type: 'recv', timeout: 3000 },
      { type: 'delay', ms: 200 },
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        compressionMethods: [CompressionMethod.DEFLATE],
      }), label: '[FUZZ] Renegotiation ClientHello (compression=DEFLATE — changed from NULL)' },
      { type: 'recv', timeout: 3000 },
    ],
  },

  // ===== Category O: TLS 1.3 Early Data & 0-RTT Fuzzing =====

  {
    name: 'tls13-early-data-no-psk',
    category: 'O',
    description: 'ClientHello with early_data extension but WITHOUT pre_shared_key (invalid)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.EARLY_DATA, data: hs.buildEarlyDataExtension() },
        ],
      }), label: '[FUZZ] ClientHello (early_data without pre_shared_key)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-garbage-early-data',
    category: 'O',
    description: 'ClientHello with early_data + send random garbage as application_data records',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.EARLY_DATA, data: hs.buildEarlyDataExtension() },
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension() },
        ],
      }), label: 'ClientHello (early_data + fake PSK)' },
      { type: 'send', data: buildRecord(ContentType.APPLICATION_DATA, Version.TLS_1_2, crypto.randomBytes(256)), label: '[FUZZ] Early data: 256 bytes garbage application_data' },
      { type: 'send', data: buildRecord(ContentType.APPLICATION_DATA, Version.TLS_1_2, crypto.randomBytes(128)), label: '[FUZZ] Early data: 128 bytes garbage application_data' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-early-data-wrong-content-type',
    category: 'O',
    description: 'Send early data using HANDSHAKE content type instead of APPLICATION_DATA',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.EARLY_DATA, data: hs.buildEarlyDataExtension() },
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension() },
        ],
      }), label: 'ClientHello (early_data + fake PSK)' },
      { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, crypto.randomBytes(128)), label: '[FUZZ] Early data in HANDSHAKE content type (should be APPLICATION_DATA)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-fake-psk-binder',
    category: 'O',
    description: 'ClientHello with pre_shared_key extension containing garbage binder hash',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension({ binderLength: 32 }) },
        ],
      }), label: '[FUZZ] ClientHello (PSK with garbage binder hash)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-psk-identity-overflow',
    category: 'O',
    description: 'PSK identity with length field claiming more bytes than provided',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension({ overflowIdentity: true }) },
        ],
      }), label: '[FUZZ] ClientHello (PSK identity length overflow)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-early-data-oversized',
    category: 'O',
    description: 'Send 100KB of garbage as early application data (exceeds typical max_early_data_size)',
    side: 'client',
    actions: (opts) => {
      const actions = [
        { type: 'send', data: hs.buildClientHello({
          hostname: opts.hostname,
          extraExtensions: [
            { type: ExtensionType.EARLY_DATA, data: hs.buildEarlyDataExtension() },
            { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
            { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension() },
          ],
        }), label: 'ClientHello (early_data + fake PSK)' },
      ];
      for (let i = 0; i < 10; i++) {
        actions.push({
          type: 'send',
          data: buildRecord(ContentType.APPLICATION_DATA, Version.TLS_1_2, crypto.randomBytes(10000)),
          label: `[FUZZ] Oversized early data chunk ${i + 1}/10 (10KB)`,
        });
      }
      actions.push({ type: 'recv', timeout: 5000 });
      return actions;
    },
  },
  {
    name: 'tls13-early-data-before-client-hello',
    category: 'O',
    description: 'Send application data records BEFORE the ClientHello message',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: buildRecord(ContentType.APPLICATION_DATA, Version.TLS_1_2, crypto.randomBytes(64)), label: '[FUZZ] Application data BEFORE ClientHello' },
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.EARLY_DATA, data: hs.buildEarlyDataExtension() },
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension() },
        ],
      }), label: 'ClientHello (early_data + fake PSK)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-multiple-psk-binders-mismatch',
    category: 'O',
    description: 'PSK extension with 2 identities but 3 binders (count mismatch)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension({ identityCount: 2, binderCount: 3 }) },
        ],
      }), label: '[FUZZ] ClientHello (PSK: 2 identities, 3 binders — mismatch)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-early-data-wrong-version',
    category: 'O',
    description: 'Early data records with SSL 3.0 version in record header',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.EARLY_DATA, data: hs.buildEarlyDataExtension() },
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension() },
        ],
      }), label: 'ClientHello (early_data + fake PSK)' },
      { type: 'send', data: buildRecord(ContentType.APPLICATION_DATA, Version.SSL_3_0, crypto.randomBytes(64)), label: '[FUZZ] Early data with SSL 3.0 record version' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-psk-with-incompatible-cipher',
    category: 'O',
    description: 'PSK identity (AES-128-GCM) but ClientHello only offers ChaCha20',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        cipherSuites: [
          CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        ],
        extraExtensions: [
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension() },
        ],
      }), label: '[FUZZ] ClientHello (PSK for AES-128-GCM, but only offers ChaCha20)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-end-of-early-data-without-early-data',
    category: 'O',
    description: 'Send EndOfEarlyData handshake message without having sent early_data extension',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello (no early_data extension)' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: hs.buildEndOfEarlyData(), label: '[FUZZ] EndOfEarlyData (without early_data in ClientHello)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'tls13-early-data-after-finished',
    category: 'O',
    description: 'Send early data (application data records) AFTER sending Finished message',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions: [
          { type: ExtensionType.EARLY_DATA, data: hs.buildEarlyDataExtension() },
          { type: ExtensionType.PSK_KEY_EXCHANGE_MODES, data: hs.buildPSKKeyExchangeModesExtension([1]) },
          { type: ExtensionType.PRE_SHARED_KEY, data: hs.buildPreSharedKeyExtension() },
        ],
      }), label: 'ClientHello (early_data + fake PSK)' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildChangeCipherSpec(), label: 'ChangeCipherSpec' },
      { type: 'send', data: hs.buildFinished(), label: 'Finished' },
      { type: 'delay', ms: 100 },
      { type: 'send', data: buildRecord(ContentType.APPLICATION_DATA, Version.TLS_1_2, crypto.randomBytes(128)), label: '[FUZZ] Application data AFTER Finished (too late for early data)' },
      { type: 'recv', timeout: 3000 },
    ],
  },

  // ===== Category P: Advanced Handshake Record Fuzzing =====

  {
    name: 'handshake-fragmented-across-records',
    category: 'P',
    description: 'Split one ClientHello handshake message body across two separate TLS handshake records',
    side: 'client',
    actions: (opts) => {
      const body = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsMsg = Buffer.alloc(4 + body.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = (body.length >> 16) & 0xff;
      hsMsg[2] = (body.length >> 8) & 0xff;
      hsMsg[3] = body.length & 0xff;
      body.copy(hsMsg, 4);
      const mid = Math.floor(hsMsg.length / 2);
      const record1 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg.slice(0, mid));
      const record2 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg.slice(mid));
      return [
        { type: 'send', data: record1, label: '[FUZZ] ClientHello fragment 1 (TLS record-level split)' },
        { type: 'send', data: record2, label: '[FUZZ] ClientHello fragment 2 (TLS record-level split)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'handshake-length-overflow',
    category: 'P',
    description: 'Handshake message with length field set to 0xFFFFFF (16MB) but only sending tiny body',
    side: 'client',
    actions: (opts) => {
      const body = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsMsg = Buffer.alloc(4 + body.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = 0xff; hsMsg[2] = 0xff; hsMsg[3] = 0xff;
      body.copy(hsMsg, 4);
      const record = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg);
      return [
        { type: 'send', data: record, label: '[FUZZ] ClientHello (handshake length=0xFFFFFF, actual body much smaller)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'handshake-length-underflow',
    category: 'P',
    description: 'Handshake length field = 10 but body is 200+ bytes',
    side: 'client',
    actions: (opts) => {
      const body = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsMsg = Buffer.alloc(4 + body.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = 0x00; hsMsg[2] = 0x00; hsMsg[3] = 0x0a;
      body.copy(hsMsg, 4);
      const record = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg);
      return [
        { type: 'send', data: record, label: '[FUZZ] ClientHello (handshake length=10, actual body=200+ bytes)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'handshake-body-zero-length',
    category: 'P',
    description: 'ClientHello with handshake length = 0 (just the 4-byte header, no body)',
    side: 'client',
    actions: (opts) => {
      const hsMsg = Buffer.from([HandshakeType.CLIENT_HELLO, 0x00, 0x00, 0x00]);
      const record = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg);
      return [
        { type: 'send', data: record, label: '[FUZZ] ClientHello (zero-length body — header only)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'unknown-handshake-type',
    category: 'P',
    description: 'Send handshake message with type 99 (undefined in spec)',
    side: 'client',
    actions: (opts) => {
      const body = crypto.randomBytes(32);
      const record = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0,
        Buffer.concat([Buffer.from([99, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]), body]));
      return [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
        { type: 'recv', timeout: 3000 },
        { type: 'send', data: record, label: '[FUZZ] Unknown handshake type 99 (32 bytes body)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'handshake-trailing-garbage',
    category: 'P',
    description: 'Valid ClientHello handshake record followed by 50 garbage bytes in the same TLS record',
    side: 'client',
    actions: (opts) => {
      const body = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsMsg = Buffer.alloc(4 + body.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = (body.length >> 16) & 0xff;
      hsMsg[2] = (body.length >> 8) & 0xff;
      hsMsg[3] = body.length & 0xff;
      body.copy(hsMsg, 4);
      const garbage = crypto.randomBytes(50);
      const payload = Buffer.concat([hsMsg, garbage]);
      const record = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, payload);
      return [
        { type: 'send', data: record, label: '[FUZZ] ClientHello + 50 bytes trailing garbage in same record' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'handshake-header-only-no-body',
    category: 'P',
    description: 'Send just a 4-byte handshake header (Finished type + length=0) after valid ClientHello',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, Buffer.from([HandshakeType.FINISHED, 0x00, 0x00, 0x00])),
        label: '[FUZZ] 4-byte handshake header only (type=Finished, length=0)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'handshake-split-at-header',
    category: 'P',
    description: 'First TLS record contains only the 4-byte handshake header, second record contains the body',
    side: 'client',
    actions: (opts) => {
      const body = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsHeader = Buffer.alloc(4);
      hsHeader[0] = HandshakeType.CLIENT_HELLO;
      hsHeader[1] = (body.length >> 16) & 0xff;
      hsHeader[2] = (body.length >> 8) & 0xff;
      hsHeader[3] = body.length & 0xff;
      const record1 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsHeader);
      const record2 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, body);
      return [
        { type: 'send', data: record1, label: '[FUZZ] TLS record 1: handshake header only (4 bytes)' },
        { type: 'send', data: record2, label: '[FUZZ] TLS record 2: handshake body (ClientHello data)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'triple-handshake-one-record',
    category: 'P',
    description: 'Pack ClientHello + CKE + Finished into a single TLS record',
    side: 'client',
    actions: (opts) => {
      const record = hs.buildMultiHandshakeRecord([
        { type: HandshakeType.CLIENT_HELLO, body: hs.buildClientHelloBody({ hostname: opts.hostname }) },
        { type: HandshakeType.CLIENT_KEY_EXCHANGE, body: crypto.randomBytes(130) },
        { type: HandshakeType.FINISHED, body: crypto.randomBytes(12) },
      ]);
      return [
        { type: 'send', data: record, label: '[FUZZ] Triple handshake in one record (CH + CKE + Finished)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
  {
    name: 'handshake-length-exceeds-record',
    category: 'P',
    description: 'Handshake msg_length > TLS record payload length (claims 500 bytes, record has 100)',
    side: 'client',
    actions: (opts) => {
      const body = crypto.randomBytes(96);
      const hsMsg = Buffer.alloc(4 + body.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = 0x00; hsMsg[2] = 0x01; hsMsg[3] = 0xf4; // 500
      body.copy(hsMsg, 4);
      const record = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg);
      return [
        { type: 'send', data: record, label: '[FUZZ] Handshake claims 500 bytes, record payload only 100' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'interleaved-handshake-and-alert',
    category: 'P',
    description: 'Alternate handshake fragments with alert records between them',
    side: 'client',
    actions: (opts) => {
      const body = hs.buildClientHelloBody({ hostname: opts.hostname });
      const hsMsg = Buffer.alloc(4 + body.length);
      hsMsg[0] = HandshakeType.CLIENT_HELLO;
      hsMsg[1] = (body.length >> 16) & 0xff;
      hsMsg[2] = (body.length >> 8) & 0xff;
      hsMsg[3] = body.length & 0xff;
      body.copy(hsMsg, 4);
      const third = Math.floor(hsMsg.length / 3);
      const frag1 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg.slice(0, third));
      const frag2 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg.slice(third, third * 2));
      const frag3 = buildRecord(ContentType.HANDSHAKE, Version.TLS_1_0, hsMsg.slice(third * 2));
      const alert = buildAlert(AlertLevel.WARNING, AlertDescription.NO_RENEGOTIATION);
      return [
        { type: 'send', data: frag1, label: '[FUZZ] Handshake fragment 1/3' },
        { type: 'send', data: alert, label: '[FUZZ] Alert interleaved between handshake fragments' },
        { type: 'send', data: frag2, label: '[FUZZ] Handshake fragment 2/3' },
        { type: 'send', data: alert, label: '[FUZZ] Alert interleaved between handshake fragments' },
        { type: 'send', data: frag3, label: '[FUZZ] Handshake fragment 3/3' },
        { type: 'recv', timeout: 5000 },
      ];
    },
  },
  {
    name: 'handshake-type-zero',
    category: 'P',
    description: 'Send handshake message with type=0 (HelloRequest in TLS 1.2, unusual as client)',
    side: 'client',
    actions: (opts) => [
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, Buffer.from([0x00, 0x00, 0x00, 0x00])),
        label: '[FUZZ] Handshake type=0 (HelloRequest from client — invalid)' },
      { type: 'recv', timeout: 3000 },
    ],
  },
  {
    name: 'handshake-message-max-type',
    category: 'P',
    description: 'Send handshake message with type=255 (maximum value)',
    side: 'client',
    actions: (opts) => {
      const body = crypto.randomBytes(16);
      return [
        { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
        { type: 'recv', timeout: 3000 },
        { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2,
          Buffer.concat([Buffer.from([0xff, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]), body])),
          label: '[FUZZ] Handshake type=255 (max value, 16 bytes body)' },
        { type: 'recv', timeout: 3000 },
      ];
    },
  },
];

function getScenario(name) {
  return SCENARIOS.find(s => s.name === name);
}

function getScenariosByCategory(cat) {
  return SCENARIOS.filter(s => s.category === cat.toUpperCase());
}

function getClientScenarios() {
  return SCENARIOS.filter(s => s.side === 'client');
}

function getServerScenarios() {
  return SCENARIOS.filter(s => s.side === 'server');
}

function listScenarios() {
  const grouped = {};
  for (const s of SCENARIOS) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return { categories: CATEGORIES, scenarios: grouped, all: SCENARIOS };
}

module.exports = { SCENARIOS, CATEGORIES, CATEGORY_SEVERITY, getScenario, getScenariosByCategory, getClientScenarios, getServerScenarios, listScenarios };
