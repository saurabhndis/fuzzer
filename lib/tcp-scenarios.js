// Raw TCP Attack Scenarios — categories RA through RG
// Requires raw sockets (CAP_NET_RAW on Linux). Each scenario has requiresRaw: true.
//
// Action types specific to raw TCP:
//   { type: 'rawConnect', window?: number }           — TCP 3-way handshake via raw socket
//   { type: 'rawSend', flags: string, data?: Buffer, seqOffset?: number, ackOffset?: number, window?: number, urgentPointer?: number, label?: string }
//   { type: 'synFlood', count: number, spoofSource?: boolean }
//   { type: 'sendOverlapping', data: Buffer, overlapBytes: number }
//   { type: 'sendOutOfOrder', data: Buffer, segments: number, order: string }
//   { type: 'tcpProbe' }                              — check if target is still alive
//
// Standard action types also work (send, recv, delay, fin, rst) via RawTCPSocket's compatible interface.

const hs = require('./handshake');
const { buildTCPOptions, TCP_OPT } = require('./raw-tcp');

const TCP_CATEGORIES = {
  RA: 'TCP SYN Attacks',
  RB: 'TCP RST Injection',
  RC: 'TCP Sequence/ACK Manipulation',
  RD: 'TCP Window Attacks',
  RE: 'TCP Segment Reordering & Overlap',
  RF: 'TCP Urgent Pointer Attacks',
  RG: 'TCP State Machine Fuzzing',
  RH: 'TCP Option Fuzzing (TLS)',
  RX: 'Advanced TLS/H2 TCP Fuzzing',
};

const TCP_CATEGORY_SEVERITY = {
  RA: 'high',
  RB: 'high',
  RC: 'high',
  RD: 'medium',
  RE: 'medium',
  RF: 'low',
  RG: 'high',
  RH: 'medium',
  RX: 'high',
};

const TCP_SCENARIOS = [

  // ===== Category RA: TCP SYN Attacks =====

  {
    name: 'syn-flood-100',
    category: 'RA',
    description: 'Send 100 SYN packets with random source ports to test SYN flood resilience',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'synFlood', count: 100, spoofSource: false },
      { type: 'delay', ms: 2000 },
      { type: 'tcpProbe', label: 'Check target alive after SYN flood' },
    ],
    expected: 'PASSED',
    expectedReason: 'Target should remain operational under small SYN flood',
  },
  {
    name: 'syn-flood-1000-spoofed',
    category: 'RA',
    description: 'Send 1000 SYN packets with spoofed random source IPs',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'synFlood', count: 1000, spoofSource: true },
      { type: 'delay', ms: 3000 },
      { type: 'tcpProbe', label: 'Check target alive after spoofed SYN flood' },
    ],
    expected: 'PASSED',
    expectedReason: 'Target should use SYN cookies or equivalent defense',
  },
  {
    name: 'syn-with-payload',
    category: 'RA',
    description: 'SYN packet carrying TLS ClientHello payload (TCP Fast Open style)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'SYN', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'SYN + ClientHello payload' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Most stacks should SYN-ACK and buffer or discard the payload',
  },
  {
    name: 'syn-with-zero-window',
    category: 'RA',
    description: 'SYN with zero advertised window to test resource exhaustion handling',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'SYN', window: 0, label: 'SYN with zero window' },
      { type: 'recv', timeout: 3000 },
      { type: 'delay', ms: 2000 },
      { type: 'tcpProbe', label: 'Check target handles zero-window SYN' },
    ],
    expectedReason: 'Target should handle zero-window SYN gracefully',
  },
  {
    name: 'syn-with-large-mss',
    category: 'RA',
    description: 'SYN with maximum sequence number to test wraparound handling',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'SYN', seqOverride: 0xFFFFFFFF, label: 'SYN with seq=0xFFFFFFFF' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should handle sequence number wraparound correctly',
  },

  // ===== Category RB: TCP RST Injection =====

  {
    name: 'rst-with-wrong-seq',
    category: 'RB',
    description: 'Establish connection, then send RST with wrong sequence number',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'rawSend', flags: 'RST', seqOffset: 100000, label: 'RST with wrong seq (+100000)' },
      { type: 'delay', ms: 500 },
      { type: 'tcpProbe', label: 'Target should still be alive (invalid RST ignored)' },
    ],
    expected: 'PASSED',
    expectedReason: 'RFC 5961: RST with out-of-window seq should be ignored',
  },
  {
    name: 'rst-with-valid-seq',
    category: 'RB',
    description: 'Establish connection, then send RST with valid in-window sequence number',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'rawSend', flags: 'RST', seqOffset: 0, label: 'RST with valid seq' },
      { type: 'delay', ms: 500 },
      { type: 'tcpProbe', label: 'Connection should be torn down' },
    ],
    expectedReason: 'RST with valid seq should reset the connection',
  },
  {
    name: 'rst-during-handshake',
    category: 'RB',
    description: 'Send RST immediately after receiving SYN-ACK (before completing handshake)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'SYN', label: 'SYN' },
      { type: 'recv', timeout: 3000 },
      { type: 'rawSend', flags: 'RST', label: 'RST (abort handshake)' },
      { type: 'delay', ms: 500 },
      { type: 'tcpProbe', label: 'Target should clean up half-open connection' },
    ],
    expected: 'PASSED',
    expectedReason: 'Target should clean up the half-open connection promptly',
  },
  {
    name: 'rst-ack-injection',
    category: 'RB',
    description: 'Send RST+ACK with forged acknowledgment number',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'rawSend', flags: 'RST|ACK', ackOffset: 99999, label: 'RST|ACK with forged ack' },
      { type: 'delay', ms: 500 },
      { type: 'tcpProbe' },
    ],
    expectedReason: 'Target should validate RST against receive window',
  },

  // ===== Category RC: TCP Sequence/ACK Manipulation =====

  {
    name: 'ack-with-future-seq',
    category: 'RC',
    description: 'ACK a sequence number far beyond what server has sent',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'rawSend', flags: 'ACK', ackOffset: 100000, label: 'ACK with future ack number (+100000)' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should send a corrective ACK or ignore',
  },
  {
    name: 'data-with-past-seq',
    category: 'RC',
    description: 'Send ClientHello with sequence number in the past (already ACKed range)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'rawSend', flags: 'PSH|ACK', seqOffset: -50000, data: hs.buildClientHello({ hostname: opts.hostname }), label: 'Data with past seq (-50000)' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should ignore or ACK with correct expected seq',
  },
  {
    name: 'data-with-future-seq',
    category: 'RC',
    description: 'Send data with sequence number ahead of expected (gap in stream)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'rawSend', flags: 'PSH|ACK', seqOffset: 1000, data: hs.buildClientHello({ hostname: opts.hostname }), label: 'Data with future seq (+1000)' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should buffer out-of-order segment and ACK expected seq',
  },
  {
    name: 'dup-ack-storm',
    category: 'RC',
    description: 'Send 50 duplicate ACKs to trigger fast retransmit behavior',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'rawSend', flags: 'ACK', label: 'Dup ACK 1/50' },
      { type: 'rawSend', flags: 'ACK', label: 'Dup ACK 2/50' },
      { type: 'rawSend', flags: 'ACK', label: 'Dup ACK 3/50' },
      { type: 'delay', ms: 100 },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target may retransmit after 3 dup ACKs (RFC 5681)',
  },

  // ===== Category RD: TCP Window Attacks =====

  {
    name: 'zero-window-then-update',
    category: 'RD',
    description: 'Advertise zero window during handshake, then send window update',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect', window: 0 },
      { type: 'delay', ms: 2000 },
      { type: 'rawSend', flags: 'ACK', window: 65535, label: 'Window update: 0 → 65535' },
      { type: 'recv', timeout: 5000 },
    ],
    expectedReason: 'Target should resume sending after window opens',
  },
  {
    name: 'window-shrink',
    category: 'RD',
    description: 'Shrink the window to 1 byte after connection is established',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'rawSend', flags: 'ACK', window: 1, label: 'Shrink window to 1 byte' },
      { type: 'recv', timeout: 5000 },
    ],
    expectedReason: 'Target should respect small window and segment accordingly',
  },
  {
    name: 'window-oscillation',
    category: 'RD',
    description: 'Rapidly oscillate window between 0 and 65535 (Sockstress variant)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'send', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'rawSend', flags: 'ACK', window: 0, label: 'Window → 0' },
      { type: 'delay', ms: 200 },
      { type: 'rawSend', flags: 'ACK', window: 65535, label: 'Window → 65535' },
      { type: 'delay', ms: 200 },
      { type: 'rawSend', flags: 'ACK', window: 0, label: 'Window → 0' },
      { type: 'delay', ms: 200 },
      { type: 'rawSend', flags: 'ACK', window: 65535, label: 'Window → 65535' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should handle rapid window changes without resource leak',
  },

  // ===== Category RE: TCP Segment Reordering & Overlap =====

  {
    name: 'overlapping-segments-conflicting',
    category: 'RE',
    description: 'Send overlapping TCP segments with conflicting data in the overlap region',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'sendOverlapping', data: hs.buildClientHello({ hostname: opts.hostname }), overlapBytes: 10 },
      { type: 'recv', timeout: 5000 },
    ],
    expectedReason: 'Target should reassemble consistently (first or last wins, but consistent)',
  },
  {
    name: 'reverse-order-segments',
    category: 'RE',
    description: 'Send TLS ClientHello split into 4 segments delivered in reverse order',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'sendOutOfOrder', data: hs.buildClientHello({ hostname: opts.hostname }), segments: 4, order: 'reverse' },
      { type: 'recv', timeout: 5000 },
    ],
    expected: 'PASSED',
    expectedReason: 'Target should reassemble out-of-order segments correctly',
  },
  {
    name: 'random-order-segments',
    category: 'RE',
    description: 'Send TLS ClientHello split into 6 segments delivered in random order',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'sendOutOfOrder', data: hs.buildClientHello({ hostname: opts.hostname }), segments: 6, order: 'random' },
      { type: 'recv', timeout: 5000 },
    ],
    expected: 'PASSED',
    expectedReason: 'Target should reassemble randomly ordered segments',
  },
  {
    name: 'interleaved-segments',
    category: 'RE',
    description: 'Send segments in interleaved order (even offsets first, then odd)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'sendOutOfOrder', data: hs.buildClientHello({ hostname: opts.hostname }), segments: 8, order: 'interleaved' },
      { type: 'recv', timeout: 5000 },
    ],
    expected: 'PASSED',
    expectedReason: 'Target should reassemble interleaved segments',
  },

  // ===== Category RF: TCP Urgent Pointer Attacks =====

  {
    name: 'zero-window-probe-flood',
    category: 'RD',
    description: 'Send ClientHello, then flood server with 20 zero-window probes to test persist timer',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const actions = [
        { type: 'rawConnect' },
        { type: 'rawSend', flags: 'PSH|ACK', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
        { type: 'recv', timeout: 2000 },
      ];
      for (let i = 0; i < 20; i++) {
        actions.push({ type: 'rawSend', flags: 'ACK', window: 0, label: `Zero-window probe #${i+1}` });
        actions.push({ type: 'delay', ms: 50 });
      }
      actions.push({ type: 'rawSend', flags: 'ACK', window: 65535, label: 'Open window' });
      actions.push({ type: 'recv', timeout: 5000 });
      return actions;
    },
    expectedReason: 'Target should handle persist timer and zero-window probes per RFC 9293',
  },

  {
    name: 'client-hello-random-drops',
    category: 'RE',
    description: 'Send ClientHello in 15 segments but randomly drop 3 of them',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      const segmentCount = 15;
      const dropCount = 3;
      const segmentSize = Math.ceil(ch.length / segmentCount);
      const indices = Array.from({ length: segmentCount }, (_, i) => i);
      const droppedIndices = new Set();
      while (droppedIndices.size < dropCount) {
        droppedIndices.add(Math.floor(Math.random() * segmentCount));
      }

      const actions = [{ type: 'rawConnect' }];
      for (let i = 0; i < segmentCount; i++) {
        if (droppedIndices.has(i)) {
          actions.push({ type: 'info', message: `[FUZZ] Dropping segment ${i+1}/${segmentCount}` });
          continue;
        }
        const start = i * segmentSize;
        const end = Math.min(start + segmentSize, ch.length);
        const data = ch.slice(start, end);
        actions.push({ type: 'rawSend', flags: i === segmentCount - 1 ? 'PSH|ACK' : 'ACK', data, label: `Segment ${i+1}/${segmentCount}` });
      }
      actions.push({ type: 'recv', timeout: 5000 });
      return actions;
    },
    expectedReason: 'Target should retransmit missing segments or time out the connection',
  },

  {
    name: 'oversized-client-hello-massive-reorder',
    category: 'RE',
    description: 'Send a 6KB padded ClientHello in 20 segments with random delivery order',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      // Build a large ClientHello with many unknown extensions to reach ~6KB
      const extraExtensions = [];
      for (let i = 0; i < 50; i++) {
        extraExtensions.push({ type: 0x7000 + i, data: Buffer.alloc(100, 0xAA) });
      }
      const largeCH = hs.buildClientHello({
        hostname: opts.hostname,
        extraExtensions
      });

      return [
        { type: 'rawConnect' },
        { 
          type: 'sendOutOfOrder', 
          data: largeCH, 
          segments: 20, 
          order: 'random',
          label: `Massive Reorder: ${largeCH.length} bytes in 20 random segments`
        },
        { type: 'recv', timeout: 10000 },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Target should correctly reassemble large out-of-order handshake records',
  },

  {
    name: 'urgent-pointer-past-data',
    category: 'RF',
    description: 'Set URG flag with urgent pointer beyond payload length',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'rawSend', flags: 'URG|PSH|ACK', urgentPointer: 9999, data: hs.buildClientHello({ hostname: opts.hostname }), label: 'URG pointer=9999 past payload' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should handle invalid urgent pointer gracefully',
  },
  {
    name: 'urgent-pointer-zero',
    category: 'RF',
    description: 'Set URG flag with zero urgent pointer',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'rawSend', flags: 'URG|PSH|ACK', urgentPointer: 0, data: hs.buildClientHello({ hostname: opts.hostname }), label: 'URG pointer=0' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should handle URG with zero pointer',
  },
  {
    name: 'urg-without-data',
    category: 'RF',
    description: 'Send URG flag on an empty segment (no payload)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'rawSend', flags: 'URG|ACK', urgentPointer: 100, label: 'URG on empty segment' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should handle URG with no data gracefully',
  },

  // ===== Category RG: TCP State Machine Fuzzing =====

  {
    name: 'data-before-handshake',
    category: 'RG',
    description: 'Send application data without completing TCP handshake',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'PSH|ACK', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'Data before handshake' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should RST or ignore data without established connection',
  },
  {
    name: 'fin-before-handshake',
    category: 'RG',
    description: 'Send FIN without ever completing TCP handshake',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'SYN', label: 'SYN' },
      { type: 'recv', timeout: 2000 },
      { type: 'rawSend', flags: 'FIN|ACK', label: 'FIN before handshake complete' },
      { type: 'delay', ms: 1000 },
      { type: 'tcpProbe' },
    ],
    expectedReason: 'Target should handle unexpected FIN in SYN_RCVD state',
  },
  {
    name: 'simultaneous-open',
    category: 'RG',
    description: 'Simulate TCP simultaneous open by sending SYN to a listening port',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'SYN', label: 'SYN (simulated simultaneous open)' },
      { type: 'recv', timeout: 3000 },
      { type: 'rawSend', flags: 'SYN|ACK', label: 'SYN|ACK (simultaneous open response)' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should handle simultaneous open per RFC 793',
  },
  {
    name: 'ack-before-syn',
    category: 'RG',
    description: 'Send ACK to a listening port without prior SYN (ACK scan)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'ACK', label: 'ACK without prior SYN' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should RST in response to unsolicited ACK',
  },
  {
    name: 'double-syn',
    category: 'RG',
    description: 'Send two SYN packets with different sequence numbers before completing handshake',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'SYN', label: 'SYN #1' },
      { type: 'recv', timeout: 2000 },
      { type: 'rawSend', flags: 'SYN', seqOffset: 10000, label: 'SYN #2 with different seq' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should handle duplicate SYN (RFC 793 §3.4)',
  },
  {
    name: 'xmas-tree-packet',
    category: 'RG',
    description: 'Send a Christmas tree packet (all flags set: SYN|FIN|RST|PSH|ACK|URG)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: 'SYN|FIN|RST|PSH|ACK|URG', urgentPointer: 1, data: Buffer.from('XMAS'), label: 'XMAS tree packet (all flags)' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Target should reject or RST — invalid flag combination',
  },
  {
    name: 'null-packet',
    category: 'RG',
    description: 'Send a TCP packet with no flags set (NULL scan)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawSend', flags: '', label: 'NULL packet (no flags)' },
      { type: 'recv', timeout: 3000 },
    ],
    expectedReason: 'Open port should drop; closed port should RST (RFC 793)',
  },

  // ===== Category RH: TCP Option Fuzzing (TLS) =====
  // These scenarios negotiate TCP options in the SYN handshake, then send TLS
  // ClientHello with TCP-level violations — testing whether the TLS stack and
  // middleboxes handle TCP option inconsistencies correctly.

  {
    name: 'ts-negotiated-then-dropped',
    category: 'RH',
    description: 'Negotiate TCP timestamps in SYN, then send TLS ClientHello without timestamps',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.SACK_PERMITTED },
        { kind: TCP_OPT.TIMESTAMP, tsval: 1000, tsecr: 0 },
        { kind: TCP_OPT.WINDOW_SCALE, value: 7 },
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN with timestamps + MSS + SACK + WS' },
        // Send TLS ClientHello with NO TCP timestamps (violates RFC 7323 §3.2)
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, label: 'TLS ClientHello — TCP timestamps dropped after negotiation' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Server should reject or reset when timestamps disappear after negotiation (RFC 7323 §3.2)',
  },

  {
    name: 'ts-negotiated-then-zero-tsval',
    category: 'RH',
    description: 'Negotiate TCP timestamps in SYN, then send TLS data with TSval=0',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.TIMESTAMP, tsval: 5000, tsecr: 0 },
      ]);
      const dataOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 0, tsecr: 0 },
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN with timestamps (TSval=5000)' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, tcpOptions: dataOpts, label: 'TLS ClientHello — TSval=0 (invalid after negotiation)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'TSval of 0 after negotiating timestamps should be treated as invalid (RFC 7323 §5.5)',
  },

  {
    name: 'ts-negotiated-then-backwards',
    category: 'RH',
    description: 'Negotiate TCP timestamps, then send TLS data with TSval going backwards',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.TIMESTAMP, tsval: 100000, tsecr: 0 },
      ]);
      const ackOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 100001, tsecr: 0 },
      ]);
      const dataOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 50, tsecr: 0 },
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, ackOptions: ackOpts, label: 'SYN with TSval=100000' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, tcpOptions: dataOpts, label: 'TLS ClientHello — TSval=50 (went backwards by 99950)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'PAWS (Protection Against Wrapped Sequences) should reject segments with old timestamps (RFC 7323 §5.5)',
  },

  {
    name: 'ts-not-negotiated-then-injected',
    category: 'RH',
    description: 'SYN without timestamps, then inject timestamps on TLS data segments',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
      ]);
      const dataOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 12345, tsecr: 67890 },
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN without timestamps (MSS only)' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, tcpOptions: dataOpts, label: 'TLS ClientHello — timestamps injected post-handshake' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Unexpected timestamps on data should be silently ignored per RFC 7323 §3.2',
  },

  {
    name: 'mss-negotiated-then-exceeded',
    category: 'RH',
    description: 'Negotiate small MSS in SYN, then send TLS ClientHello exceeding it',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 100 },
      ]);
      // Build a large ClientHello that exceeds 100-byte MSS
      const ch = hs.buildClientHello({
        hostname: opts.hostname,
        extensions: true,
      });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN with MSS=100 (very small)' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, label: `TLS ClientHello (${ch.length}B) exceeding MSS=100` },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'MSS is advisory for sender; receiver should accept oversized segments (RFC 9293 §3.7.1)',
  },

  {
    name: 'mss-zero',
    category: 'RH',
    description: 'Negotiate MSS=0 in SYN, then send TLS ClientHello',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 0 },
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN with MSS=0 (invalid)' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, label: 'TLS ClientHello after MSS=0 negotiation' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'MSS=0 is invalid and should cause connection rejection',
  },

  {
    name: 'sack-negotiated-then-bogus-sack-blocks',
    category: 'RH',
    description: 'Negotiate SACK in SYN, then send TLS data with bogus SACK option blocks',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.SACK_PERMITTED },
      ]);
      // Bogus SACK block: claim we received data from far-future sequence numbers
      const sackBlock = Buffer.alloc(10);
      sackBlock[0] = TCP_OPT.SACK;
      sackBlock[1] = 10;  // length: 2 + 8 (one 4+4 block)
      sackBlock.writeUInt32BE(0xFFFF0000, 2); // left edge
      sackBlock.writeUInt32BE(0xFFFF1000, 6); // right edge
      const dataOpts = Buffer.concat([
        Buffer.from([TCP_OPT.NOP, TCP_OPT.NOP]),
        sackBlock,
      ]);
      // Pad to 4-byte boundary
      const padLen = (4 - dataOpts.length % 4) % 4;
      const paddedOpts = padLen > 0 ? Buffer.concat([dataOpts, Buffer.alloc(padLen)]) : dataOpts;

      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN with SACK permitted' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, tcpOptions: paddedOpts, label: 'TLS ClientHello + bogus SACK blocks (far-future seq)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Bogus SACK blocks from client should be ignored by server (RFC 2018 §4)',
  },

  {
    name: 'ws-negotiated-then-oversized-window',
    category: 'RH',
    description: 'Negotiate window scale in SYN, then advertise impossibly large window on TLS data',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.WINDOW_SCALE, value: 14 },  // scale factor 2^14 = 16384
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN with window scale=14 (2^14)' },
        // Window field = 65535, scaled by 2^14 = 1,073,725,440 bytes (~1GB)
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, window: 65535, label: 'TLS ClientHello — window=65535 * 2^14 (~1GB advertised)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Large scaled windows are valid; server should process normally (RFC 7323 §2.3)',
  },

  {
    name: 'ts-negotiated-tls-fragmented-different-ts',
    category: 'RH',
    description: 'Negotiate timestamps, then send TLS ClientHello in 2 segments with different TSvals',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.TIMESTAMP, tsval: 10000, tsecr: 0 },
      ]);
      const ackOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 10001, tsecr: 0 },
      ]);
      const ts1 = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 10002, tsecr: 0 },
      ]);
      const ts2 = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 9000, tsecr: 0 },
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      const half = Math.floor(ch.length / 2);
      return [
        { type: 'rawConnect', synOptions: synOpts, ackOptions: ackOpts, label: 'SYN with timestamps' },
        { type: 'rawSend', flags: 'ACK', data: ch.slice(0, half), tcpOptions: ts1, label: `TLS ClientHello frag 1/${ch.length}B — TSval=10002` },
        { type: 'delay', ms: 50 },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch.slice(half), tcpOptions: ts2, label: `TLS ClientHello frag 2/${ch.length}B — TSval=9000 (backwards!)` },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Second fragment has TSval going backwards — PAWS should reject it (RFC 7323 §5.5)',
  },

  {
    name: 'unknown-tcp-options-with-tls',
    category: 'RH',
    description: 'Send TLS ClientHello with unknown/experimental TCP options',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
      ]);
      // Unknown option kinds 253, 254 (reserved for experiments per RFC 6994)
      const experimentalOpts = Buffer.from([
        253, 4, 0xDE, 0xAD,     // experimental option 253, length 4
        254, 6, 0xBE, 0xEF, 0xCA, 0xFE,  // experimental option 254, length 6
        TCP_OPT.NOP, TCP_OPT.NOP, // padding
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN with MSS only' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, tcpOptions: experimentalOpts, label: 'TLS ClientHello + unknown TCP options 253/254 (experimental)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Unknown TCP options should be silently ignored (RFC 9293 §3.1)',
  },

  {
    name: 'ts-negotiated-then-huge-jump',
    category: 'RH',
    description: 'Negotiate timestamps then jump TSval forward by ~2^31 (near wraparound)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.TIMESTAMP, tsval: 1000, tsecr: 0 },
      ]);
      const ackOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 1001, tsecr: 0 },
      ]);
      const dataOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 0x80000000, tsecr: 0 },
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, ackOptions: ackOpts, label: 'SYN with TSval=1000' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, tcpOptions: dataOpts, label: 'TLS ClientHello — TSval=2^31 (huge forward jump, near wraparound)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'PAWS treats TSval jumps near 2^31 as going backwards due to signed comparison (RFC 7323 §5.5)',
  },

  {
    name: 'malformed-tcp-option-length-with-tls',
    category: 'RH',
    description: 'Send TLS ClientHello with malformed TCP option (length exceeds packet)',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
      ]);
      // Malformed option: kind=8 (timestamp) but length=255 (way beyond actual data)
      const malformed = Buffer.alloc(12);
      malformed[0] = TCP_OPT.NOP;
      malformed[1] = TCP_OPT.NOP;
      malformed[2] = TCP_OPT.TIMESTAMP;
      malformed[3] = 255;  // Claim 255 bytes but only 10 present
      malformed.writeUInt32BE(12345, 4);
      malformed.writeUInt32BE(0, 8);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, label: 'SYN with MSS' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, tcpOptions: malformed, label: 'TLS ClientHello — TCP timestamp option with length=255 (overflows)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Malformed TCP option with invalid length should cause segment rejection',
  },

  {
    name: 'ts-negotiated-tls-data-then-no-ts',
    category: 'RH',
    description: 'Full TLS handshake start with timestamps, then drop timestamps mid-stream',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const synOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.TIMESTAMP, tsval: 50000, tsecr: 0 },
        { kind: TCP_OPT.WINDOW_SCALE, value: 7 },
      ]);
      const ackOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 50001, tsecr: 0 },
      ]);
      const ts1 = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 50002, tsecr: 0 },
      ]);
      const ch = hs.buildClientHello({ hostname: opts.hostname });
      return [
        { type: 'rawConnect', synOptions: synOpts, ackOptions: ackOpts, label: 'SYN with timestamps + window scale' },
        { type: 'rawSend', flags: 'PSH|ACK', data: ch, tcpOptions: ts1, label: 'TLS ClientHello — with valid timestamp' },
        { type: 'recv', timeout: 5000 },
        // Now respond to ServerHello with ACK but NO timestamps
        { type: 'rawSend', flags: 'ACK', label: 'ACK ServerHello — timestamps suddenly missing' },
        { type: 'delay', ms: 500 },
        { type: 'tcpProbe', label: 'Check if server is still alive' },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Dropping timestamps after negotiation violates RFC 7323 — server should reject subsequent segments',
  },

  // ===== Category RX: Advanced TLS/H2 TCP Fuzzing =====

  {
    name: 'tls-client-hello-overlapping-tcp',
    category: 'RX',
    description: 'Send TLS ClientHello in overlapping TCP segments',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { 
        type: 'sendOverlapping', 
        data: hs.buildClientHello({ hostname: opts.hostname }), 
        overlapBytes: 15,
        label: 'TLS ClientHello (15-byte overlaps)'
      },
      { type: 'recv', timeout: 5000 },
    ],
    expected: 'PASSED',
    expectedReason: 'Target should correctly reassemble overlapping TCP segments',
  },

  {
    name: 'h2-preface-out-of-order',
    category: 'RX',
    description: 'Send H2 connection preface in reverse TCP order',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => {
      const preface = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
      const settings = Buffer.from([0,0,0, 4, 0,0,0,0,0]); // Empty SETTINGS
      return [
        { type: 'rawConnect' },
        { 
          type: 'sendOutOfOrder', 
          data: Buffer.concat([preface, settings]), 
          segments: 4, 
          order: 'reverse',
          label: 'H2 Preface + SETTINGS (reverse TCP order)'
        },
        { type: 'recv', timeout: 5000 }
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Target should reassemble out-of-order TCP segments before H2 parsing',
  },

  {
    name: 'tls-handshake-zero-window-stall',
    category: 'RX',
    description: 'Send ClientHello, receive response, then advertise zero window and stall',
    side: 'client',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'rawConnect' },
      { type: 'rawSend', flags: 'PSH|ACK', data: hs.buildClientHello({ hostname: opts.hostname }), label: 'ClientHello' },
      { type: 'recv', timeout: 3000 },
      { type: 'rawSend', flags: 'ACK', window: 0, label: '[FUZZ] Advertise window=0 (stall)' },
      { type: 'delay', ms: 5000 },
      { type: 'rawSend', flags: 'ACK', window: 65535, label: 'Resume: window=65535' },
      { type: 'recv', timeout: 5000 },
    ],
    expected: 'PASSED',
    expectedReason: 'Target should handle zero-window stall during handshake gracefully',
  },

  // ===== Server-side raw TCP scenarios =====

  {
    name: 'server-rst-injection',
    category: 'RB',
    description: 'Server accepts connection then sends RST with wrong seq to test client behavior',
    side: 'server',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'recv', timeout: 10000 },
      { type: 'rawSend', flags: 'RST', seqOffset: 50000, label: 'RST with wrong seq from server' },
      { type: 'delay', ms: 1000 },
    ],
    expectedReason: 'Client should ignore RST with out-of-window seq',
  },
  {
    name: 'server-window-zero',
    category: 'RD',
    description: 'Server advertises zero window to test client persist timer behavior',
    side: 'server',
    requiresRaw: true,
    actions: (opts) => [
      { type: 'recv', timeout: 10000 },
      { type: 'rawSend', flags: 'ACK', window: 0, label: 'Server advertises window=0' },
      { type: 'delay', ms: 5000 },
      { type: 'rawSend', flags: 'ACK', window: 65535, label: 'Server opens window' },
      { type: 'recv', timeout: 5000 },
    ],
    expectedReason: 'Client should use persist timer and resume when window opens',
  },

  {
    name: 'server-ts-static',
    category: 'RH',
    description: 'Server sends the exact same TCP timestamp (TSval) in every packet after negotiation',
    side: 'server',
    requiresRaw: true,
    actions: (opts) => {
      const tsval = 1234567;
      const synAckOpts = buildTCPOptions([
        { kind: TCP_OPT.MSS, value: 1460 },
        { kind: TCP_OPT.TIMESTAMP, tsval: tsval, tsecr: 0 },
      ]);
      const dataOpts = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: tsval, tsecr: 0 },
      ]);
      return [
        { type: 'recv', timeout: 5000 }, // Wait for ClientHello
        { type: 'rawSend', flags: 'SYN|ACK', tcpOptions: synAckOpts, label: `SYN|ACK with TSval=${tsval}` },
        { type: 'recv', timeout: 3000 }, // Wait for ACK
        { type: 'rawSend', flags: 'PSH|ACK', data: hs.buildServerHello(), tcpOptions: dataOpts, label: `ServerHello with same TSval=${tsval}` },
        { type: 'delay', ms: 500 },
        { type: 'rawSend', flags: 'PSH|ACK', data: hs.buildServerHelloDone(), tcpOptions: dataOpts, label: `ServerHelloDone with same TSval=${tsval}` },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expectedReason: 'Stagnant timestamps for new data may be tolerated or cause issues depending on client clock resolution',
  },

  {
    name: 'server-ts-backwards',
    category: 'RH',
    description: 'Server sends a valid timestamp, then a subsequent packet with an older timestamp',
    side: 'server',
    requiresRaw: true,
    actions: (opts) => {
      const ts1 = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 20000, tsecr: 0 },
      ]);
      const ts2 = buildTCPOptions([
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.NOP },
        { kind: TCP_OPT.TIMESTAMP, tsval: 1000, tsecr: 0 }, // Older!
      ]);
      return [
        { type: 'recv', timeout: 5000 },
        { type: 'rawSend', flags: 'SYN|ACK', label: 'SYN|ACK' },
        { type: 'recv', timeout: 3000 },
        { type: 'rawSend', flags: 'PSH|ACK', data: hs.buildServerHello(), tcpOptions: ts1, label: 'ServerHello with TSval=20000' },
        { type: 'delay', ms: 200 },
        { type: 'rawSend', flags: 'PSH|ACK', data: hs.buildServerHelloDone(), tcpOptions: ts2, label: 'ServerHelloDone with TSval=1000 (backwards)' },
        { type: 'recv', timeout: 5000 },
      ];
    },
    expected: 'DROPPED',
    expectedReason: 'Client PAWS (RFC 7323) should drop the packet with the older timestamp',
  },
];

// ── Lookup functions (matching pattern from scenarios.js) ─────────────────────

function getTcpScenario(name) {
  return TCP_SCENARIOS.find(s => s.name === name);
}

function getTcpScenariosByCategory(cat) {
  return TCP_SCENARIOS.filter(s => s.category === cat.toUpperCase());
}

function getTcpClientScenarios() {
  return TCP_SCENARIOS.filter(s => s.side === 'client');
}

function getTcpServerScenarios() {
  return TCP_SCENARIOS.filter(s => s.side === 'server');
}

function listTcpScenarios() {
  const grouped = {};
  for (const s of TCP_SCENARIOS) {
    const cat = s.category;
    const label = TCP_CATEGORIES[cat] || cat;
    if (!grouped[cat]) grouped[cat] = { label, scenarios: [] };
    grouped[cat].scenarios.push({ name: s.name, side: s.side, description: s.description });
  }
  return grouped;
}

module.exports = {
  TCP_SCENARIOS,
  TCP_CATEGORIES,
  TCP_CATEGORY_SEVERITY,
  getTcpScenario,
  getTcpScenariosByCategory,
  getTcpClientScenarios,
  getTcpServerScenarios,
  listTcpScenarios,
};
