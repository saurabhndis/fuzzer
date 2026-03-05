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

const TCP_CATEGORIES = {
  RA: 'TCP SYN Attacks',
  RB: 'TCP RST Injection',
  RC: 'TCP Sequence/ACK Manipulation',
  RD: 'TCP Window Attacks',
  RE: 'TCP Segment Reordering & Overlap',
  RF: 'TCP Urgent Pointer Attacks',
  RG: 'TCP State Machine Fuzzing',
};

const TCP_CATEGORY_SEVERITY = {
  RA: 'high',
  RB: 'high',
  RC: 'high',
  RD: 'medium',
  RE: 'medium',
  RF: 'low',
  RG: 'high',
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
