// Auto-compute expected outcome for fuzzing scenarios
//
// Three-layer decision system:
//   Layer 1: Explicit overrides for known PASSED scenarios
//   Layer 2: Action-based heuristics (detects valid TCP behavior patterns)
//   Layer 3: Category default (DROPPED for all violation categories)

const { CATEGORIES } = require('./scenarios');

// Layer 1: Scenarios where valid data is sent in unusual ways — server should accept
const EXPLICIT_PASSED = {
  'rst-mid-handshake': 'RST is a valid client abort; server response expected first',
  'slow-drip-client-hello': 'Server should reassemble TCP segments correctly',
  'split-record-across-segments': 'Server should reassemble fragmented TCP segments',
  'record-version-mismatch': 'Record version often differs from body version (common compat behavior)',
  'unknown-extensions': 'Server should ignore unknown extensions per RFC',
  'empty-sni': 'Empty SNI is tolerated by most servers (uses default vhost)',
};

// Layer 3: Category defaults — all default to DROPPED (secure expectation)
const CATEGORY_REASONS = {
  A: 'Must reject handshake order violations (protocol state machine bypass)',
  B: 'Must reject server handshake order violations (state machine bypass)',
  C: 'Must reject parameter mutation (downgrade/mismatch attacks)',
  D: 'Must reject alert injection (protocol confusion)',
  E: 'Must reject TCP manipulation abuse',
  F: 'Must reject record layer violations (fundamental protocol violations)',
  G: 'Must reject CCS attacks (CVE-2014-0224 vector)',
  H: 'Must reject extension fuzzing (parser robustness)',
  I: 'Must reject known vulnerability vectors (CVE detection)',
  J: 'Must reject invalid PQC key material',
  K: 'Must reject SNI evasion and fragmentation attacks',
  L: 'Must reject ALPN protocol confusion',
  M: 'Must reject extension malformation (parser crash/memory corruption)',
  N: 'Must reject parameter reneging (mid-stream downgrade/confusion attacks)',
  O: 'Must reject invalid TLS 1.3 early data and PSK abuse',
  P: 'Must reject advanced handshake record malformation',
};

/**
 * Analyze scenario actions to detect valid-behavior patterns
 * Returns { isValidBehavior: bool, reason: string } if a pattern is detected
 */
function analyzeActions(scenario) {
  let actions;
  try {
    actions = scenario.actions({ hostname: 'probe.test' });
  } catch (_) {
    return null;
  }

  const types = actions.map(a => a.type);
  const labels = actions.map(a => (a.label || '').toLowerCase());

  const hasSlowDrip = types.includes('slowDrip');
  const hasFragment = types.includes('fragment');
  const hasRST = types.includes('rst');
  const hasFIN = types.includes('fin');

  // Check if fuzz labels indicate violations
  const violationLabels = labels.some(l =>
    l.includes('[cve-') || l.includes('[vuln]') || l.includes('[malform]') ||
    l.includes('[sni-evasion]') || l.includes('[alpn]') || l.includes('[pqc]') ||
    l.includes('garbage') || l.includes('malformed') || l.includes('oversized') ||
    l.includes('duplicate') || l.includes('truncated') || l.includes('corrupted')
  );

  if (violationLabels) return null;

  // Pattern: TCP reassembly (slowDrip or fragment with valid ClientHello, no FIN/violations)
  if ((hasSlowDrip || hasFragment) && !hasFIN) {
    const sendCount = types.filter(t => t === 'send').length;
    if (sendCount === 0) {
      return { expected: 'PASSED', reason: 'Server should reassemble valid TCP segments' };
    }
  }

  // Pattern: RST after valid exchange (valid client abort)
  if (hasRST && !hasFIN && !hasSlowDrip && !hasFragment) {
    const sendIdx = types.indexOf('send');
    const recvIdx = types.indexOf('recv');
    const rstIdx = types.indexOf('rst');
    // RST after sending and receiving = valid abort
    if (sendIdx >= 0 && recvIdx > sendIdx && rstIdx > recvIdx) {
      return { expected: 'PASSED', reason: 'RST after valid exchange is a valid client abort' };
    }
  }

  return null;
}

/**
 * Compute the expected outcome for a scenario
 * Returns { expected: 'DROPPED'|'PASSED', reason: string }
 */
function computeExpected(scenario) {
  // Layer 1: Explicit overrides
  if (EXPLICIT_PASSED[scenario.name]) {
    return {
      expected: 'PASSED',
      reason: EXPLICIT_PASSED[scenario.name],
    };
  }

  // Layer 2: Action-based heuristics
  const heuristic = analyzeActions(scenario);
  if (heuristic) {
    return heuristic;
  }

  // Layer 3: Category default — DROPPED (secure expectation)
  const reason = CATEGORY_REASONS[scenario.category] ||
    `Protocol violation in category ${scenario.category}: ${CATEGORIES[scenario.category] || 'Unknown'}`;
  return {
    expected: 'DROPPED',
    reason,
  };
}

module.exports = { computeExpected, EXPLICIT_PASSED };
