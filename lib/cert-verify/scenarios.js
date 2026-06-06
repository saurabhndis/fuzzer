'use strict';

// 300 cert-verification scenarios: 150 CRL + 150 OCSP.
// Each scenario includes:
//   - useCustomServer: true  — server.js --agent presents the cert via TLS
//   - serverHandler()        — wraps raw socket in TLS with the scenario's chain
// Matching client scenarios (name + '-client') make a TLS connection through the
// firewall and report ALLOWED (PASSED) or BLOCKED (DROPPED).

const DELAYS      = [0, 100, 200, 500, 1000, 2000, 3000, 5000, 8000, 10000, 15000, 20000, 30000, 45000, 60000];
const SHORT_DELAYS = [0, 100, 500, 1000, 2000, 3000, 5000, 8000, 10000, 15000];

const CRL_REASONS  = [0, 1, 2, 3, 4, 5, 6, 8, 9, 10];
const REASON_NAMES = [
  'unspecified', 'keyCompromise', 'CACompromise', 'affiliationChanged',
  'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL',
  'privilegeWithdrawn', 'aACompromise',
];

const EXPIRED_OFFSETS = [
  60e3, 5 * 60e3, 30 * 60e3, 60 * 60e3,
  6 * 3600e3, 12 * 3600e3, 24 * 3600e3, 48 * 3600e3,
  7 * 86400e3, 30 * 86400e3,
];
const FUTURE_OFFSETS = [
  60e3, 5 * 60e3, 30 * 60e3, 60 * 60e3,
  6 * 3600e3, 12 * 3600e3, 24 * 3600e3, 48 * 3600e3,
  7 * 86400e3, 30 * 86400e3,
];

const CV_SERVER_SCENARIOS = [];
const CV_CLIENT_SCENARIOS = [];

let crlChain  = 0;    // next available CRL chain index  (0–149)
let ocspChain = 150;  // next available OCSP chain index (150–299)

const GOOD = { status: 'good', delay: 0, type: 'normal' };

// ── serverHandler factory ────────────────────────────────────────────────────

function makeServerHandler(scenarioRef) {
  return async function cvServerHandler(socket, logger, _pcap, serverConfig) {
    const tls = require('tls');
    const mgr = require('./cv-server-manager');

    const ip      = (serverConfig && serverConfig.cvServerIP) || process.env.CV_SERVER_IP  || '127.0.0.1';
    const crlPort = (serverConfig && serverConfig.crlPort)    || parseInt(process.env.CV_CRL_PORT  || '') || 18888;
    const ocspPort= (serverConfig && serverConfig.ocspPort)   || parseInt(process.env.CV_OCSP_PORT || '') || 18889;

    await mgr.init({ serverIP: ip, crlPort, ocspPort });

    // Resolve the cert chain for this scenario
    let chain;
    if (scenarioRef.deadChain) {
      chain = scenarioRef.deadChain.type === 'crl'
        ? mgr.getDeadCrlChain(scenarioRef.deadChain.index)
        : mgr.getDeadOcspChain(scenarioRef.deadChain.index);
    } else {
      chain = mgr.getChain(scenarioRef.chainIndex);
    }

    if (chain) mgr.configureScenario(scenarioRef, chain);

    const tlsOpts = chain ? mgr.buildTLSContextOpts(chain) : mgr.buildTLSContextOpts(mgr.getChain(0));

    return new Promise((resolve) => {
      let settled = false;
      const done = (result) => { if (!settled) { settled = true; resolve(result); } };

      const tlsSocket = new tls.TLSSocket(socket, { isServer: true, ...tlsOpts });

      const safetyTimer = setTimeout(() => {
        tlsSocket.destroy();
        done({ status: 'PASSED', response: 'Cert presented (no handshake within 30s)' });
      }, 30000);

      tlsSocket.on('secure', () => {
        if (logger) logger.info(`[CV] TLS done: ${scenarioRef.name}`);
        tlsSocket.write('HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
        setTimeout(() => {
          clearTimeout(safetyTimer);
          tlsSocket.destroy();
          done({ status: 'PASSED', response: 'Cert presented and TLS handshake completed' });
        }, 500);
      });

      tlsSocket.on('error', (err) => {
        clearTimeout(safetyTimer);
        if (logger) logger.info(`[CV] TLS error (${scenarioRef.name}): ${err.message}`);
        done({ status: 'PASSED', response: 'Cert presented (TLS error from peer: ' + err.message + ')' });
      });

      tlsSocket.on('close', () => {
        clearTimeout(safetyTimer);
        done({ status: 'PASSED', response: 'Cert presented (connection closed)' });
      });
    });
  };
}

// ── client scenario factory ──────────────────────────────────────────────────

function makeCvClientScenario(serverScenario) {
  const interDelay = (serverScenario.interConfig && serverScenario.interConfig.delay) || 0;
  const leafDelay  = (serverScenario.leafConfig  && serverScenario.leafConfig.delay)  || 0;
  const maxDelay   = Math.max(interDelay, leafDelay);
  const timeoutMs  = Math.max(20000, maxDelay + 15000);
  const expectedStatus = serverScenario.expected === 'allowed' ? 'PASSED' : 'DROPPED';

  return {
    name:            serverScenario.name + '-client',
    category:        'CV',
    description:     serverScenario.description + ' (client)',
    side:            'client',
    expected:        expectedStatus,
    useCustomClient: true,
    clientHandler:   async (host, port, logger) => {
      const tls = require('tls');
      return new Promise((resolve) => {
        if (logger) logger.info(`[CV-client] ${serverScenario.name}: connecting ${host}:${port} (expect ${expectedStatus})`);
        let settled = false;
        const done = (r) => { if (!settled) { settled = true; resolve(r); } };

        const timer = setTimeout(() => {
          done({ status: 'DROPPED', response: 'Connection timeout (firewall blocked or too slow)' });
        }, timeoutMs);

        let sock;
        try {
          sock = tls.connect({ host, port, rejectUnauthorized: false }, () => {
            clearTimeout(timer);
            if (logger) logger.info(`[CV-client] ALLOWED — TLS connected`);
            done({ status: 'PASSED', response: 'TLS handshake completed (ALLOWED)' });
            setTimeout(() => { try { sock.destroy(); } catch (_) {} }, 200);
          });
          sock.on('error', (err) => {
            clearTimeout(timer);
            if (logger) logger.info(`[CV-client] BLOCKED: ${err.message}`);
            done({ status: 'DROPPED', response: 'Connection failed (BLOCKED): ' + err.message });
          });
        } catch (err) {
          clearTimeout(timer);
          done({ status: 'DROPPED', response: 'Connect threw: ' + err.message });
        }
      });
    },
  };
}

// ── scenario add helpers ─────────────────────────────────────────────────────

function addCRL(name, desc, interCfg, leafCfg, expected, group) {
  const s = {
    index: CV_SERVER_SCENARIOS.length, name, description: desc, category: 'CV', side: 'server',
    certType: 'crl', chainIndex: crlChain++, deadChain: null,
    interConfig: interCfg, leafConfig: leafCfg, expected, group,
    useCustomServer: true, serverHandler: null,
  };
  s.serverHandler = makeServerHandler(s);
  CV_SERVER_SCENARIOS.push(s);
  CV_CLIENT_SCENARIOS.push(makeCvClientScenario(s));
}

function addOCSP(name, desc, interCfg, leafCfg, expected, group) {
  const s = {
    index: CV_SERVER_SCENARIOS.length, name, description: desc, category: 'CV', side: 'server',
    certType: 'ocsp', chainIndex: ocspChain++, deadChain: null,
    interConfig: interCfg, leafConfig: leafCfg, expected, group,
    useCustomServer: true, serverHandler: null,
  };
  s.serverHandler = makeServerHandler(s);
  CV_SERVER_SCENARIOS.push(s);
  CV_CLIENT_SCENARIOS.push(makeCvClientScenario(s));
}

function addDeadCRL(name, desc, deadIdx, group) {
  const s = {
    index: CV_SERVER_SCENARIOS.length, name, description: desc, category: 'CV', side: 'server',
    certType: 'crl', chainIndex: -1, deadChain: { type: 'crl', index: deadIdx },
    interConfig: null, leafConfig: null, expected: 'blocked', group,
    useCustomServer: true, serverHandler: null,
  };
  s.serverHandler = makeServerHandler(s);
  CV_SERVER_SCENARIOS.push(s);
  CV_CLIENT_SCENARIOS.push(makeCvClientScenario(s));
}

function addDeadOCSP(name, desc, deadIdx, group) {
  const s = {
    index: CV_SERVER_SCENARIOS.length, name, description: desc, category: 'CV', side: 'server',
    certType: 'ocsp', chainIndex: -1, deadChain: { type: 'ocsp', index: deadIdx },
    interConfig: null, leafConfig: null, expected: 'blocked', group,
    useCustomServer: true, serverHandler: null,
  };
  s.serverHandler = makeServerHandler(s);
  CV_SERVER_SCENARIOS.push(s);
  CV_CLIENT_SCENARIOS.push(makeCvClientScenario(s));
}

// ── CRL SCENARIOS ────────────────────────────────────────────────────────────

// Group A: Valid cert, CRL good, 15 leaf-CRL delay variations (chains 0–14)
for (let i = 0; i < 15; i++) {
  const d = DELAYS[i];
  addCRL(
    `cv-crl-valid-delay-${d}ms`,
    `Valid leaf, CRL good, leaf CRL delay ${d}ms`,
    { ...GOOD },
    { status: 'good', delay: d, type: 'normal' },
    'allowed', 'crl-valid-delay'
  );
}

// Group B: Revoked cert, CRL revoked, 15 delay variations (chains 15–29)
for (let i = 0; i < 15; i++) {
  const d = DELAYS[i];
  addCRL(
    `cv-crl-revoked-delay-${d}ms`,
    `Revoked leaf, CRL revoked, leaf CRL delay ${d}ms`,
    { ...GOOD },
    { status: 'revoked', delay: d, type: 'normal' },
    'blocked', 'crl-revoked-delay'
  );
}

// Group C: Expired leaf CRL — nextUpdate in the past (chains 30–39)
for (let i = 0; i < 10; i++) {
  const off = EXPIRED_OFFSETS[i];
  addCRL(
    `cv-crl-leaf-expired-${i + 1}`,
    `Valid leaf, leaf CRL expired (nextUpdate ${Math.round(off / 60000)}min ago)`,
    { ...GOOD },
    { status: 'good', delay: 0, type: 'expired', expiredOffset: off },
    'blocked', 'crl-leaf-expired'
  );
}

// Group D: Future leaf CRL — thisUpdate in the future (chains 40–49)
for (let i = 0; i < 10; i++) {
  const off = FUTURE_OFFSETS[i];
  addCRL(
    `cv-crl-leaf-future-${i + 1}`,
    `Valid leaf, leaf CRL thisUpdate in future (+${Math.round(off / 60000)}min)`,
    { ...GOOD },
    { status: 'good', delay: 0, type: 'future', futureOffset: off },
    'blocked', 'crl-leaf-future'
  );
}

// Group E: Unreachable CRL server — dead port (deadCrlChains 0–9)
for (let i = 0; i < 10; i++) {
  addDeadCRL(
    `cv-crl-unreachable-${i + 1}`,
    `CRL URL → dead port, connection refused (variant ${i + 1})`,
    i, 'crl-unreachable'
  );
}

// Group F: Malformed / error leaf CRL responses (chains 50–59)
const LEAF_CRL_TYPES = [
  'malformed', 'empty', 'truncated', 'wrong-sig', 'wrong-issuer',
  'http404', 'http500', 'malformed', 'empty', 'truncated',
];
for (let i = 0; i < 10; i++) {
  addCRL(
    `cv-crl-leaf-malformed-${i + 1}`,
    `Leaf CRL type: ${LEAF_CRL_TYPES[i]}`,
    { ...GOOD },
    { status: 'good', delay: 0, type: LEAF_CRL_TYPES[i] },
    'blocked', 'crl-leaf-malformed'
  );
}

// Group G: Large leaf CRL — cert NOT revoked (chains 60–69)
const LARGE_ENTRIES = [10, 50, 100, 500, 1000, 2000, 5000, 10000, 50000, 100000];
for (let i = 0; i < 10; i++) {
  addCRL(
    `cv-crl-leaf-large-${i + 1}`,
    `Valid cert; leaf CRL has ${LARGE_ENTRIES[i]} extra entries (cert not revoked)`,
    { ...GOOD },
    { status: 'good', delay: 0, type: 'normal', extraEntries: LARGE_ENTRIES[i] },
    'allowed', 'crl-leaf-large'
  );
}

// Group H: CRL revocation reasons for leaf (chains 70–79)
for (let i = 0; i < 10; i++) {
  addCRL(
    `cv-crl-leaf-reason-${REASON_NAMES[i]}`,
    `Revoked leaf, CRLReason: ${REASON_NAMES[i]} (${CRL_REASONS[i]})`,
    { ...GOOD },
    { status: 'revoked', delay: 0, type: 'normal', reason: CRL_REASONS[i] },
    'blocked', 'crl-leaf-reasons'
  );
}

// Group I: Intermediate revoked in CRL, leaf is good (chains 80–89)
for (let i = 0; i < 10; i++) {
  const d = SHORT_DELAYS[i];
  addCRL(
    `cv-crl-inter-revoked-${i + 1}`,
    `Intermediate CRL revoked, leaf good, inter CRL delay ${d}ms`,
    { status: 'revoked', delay: d, type: 'normal' },
    { ...GOOD },
    'blocked', 'crl-inter-revoked'
  );
}

// Group J: Expired intermediate CRL (chains 90–99)
for (let i = 0; i < 10; i++) {
  const off = EXPIRED_OFFSETS[i];
  addCRL(
    `cv-crl-inter-expired-${i + 1}`,
    `Inter CRL expired (${Math.round(off / 60000)}min ago), leaf CRL good`,
    { status: 'good', delay: 0, type: 'expired', expiredOffset: off },
    { ...GOOD },
    'blocked', 'crl-inter-expired'
  );
}

// Group K: Malformed / error intermediate CRL (chains 100–109)
const INTER_CRL_TYPES = [
  'malformed', 'empty', 'truncated', 'wrong-sig', 'wrong-issuer',
  'http404', 'http500', 'malformed', 'empty', 'truncated',
];
for (let i = 0; i < 10; i++) {
  addCRL(
    `cv-crl-inter-malformed-${i + 1}`,
    `Intermediate CRL type: ${INTER_CRL_TYPES[i]}, leaf CRL good`,
    { status: 'good', delay: 0, type: INTER_CRL_TYPES[i] },
    { ...GOOD },
    'blocked', 'crl-inter-malformed'
  );
}

// Group L: Future intermediate CRL (5) + dual inter+leaf delay (5) (chains 110–119)
for (let i = 0; i < 5; i++) {
  const off = FUTURE_OFFSETS[i];
  addCRL(
    `cv-crl-inter-future-${i + 1}`,
    `Inter CRL thisUpdate in future (+${Math.round(off / 60000)}min)`,
    { status: 'good', delay: 0, type: 'future', futureOffset: off },
    { ...GOOD },
    'blocked', 'crl-inter-future'
  );
}
for (let i = 0; i < 5; i++) {
  const id = SHORT_DELAYS[i + 5];
  const ld = SHORT_DELAYS[i];
  addCRL(
    `cv-crl-dual-delay-${i + 1}`,
    `Both inter CRL (${id}ms) and leaf CRL (${ld}ms) delayed, cert valid`,
    { ...GOOD, delay: id },
    { status: 'good', delay: ld, type: 'normal' },
    'allowed', 'crl-dual-delay'
  );
}

// Group M: Large intermediate CRL — cert not revoked (chains 120–129)
for (let i = 0; i < 10; i++) {
  addCRL(
    `cv-crl-inter-large-${i + 1}`,
    `Valid cert; inter CRL has ${LARGE_ENTRIES[i]} extra entries`,
    { status: 'good', delay: 0, type: 'normal', extraEntries: LARGE_ENTRIES[i] },
    { ...GOOD },
    'allowed', 'crl-inter-large'
  );
}

// Group N: Combo anomalies (chains 130–139)
for (let i = 0; i < 5; i++) {
  addCRL(
    `cv-crl-combo-leaf-revoked-inter-expired-${i + 1}`,
    `Leaf revoked, inter CRL expired — double failure`,
    { status: 'good', delay: 0, type: 'expired', expiredOffset: EXPIRED_OFFSETS[i] },
    { status: 'revoked', delay: 0, type: 'normal' },
    'blocked', 'crl-combo'
  );
}
for (let i = 0; i < 5; i++) {
  addCRL(
    `cv-crl-combo-inter-revoked-leaf-expired-${i + 1}`,
    `Intermediate revoked, leaf CRL expired — double failure`,
    { status: 'revoked', delay: 0, type: 'normal' },
    { status: 'good', delay: 0, type: 'expired', expiredOffset: EXPIRED_OFFSETS[i] },
    'blocked', 'crl-combo'
  );
}

// ── OCSP SCENARIOS ───────────────────────────────────────────────────────────

// Group O: Valid cert, OCSP good, 15 leaf-OCSP delay variations (chains 150–164)
for (let i = 0; i < 15; i++) {
  const d = DELAYS[i];
  addOCSP(
    `cv-ocsp-valid-delay-${d}ms`,
    `Valid leaf, OCSP good, leaf OCSP delay ${d}ms`,
    { ...GOOD },
    { status: 'good', delay: d, type: 'normal' },
    'allowed', 'ocsp-valid-delay'
  );
}

// Group P: Revoked cert, OCSP revoked, 15 delay variations (chains 165–179)
for (let i = 0; i < 15; i++) {
  const d = DELAYS[i];
  addOCSP(
    `cv-ocsp-revoked-delay-${d}ms`,
    `Revoked leaf, OCSP revoked, leaf OCSP delay ${d}ms`,
    { ...GOOD },
    { status: 'revoked', delay: d, type: 'normal' },
    'blocked', 'ocsp-revoked-delay'
  );
}

// Group Q: Expired leaf OCSP (chains 180–189)
for (let i = 0; i < 10; i++) {
  const off = EXPIRED_OFFSETS[i];
  addOCSP(
    `cv-ocsp-leaf-expired-${i + 1}`,
    `Valid leaf, OCSP expired (nextUpdate ${Math.round(off / 60000)}min ago)`,
    { ...GOOD },
    { status: 'good', delay: 0, type: 'expired', expiredOffset: off },
    'blocked', 'ocsp-leaf-expired'
  );
}

// Group R: Future leaf OCSP — thisUpdate in future (chains 190–199)
for (let i = 0; i < 10; i++) {
  const off = FUTURE_OFFSETS[i];
  addOCSP(
    `cv-ocsp-leaf-future-${i + 1}`,
    `Valid leaf, OCSP thisUpdate in future (+${Math.round(off / 60000)}min)`,
    { ...GOOD },
    { status: 'good', delay: 0, type: 'future', futureOffset: off },
    'blocked', 'ocsp-leaf-future'
  );
}

// Group S: Unreachable OCSP server — dead port (deadOcspChains 0–9)
for (let i = 0; i < 10; i++) {
  addDeadOCSP(
    `cv-ocsp-unreachable-${i + 1}`,
    `OCSP URL → dead port, connection refused (variant ${i + 1})`,
    i, 'ocsp-unreachable'
  );
}

// Group T: Malformed / error leaf OCSP responses (chains 200–209)
const LEAF_OCSP_TYPES = [
  'malformed', 'empty', 'tryLater', 'unauthorized', 'malformedRequest',
  'sigRequired', 'http404', 'http500', 'malformed', 'empty',
];
for (let i = 0; i < 10; i++) {
  addOCSP(
    `cv-ocsp-leaf-malformed-${i + 1}`,
    `Leaf OCSP type: ${LEAF_OCSP_TYPES[i]}`,
    { ...GOOD },
    { status: 'good', delay: 0, type: LEAF_OCSP_TYPES[i] },
    'blocked', 'ocsp-leaf-malformed'
  );
}

// Group U: Wrong-sig OCSP response + delay variations (chains 210–219)
for (let i = 0; i < 10; i++) {
  const d = SHORT_DELAYS[i];
  addOCSP(
    `cv-ocsp-wrong-sig-${i + 1}`,
    `Leaf OCSP wrong-sig, delay ${d}ms`,
    { ...GOOD },
    { status: 'good', delay: d, type: 'wrong-sig' },
    'blocked', 'ocsp-wrong-sig'
  );
}

// Group V: OCSP revocation reasons for leaf (chains 220–229)
for (let i = 0; i < 10; i++) {
  addOCSP(
    `cv-ocsp-leaf-reason-${REASON_NAMES[i]}`,
    `Revoked leaf via OCSP, reason: ${REASON_NAMES[i]} (${CRL_REASONS[i]})`,
    { ...GOOD },
    { status: 'revoked', delay: 0, type: 'normal', reason: CRL_REASONS[i] },
    'blocked', 'ocsp-leaf-reasons'
  );
}

// Group W: Intermediate revoked via OCSP, leaf good (chains 230–239)
for (let i = 0; i < 10; i++) {
  const d = SHORT_DELAYS[i];
  addOCSP(
    `cv-ocsp-inter-revoked-${i + 1}`,
    `Intermediate revoked via OCSP, leaf good, inter delay ${d}ms`,
    { status: 'revoked', delay: d, type: 'normal' },
    { ...GOOD },
    'blocked', 'ocsp-inter-revoked'
  );
}

// Group X: Expired intermediate OCSP (chains 240–249)
for (let i = 0; i < 10; i++) {
  const off = EXPIRED_OFFSETS[i];
  addOCSP(
    `cv-ocsp-inter-expired-${i + 1}`,
    `Inter OCSP expired (${Math.round(off / 60000)}min ago), leaf OCSP good`,
    { status: 'good', delay: 0, type: 'expired', expiredOffset: off },
    { ...GOOD },
    'blocked', 'ocsp-inter-expired'
  );
}

// Group Y: Malformed / error intermediate OCSP (chains 250–259)
const INTER_OCSP_TYPES = [
  'malformed', 'empty', 'tryLater', 'unauthorized', 'malformedRequest',
  'sigRequired', 'http404', 'http500', 'wrong-sig', 'malformed',
];
for (let i = 0; i < 10; i++) {
  addOCSP(
    `cv-ocsp-inter-malformed-${i + 1}`,
    `Intermediate OCSP type: ${INTER_OCSP_TYPES[i]}, leaf OCSP good`,
    { status: 'good', delay: 0, type: INTER_OCSP_TYPES[i] },
    { ...GOOD },
    'blocked', 'ocsp-inter-malformed'
  );
}

// Group Z: Dual OCSP delay — both inter and leaf delayed (chains 260–269)
for (let i = 0; i < 10; i++) {
  const id = SHORT_DELAYS[i];
  const ld = SHORT_DELAYS[(i + 5) % 10];
  addOCSP(
    `cv-ocsp-dual-delay-${i + 1}`,
    `Both inter (${id}ms) and leaf (${ld}ms) OCSP delayed, cert valid`,
    { ...GOOD, delay: id },
    { status: 'good', delay: ld, type: 'normal' },
    'allowed', 'ocsp-dual-delay'
  );
}

// Group AA: Future intermediate OCSP (5) + OCSP unknown status (5) (chains 270–279)
for (let i = 0; i < 5; i++) {
  const off = FUTURE_OFFSETS[i];
  addOCSP(
    `cv-ocsp-inter-future-${i + 1}`,
    `Inter OCSP thisUpdate in future (+${Math.round(off / 60000)}min)`,
    { status: 'good', delay: 0, type: 'future', futureOffset: off },
    { ...GOOD },
    'blocked', 'ocsp-inter-future'
  );
}
for (let i = 0; i < 5; i++) {
  addOCSP(
    `cv-ocsp-unknown-status-${i + 1}`,
    `OCSP returns unknown status for leaf cert (variant ${i + 1})`,
    { ...GOOD },
    { status: 'unknown', delay: SHORT_DELAYS[i], type: 'normal' },
    'blocked', 'ocsp-unknown-status'
  );
}

// Group AB: Combo (chains 280–289)
for (let i = 0; i < 5; i++) {
  addOCSP(
    `cv-ocsp-combo-leaf-revoked-inter-expired-${i + 1}`,
    `Leaf revoked, inter OCSP expired — double failure`,
    { status: 'good', delay: 0, type: 'expired', expiredOffset: EXPIRED_OFFSETS[i] },
    { status: 'revoked', delay: 0, type: 'normal' },
    'blocked', 'ocsp-combo'
  );
}
for (let i = 0; i < 5; i++) {
  addOCSP(
    `cv-ocsp-combo-inter-revoked-leaf-expired-${i + 1}`,
    `Intermediate revoked via OCSP, leaf OCSP expired`,
    { status: 'revoked', delay: 0, type: 'normal' },
    { status: 'good', delay: 0, type: 'expired', expiredOffset: EXPIRED_OFFSETS[i] },
    'blocked', 'ocsp-combo'
  );
}

if (CV_SERVER_SCENARIOS.length !== 300) {
  throw new Error(`Expected 300 CV server scenarios, got ${CV_SERVER_SCENARIOS.length}`);
}
if (CV_CLIENT_SCENARIOS.length !== 300) {
  throw new Error(`Expected 300 CV client scenarios, got ${CV_CLIENT_SCENARIOS.length}`);
}

const CV_CATEGORIES = {
  CV: 'Certificate Revocation Verification (CRL/OCSP)',
};

const CV_CATEGORY_SEVERITY = {
  CV: 'high',
};

function listCertVerifyScenarios() {
  const grouped = {};
  for (const s of CV_SERVER_SCENARIOS) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return { categories: CV_CATEGORIES, scenarios: grouped };
}

// Keep SCENARIOS as an alias for backward compat (standalone cert-verify-server.js uses it)
const SCENARIOS = CV_SERVER_SCENARIOS;

module.exports = {
  SCENARIOS,
  CV_SERVER_SCENARIOS,
  CV_CLIENT_SCENARIOS,
  CV_CATEGORIES,
  CV_CATEGORY_SEVERITY,
  listCertVerifyScenarios,
};
