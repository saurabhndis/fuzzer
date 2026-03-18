#!/usr/bin/env node
// Generates docs/test-scenarios.html from the live scenario definitions.
// Run: node docs/generate-test-scenarios.js

const path = require('path');
const fs = require('fs');

// Load scenario modules
const libDir = path.join(__dirname, '..', 'lib');
const { getClientScenarios, getServerScenarios, CATEGORIES, CATEGORY_SEVERITY } = require(path.join(libDir, 'scenarios'));
const { listHttp2ClientScenarios, listHttp2ServerScenarios } = require(path.join(libDir, 'http2-scenarios'));
const { listQuicClientScenarios, listQuicServerScenarios, QUIC_CATEGORIES } = require(path.join(libDir, 'quic-scenarios'));
const { getTcpClientScenarios, getTcpServerScenarios, TCP_CATEGORIES } = require(path.join(libDir, 'tcp-scenarios'));

const H2_CATEGORIES = {
  AA: 'HTTP/2 CVE & Rapid Attack', AB: 'HTTP/2 Flood / Resource Exhaustion',
  AC: 'HTTP/2 Stream & Flow Control Violations', AD: 'HTTP/2 Frame Structure & Header Attacks',
  AE: 'HTTP/2 Stream Abuse Extensions', AF: 'HTTP/2 Extended Frame Attacks',
  AG: 'HTTP/2 Flow Control Attacks', AH: 'HTTP/2 Connectivity & TLS Probes',
  AI: 'HTTP/2 General Frame Mutation', AJ: 'HTTP/2 Server-to-Client Attacks',
  AK: 'HTTP/2 Server Protocol Violations', AL: 'HTTP/2 Server Header Violations',
  AM: 'HTTP/2 Functional Validation', AN: 'HTTP/2 Firewall Detection',
  AO: 'HTTP/2 Sandbox Detection', H2S: 'HTTP/2 Server-Side Fuzzing',
};
const allCats = { ...CATEGORIES, ...QUIC_CATEGORIES, ...TCP_CATEGORIES, ...H2_CATEGORIES, RX: 'Advanced TLS/H2 TCP Fuzzing' };

// Gather all scenarios
const all = [
  ...getClientScenarios(), ...getServerScenarios(),
  ...listHttp2ClientScenarios(), ...listHttp2ServerScenarios(),
  ...listQuicClientScenarios(), ...listQuicServerScenarios(),
  ...getTcpClientScenarios(), ...getTcpServerScenarios(),
];

// Group by category
const cats = {};
for (const sc of all) {
  if (!cats[sc.category]) cats[sc.category] = [];
  cats[sc.category].push(sc);
}

function getProtocol(cat) {
  if (/^(AA|AB|AC|AD|AE|AF|AG|AH|AI|AJ|AK|AL|AM|AN|AO|H2S)$/.test(cat)) return 'h2';
  if (/^(QA|QB|QC|QD|QE|QF|QG|QH|QI|QJ|QK|QL|QS|QSCAN)$/.test(cat)) return 'quic';
  if (/^(RA|RB|RC|RD|RE|RF|RG|RH|RX)$/.test(cat)) return 'tcp';
  return 'tls';
}

function protoBadge(proto) {
  const map = { tls: 'badge-tls', h2: 'badge-h2', quic: 'badge-quic', tcp: 'badge-tcp' };
  const label = { tls: 'TLS', h2: 'HTTP/2', quic: 'QUIC', tcp: 'TCP' };
  return `<span class="protocol-badge ${map[proto]}">${label[proto]}</span>`;
}

function sevColor(sev) {
  const map = { critical: '#ef4444', high: '#f97316', medium: '#fbbf24', low: '#94a3b8', info: '#6b7280' };
  return map[sev] || '#6b7280';
}

function sevBadge(sev) {
  return `<span class="sev-badge" style="background:${sevColor(sev)};color:${sev==='medium'||sev==='low'?'black':'white'}">${sev.toUpperCase()}</span>`;
}

function esc(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

// Protocol groupings for the summary
const protocols = [
  { id: 'tls', label: 'TLS / SSL', prefix: 'tls' },
  { id: 'h2', label: 'HTTP/2', prefix: 'h2' },
  { id: 'quic', label: 'QUIC', prefix: 'quic' },
  { id: 'tcp', label: 'Raw TCP', prefix: 'tcp' },
];

// Build categories sorted by protocol then by cat code
const sortedCats = Object.keys(cats).sort((a, b) => {
  const pa = getProtocol(a), pb = getProtocol(b);
  const protoOrder = { tls: 0, h2: 1, quic: 2, tcp: 3 };
  if (protoOrder[pa] !== protoOrder[pb]) return protoOrder[pa] - protoOrder[pb];
  return a.localeCompare(b);
});

let totalScenarios = 0;
for (const arr of Object.values(cats)) totalScenarios += arr.length;

// Generate HTML
let html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protocol Fuzzer — Test Scenario Reference</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --primary: #38bdf8;
            --secondary: #818cf8;
            --text: #f1f5f9;
            --text-dim: #94a3b8;
            --accent: #f472b6;
            --warning: #fbbf24;
            --danger: #ef4444;
            --success: #10b981;
        }
        * { box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; margin: 0; padding: 0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
        header { border-bottom: 1px solid var(--surface); padding-bottom: 20px; margin-bottom: 20px; }
        h1 { font-size: 2.5rem; margin: 0; color: var(--primary); }
        h2 { font-size: 1.8rem; margin-top: 60px; color: var(--secondary); border-left: 4px solid var(--primary); padding-left: 15px; }
        h3 { font-size: 1.3rem; color: var(--accent); margin-top: 30px; }
        p { color: var(--text-dim); font-size: 1.05rem; }
        a { color: var(--primary); text-decoration: none; }
        a:hover { text-decoration: underline; }
        code { background: #334155; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: var(--accent); font-size: 0.9em; }

        .protocol-badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; margin-right: 6px; }
        .badge-tls { background: #0284c7; color: white; }
        .badge-h2 { background: #059669; color: white; }
        .badge-quic { background: #7c3aed; color: white; }
        .badge-tcp { background: #ea580c; color: white; }

        .sev-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }

        .expected-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
        .expected-dropped { background: #dc262620; color: #ef4444; border: 1px solid #ef444440; }
        .expected-passed { background: #10b98120; color: #10b981; border: 1px solid #10b98140; }
        .expected-connected { background: #38bdf820; color: #38bdf8; border: 1px solid #38bdf840; }

        /* Summary dashboard */
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin: 30px 0; }
        .dash-card { background: var(--surface); border-radius: 12px; padding: 25px; text-align: center; }
        .dash-card .num { font-size: 2.5rem; font-weight: bold; margin: 0; }
        .dash-card .label { font-size: 0.9rem; color: var(--text-dim); margin: 5px 0 0 0; }

        /* TOC */
        .toc { background: var(--surface); border-radius: 12px; padding: 25px 30px; margin: 30px 0; columns: 2; column-gap: 40px; }
        .toc-group { break-inside: avoid; margin-bottom: 15px; }
        .toc-group h4 { margin: 0 0 8px 0; font-size: 1rem; }
        .toc-group ul { margin: 0; padding-left: 18px; list-style: none; }
        .toc-group ul li { margin: 3px 0; font-size: 0.9rem; }
        .toc-group ul li a { color: var(--text-dim); }
        .toc-group ul li a:hover { color: var(--primary); }
        .toc-count { color: var(--text-dim); font-size: 0.8rem; }

        /* Category sections */
        .cat-header { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
        .cat-header h2 { margin: 0; flex-shrink: 0; }
        .cat-meta { display: flex; gap: 8px; align-items: center; }

        .cat-description { color: var(--text-dim); font-size: 1rem; margin: 10px 0 20px 0; border-left: 3px solid #334155; padding-left: 15px; }

        /* Scenario table */
        .scenario-table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 10px; overflow: hidden; margin: 15px 0 40px 0; font-size: 0.88rem; }
        .scenario-table thead th { background: #334155; color: var(--primary); padding: 10px 12px; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; z-index: 1; }
        .scenario-table tbody td { padding: 8px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }
        .scenario-table tbody tr:last-child td { border-bottom: none; }
        .scenario-table tbody tr:hover { background: #334155; }
        .scenario-table .name { color: var(--text); font-family: monospace; font-size: 0.85rem; white-space: nowrap; }
        .scenario-table .desc { color: var(--text-dim); max-width: 500px; }
        .scenario-table .side { text-align: center; }
        .scenario-table .side-client { color: var(--primary); }
        .scenario-table .side-server { color: var(--accent); }
        .scenario-table .expected { text-align: center; }

        /* Collapsible for large categories */
        details { margin: 0; }
        details summary { cursor: pointer; padding: 10px 15px; background: #334155; border-radius: 8px; margin-bottom: 10px; font-size: 0.95rem; color: var(--text); user-select: none; }
        details summary:hover { background: #3b4d63; }
        details[open] summary { border-radius: 8px 8px 0 0; margin-bottom: 0; }

        /* Footer */
        .footer { margin-top: 80px; text-align: center; color: var(--text-dim); font-size: 0.9rem; border-top: 1px solid var(--surface); padding-top: 20px; }

        /* Responsive */
        @media (max-width: 768px) {
            .toc { columns: 1; }
            .scenario-table { font-size: 0.8rem; }
            .scenario-table .desc { max-width: 250px; }
            .dashboard { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Test Scenario Reference</h1>
            <p>Complete reference of all ${totalScenarios.toLocaleString()} test scenarios across TLS, HTTP/2, QUIC, and Raw TCP protocols. Each scenario is a self-contained test case with a defined expected outcome.</p>
        </header>
`;

// Dashboard
const protoCounts = {};
for (const cat of sortedCats) {
  const p = getProtocol(cat);
  if (!protoCounts[p]) protoCounts[p] = 0;
  protoCounts[p] += cats[cat].length;
}
const sevCounts = {};
for (const cat of sortedCats) {
  const sev = CATEGORY_SEVERITY[cat] || 'info';
  if (!sevCounts[sev]) sevCounts[sev] = 0;
  sevCounts[sev] += cats[cat].length;
}

html += `
        <div class="dashboard">
            <div class="dash-card"><p class="num" style="color:var(--primary)">${totalScenarios.toLocaleString()}</p><p class="label">Total Scenarios</p></div>
            <div class="dash-card"><p class="num" style="color:#0284c7">${protoCounts.tls || 0}</p><p class="label">TLS / SSL</p></div>
            <div class="dash-card"><p class="num" style="color:#059669">${protoCounts.h2 || 0}</p><p class="label">HTTP/2</p></div>
            <div class="dash-card"><p class="num" style="color:#7c3aed">${protoCounts.quic || 0}</p><p class="label">QUIC</p></div>
            <div class="dash-card"><p class="num" style="color:#ea580c">${protoCounts.tcp || 0}</p><p class="label">Raw TCP</p></div>
            <div class="dash-card"><p class="num" style="color:var(--danger)">${sevCounts.critical || 0}</p><p class="label">Critical Severity</p></div>
            <div class="dash-card"><p class="num" style="color:var(--warning)">${sevCounts.high || 0}</p><p class="label">High Severity</p></div>
            <div class="dash-card"><p class="num" style="color:var(--text-dim)">${(sevCounts.medium||0)+(sevCounts.low||0)+(sevCounts.info||0)}</p><p class="label">Medium / Low / Info</p></div>
        </div>
`;

// Table of Contents
html += `
        <h2 style="margin-top:40px">Table of Contents</h2>
        <div class="toc">
`;

let currentProto = '';
for (const cat of sortedCats) {
  const proto = getProtocol(cat);
  if (proto !== currentProto) {
    if (currentProto) html += `</ul></div>`;
    currentProto = proto;
    const protoLabel = { tls: 'TLS / SSL', h2: 'HTTP/2', quic: 'QUIC', tcp: 'Raw TCP' }[proto];
    html += `<div class="toc-group"><h4>${protoBadge(proto)} ${protoLabel}</h4><ul>`;
  }
  const name = allCats[cat] || cat;
  const sev = CATEGORY_SEVERITY[cat] || 'info';
  html += `<li><a href="#cat-${cat}">${cat}</a> — ${esc(name)} <span class="toc-count">(${cats[cat].length})</span></li>\n`;
}
html += `</ul></div></div>`;

// Category descriptions (manually enriched)
const catDescriptions = {
  A: 'Tests whether the target correctly rejects TLS handshake messages received in illegal order. A properly implemented TLS state machine should send a fatal alert and terminate the connection when it receives a Finished, ClientKeyExchange, or Certificate message before a ClientHello.',
  C: 'Mutates fields within an otherwise valid ClientHello to test parser robustness. Includes version downgrades (advertising TLS 1.0 in a 1.2 handshake), session ID corruption, SNI hostname mismatches, and random value overwrites.',
  D: 'Injects TLS alert records at incorrect points in the handshake state machine. Tests include sending warning alerts during handshake, fatal alerts followed by continued data, close_notify mid-handshake, unknown alert types, and alert floods.',
  E: 'Attacks the TCP layer beneath the TLS handshake. Sends TCP FIN after ClientHello, RST mid-handshake, performs half-close then continues sending, drips ClientHello byte-by-byte (1 byte per 20ms), and fragments TLS records across TCP segments.',
  F: 'Targets the TLS record layer with malformed records. Includes wrong record version fields, oversized records (>16KB), zero-length records, wrong content types, incorrect length fields, interleaved content types, and garbage data between valid records.',
  G: 'Injects ChangeCipherSpec (CCS) records at illegal points in the handshake. Tests early CCS (before ServerHelloDone), multiple CCS records, CCS before any ClientHello, and CCS with embedded payload data. Based on the CCS Injection attack (CVE-2014-0224).',
  H: 'Fuzzes TLS ClientHello extensions with structural errors. Tests duplicate extension IDs, unknown/undefined extension types (0xFEED, 0xBEEF), oversized extensions (64KB), empty SNI values, and malformed supported_versions.',
  I: 'Probes for 32 known TLS/SSL CVEs including Heartbleed (CVE-2014-0160), POODLE (CVE-2014-3566), CCS Injection (CVE-2014-0224), FREAK (CVE-2015-0204), Logjam (CVE-2015-4000), DROWN (CVE-2016-0800), Sweet32 (CVE-2016-2183), CRIME (CVE-2012-4929), RC4 Bias, BEAST, Ticketbleed, and more.',
  J: 'Tests Post-Quantum Cryptography (PQC) key exchange support and robustness. Includes X25519+ML-KEM-768 hybrid (1216B), standalone ML-KEM-768, X25519Kyber768 draft format, malformed PQC key shares, oversized shares (10KB), and ML-KEM-1024.',
  K: 'Evades SNI-based Deep Packet Inspection (DPI) by fragmenting the ClientHello so that the SNI hostname is not in the first TCP segment. Techniques include delayed SNI, hostname-boundary splits, 1-byte TCP fragments, multiple SNI entries, IP addresses in SNI, and oversized hostnames.',
  L: 'Fuzzes ALPN (Application-Layer Protocol Negotiation) with invalid protocol identifiers. Tests unknown protocols, empty protocol strings, oversized lists (50 entries), duplicate "h2" entries, 255-byte protocol names, and wrong list length fields.',
  M: 'Attacks the internal structure of individual TLS extensions. Sends extensions with wrong inner length fields (too short, too long), truncated key_share payloads, supported_versions with odd byte counts, and empty signature_algorithms.',
  N: 'Tests "parameter reneging" — changing negotiated parameters between handshake messages. Includes cipher suite downgrades mid-handshake, version switches between ClientHello and Finished, and conflicting parameter values across messages.',
  O: 'Fuzzes TLS 1.3 early data (0-RTT) mechanisms. Sends early data without proper PSK, replays 0-RTT data, binds PSK to wrong identities, and manipulates the early_exporter_master_secret.',
  P: 'Advanced attacks on TLS record/handshake message boundaries. Packs multiple handshake messages into a single record, splits one handshake across many records, fragments handshake messages mid-field, and sends out-of-sequence fragments.',
  Q: 'Mutates individual fields within the ClientHello message body. Attacks session ID length/content, cipher suite list ordering and padding, compression method fields, random value bytes, and supported_versions list entries.',
  R: 'Fuzzes the inner byte structure of TLS extensions. Attacks key_share format at the byte level, supported_groups encoding, signature_algorithms truncation, and extension length field off-by-one errors.',
  S: 'Byte-level attacks on TLS record headers. Flips individual bits in version bytes, varies content type values, introduces off-by-one in length fields, and tests version/length field boundary conditions.',
  T: 'Byte-level fuzzing of TLS Alert and ChangeCipherSpec messages. Flips alert level/description bits, injects payload into CCS records, sends multiple CCS bytes, and corrupts alert record format.',
  U: 'Sends handshake messages with undefined or legacy type codes. Includes undefined types (0xFF), SSLv2 ClientHello format, heartbeat extension requests (Heartbleed vector), and SSLv3 remnant messages.',
  V: 'Fuzzes cipher suite and signature algorithm values. Sends unknown cipher suite IDs, mismatched signature algorithms, unsupported signing algorithms, GREASE values (RFC 8701), and reordered cipher suite lists.',
  X: 'Sends unsolicited or malformed client certificates. Tests include certificates sent without CertificateRequest, self-signed certs with wrong key sizes, expired certificates, and certificate validation bypass attempts.',
  Z: 'Well-behaved counterparts that implement correct TLS behavior. Used internally for distributed mode testing to verify that compliant connections succeed. Includes standard TLS handshake and HTTP GET/POST over TLS.',
  FV: 'Functional validation baselines — complete, correct TLS handshakes followed by real HTTP GET/POST traffic. These are non-fuzzing scenarios that establish ground truth for the target\'s normal operation.',
  FW: 'Sends 104 known malicious payloads (malware signatures, SQL injection, XSS, command injection, exploit code, etc.) as HTTP POST bodies over TLS. The target firewall/IPS should detect and block each payload. Payload echoed back unchanged means detection failure.',
  SB: 'Sends 55 sandbox-evasion payloads (exploit kit landing pages, obfuscated JavaScript, browser exploits, cryptocurrency miners, droppers) to a well-behaved echo server. The firewall should detect malicious content in the response body and block it.',
  SRV: 'Server-side TLS fuzzing — the fuzzer acts as a malicious TLS server. Sends invalid ServerHello, premature CCS, wrong cipher suite selection, corrupted certificates, and truncated handshake messages to connecting clients.',
  SCAN: 'Non-fuzzing compatibility scanning. Tests every combination of TLS version (SSL 3.0 through TLS 1.3), cipher suite, named group, and signature algorithm to map the target\'s supported configuration matrix.',
  PAN: 'Palo Alto Networks URL category detection probes. Sends TLS ClientHello with SNI set to known domains from 30 URL categories (adult, malware, phishing, gambling, etc.) to verify PAN-OS URL filtering policy enforcement.',
  'PAN-PQC': 'Combines PQC key exchange bloat (~2KB ClientHello) with SNI fragmentation to test whether PAN-OS can still categorize URLs when the SNI hostname is delayed to the second TLS record or split across record boundaries.',

  // HTTP/2
  AA: 'Tests critical HTTP/2 CVEs. Rapid Reset (CVE-2023-44487): opens 100 streams with immediate RST_STREAM to overwhelm the server. CONTINUATION Flood: sends 50 CONTINUATION frames without END_HEADERS to exhaust server header buffers.',
  AB: 'Resource exhaustion attacks. SETTINGS flood (1000 frames), PING flood (1000 frames), and empty DATA frame flood (50 frames per stream). Tests server rate limiting and backpressure mechanisms.',
  AC: 'Violates HTTP/2 stream and flow control rules. Opens 110 streams when the limit is 100, sends erratic WINDOW_UPDATE (zero increment, on closed streams, max overflow), exceeds initial flow control window, and creates circular PRIORITY dependencies.',
  AD: 'Attacks HTTP/2 frame structure and headers. Sends SETTINGS on non-zero stream ID, HEADERS on stream 0, stray CONTINUATION without preceding HEADERS, undefined frame types (0xFF), HPACK bombs, and frames with wrong payload sizes.',
  AE: 'Extended stream abuse vectors including RST_STREAM flood (CVE-2019-9514) and dependency cycle attacks.',
  AF: 'Malformed frame attacks: corrupted RST_STREAM payload, PUSH_PROMISE without SETTINGS enablement, invalid GOAWAY frames, and corrupted DATA payloads.',
  AG: 'Flow control window manipulation. Exhausts connection-level windows, overflows increment counters, manipulates per-stream windows. Includes CVE-2019-9517 (internal data buffering).',
  AH: 'Non-fuzzing HTTP/2 connectivity probes. Tests TCP reachability, TLS ALPN negotiation, HTTP/2 preface exchange, and SETTINGS round-trip across different TLS configurations.',
  AI: 'Randomized frame mutation — sends frames with random type, flags, stream ID, and payload to test parser robustness against unexpected input.',
  AJ: 'Server-to-client attacks where the fuzzer acts as a malicious HTTP/2 server. Sends unsolicited PUSH_PROMISE, invalid response headers, and corrupted DATA frames.',
  AK: 'Server protocol violations — the fuzzer server sends frames that violate HTTP/2 RFC rules (wrong stream states, invalid frame sequences, flow control violations).',
  AL: 'Server header field violations per RFC 9113 section 8.1.2. Tests invalid pseudo-headers, duplicate pseudo-headers, missing required headers in responses.',
  AM: 'Functional validation baselines for HTTP/2. Performs normal GET and POST requests, proper stream lifecycle, clean SETTINGS exchange, and GOAWAY shutdown.',
  AN: 'Same 104 firewall detection payloads as FW category, delivered via HTTP/2 POST bodies instead of TLS. Tests whether the firewall inspects HTTP/2 streams for malicious content.',
  AO: 'Same 55 sandbox detection payloads as SB category, delivered via HTTP/2. Tests whether the firewall inspects HTTP/2 response bodies for sandbox-evasion content.',
  H2S: 'HTTP/2 server-side fuzzing — the fuzzer acts as a malicious server. Includes PUSH flood, malformed response headers, corrupted DATA frames, and invalid SETTINGS ACKs.',

  // QUIC
  QA: 'QUIC handshake and connection initialization fuzzing. Tests ClientHello ordering within CRYPTO frames, incomplete handshakes, duplicate Initial packets, version mismatches, and PQC key share injection.',
  QB: 'Corrupts QUIC transport parameters and ALPN negotiation. Tests invalid transport parameter values and ALPN/SNI fuzzing within QUIC Initial packets.',
  QC: 'QUIC resource exhaustion and DoS attacks. Tests CRYPTO frame buffer gaps, amplification padding attacks, and connection flood scenarios.',
  QD: 'QUIC flow control and stream error fuzzing. Tests ACK range manipulation, stream data overlap, and invalid stream frame fields.',
  QE: 'QUIC connection migration and path validation fuzzing. Tests path challenge/response manipulation.',
  QF: 'QUIC frame structure mutations. Sends undefined frame types and tests post-handshake HTTP request smuggling attempts.',
  QG: 'Maps TLS handshake order violation scenarios (Category A-G) into QUIC CRYPTO frames. Tests the same state machine attacks but delivered over QUIC Initial packets instead of raw TCP. Largest QUIC category with 711 scenarios.',
  QH: 'Maps TLS parameter mutation and extension fuzzing (Category C, H, M, R) into QUIC. Tests ClientHello field mutations, extension structure attacks, and parameter conflicts delivered via QUIC.',
  QI: 'Maps TLS alert injection and record layer attacks (Category D, F, S, T) into QUIC. Tests alert message injection and record format violations within QUIC CRYPTO frames.',
  QJ: 'Maps TLS CVE detection and PQC scenarios (Category I, J) plus cipher/signature fuzzing (Category V) into QUIC. Probes for Heartbleed, POODLE, and other CVEs over QUIC transport.',
  QK: 'Maps TLS client certificate abuse scenarios (Category X) into QUIC. Tests unsolicited certificates, malformed cert chains, and validation bypass attempts over QUIC.',
  QS: 'QUIC server-side fuzzing — the fuzzer acts as a malicious QUIC server. Sends stream resets, STOP_SENDING frames, invalid transport parameters, and malformed server responses.',
  QSCAN: 'Non-fuzzing QUIC compatibility scanning. Probes QUIC version 1 and version 2 with different cipher suites, named groups (including PQC), and ALPN values to map server support.',

  // TCP
  RA: 'SYN flood attacks. Sends 100–1000 SYN packets (optionally with spoofed source IPs), SYN packets with data payload, and SYN with zero window size.',
  RB: 'TCP RST injection. Sends RST with wrong sequence numbers, valid-sequence RST during data transfer, and RST during the three-way handshake.',
  RC: 'Manipulates TCP sequence numbers and ACKs. Sends data with future sequence numbers, past sequence numbers, and duplicate ACK floods.',
  RD: 'TCP window attacks. Sends zero-window advertisements, shrinks window mid-connection, and oscillates window size rapidly.',
  RE: 'TCP segment reordering and overlap. Sends segments out of order, sends overlapping segments with conflicting data, and reverses segment delivery order.',
  RF: 'TCP urgent pointer attacks. Sends URG pointer past actual data length and URG flag with zero-length urgent data.',
  RG: 'TCP state machine fuzzing. Sends data before completing the three-way handshake, FIN before handshake, XMAS scan (all flags set), NULL scan (no flags), and ACK-only packets.',
  RH: 'TCP option negotiation attacks. Negotiates timestamp/MSS/SACK options during handshake then violates them during data transfer — drops timestamps, changes MSS, sends invalid SACK blocks.',
  RX: 'Combined TCP + TLS/HTTP2 attacks. Sends TLS ClientHello with overlapping TCP segments, HTTP/2 connection preface with out-of-order segments, and TLS record split across reordered TCP segments.',
};

// Generate category sections
for (const cat of sortedCats) {
  const arr = cats[cat];
  const proto = getProtocol(cat);
  const name = allCats[cat] || cat;
  const sev = CATEGORY_SEVERITY[cat] || 'info';
  const desc = catDescriptions[cat] || '';

  html += `
        <section id="cat-${cat}">
            <div class="cat-header">
                <h2>${esc(cat)} — ${esc(name)}</h2>
                <div class="cat-meta">
                    ${protoBadge(proto)}
                    ${sevBadge(sev)}
                    <span style="color:var(--text-dim);font-size:0.9rem">${arr.length} scenario${arr.length!==1?'s':''}</span>
                </div>
            </div>
`;

  if (desc) {
    html += `            <p class="cat-description">${desc}</p>\n`;
  }

  // For categories with > 30 scenarios, use collapsible
  const useCollapsible = arr.length > 30;
  if (useCollapsible) {
    html += `            <details><summary>Show all ${arr.length} scenarios</summary>\n`;
  }

  html += `            <table class="scenario-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Scenario Name</th>
                        <th>Description</th>
                        <th>Side</th>
                        <th>Expected</th>
                    </tr>
                </thead>
                <tbody>
`;

  for (let i = 0; i < arr.length; i++) {
    const sc = arr[i];
    const expected = sc.expected || 'DROPPED';
    const expClass = expected === 'DROPPED' ? 'expected-dropped' : expected === 'PASSED' ? 'expected-passed' : 'expected-connected';
    const sideClass = sc.side === 'client' ? 'side-client' : 'side-server';
    html += `                    <tr>
                        <td style="color:var(--text-dim)">${i+1}</td>
                        <td class="name">${esc(sc.name)}</td>
                        <td class="desc">${esc(sc.description)}</td>
                        <td class="side ${sideClass}">${sc.side}</td>
                        <td class="expected"><span class="expected-badge ${expClass}">${esc(expected)}</span></td>
                    </tr>
`;
  }

  html += `                </tbody>
            </table>
`;
  if (useCollapsible) {
    html += `            </details>\n`;
  }
  html += `        </section>\n`;
}

// Expected output guide
html += `
        <section id="expected-output-guide">
            <h2>Understanding Expected Output</h2>
            <p>Every scenario has an <strong>expected</strong> field that defines what correct target behavior looks like.</p>

            <table class="scenario-table" style="max-width:900px">
                <thead>
                    <tr><th>Expected Value</th><th>What It Means</th><th>When Target Passes</th><th>When Target Fails</th></tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="expected-badge expected-dropped">DROPPED</span></td>
                        <td>The target should <strong>reject</strong> this input &mdash; it is malformed, illegal, or malicious.</td>
                        <td>Target sends a TLS Alert, TCP RST, HTTP 403, GOAWAY, or drops the connection silently. <strong>Verdict: AS EXPECTED.</strong></td>
                        <td>Target accepts the input, continues the handshake, or echoes the payload. <strong>Verdict: UNEXPECTED</strong> &mdash; indicates a vulnerability or detection gap.</td>
                    </tr>
                    <tr>
                        <td><span class="expected-badge expected-passed">PASSED</span></td>
                        <td>The target should <strong>accept</strong> this input &mdash; it is valid and RFC-compliant.</td>
                        <td>Target completes the handshake, responds with valid data, or acknowledges the connection. <strong>Verdict: AS EXPECTED.</strong></td>
                        <td>Target rejects a valid connection, sends unexpected alerts, or crashes. <strong>Verdict: UNEXPECTED</strong> &mdash; indicates a false positive or misconfiguration.</td>
                    </tr>
                    <tr>
                        <td><span class="expected-badge expected-connected">CONNECTED</span></td>
                        <td>The target should <strong>establish a connection</strong> (used for connectivity scanning).</td>
                        <td>TCP/TLS/QUIC connection succeeds. <strong>Verdict: AS EXPECTED.</strong></td>
                        <td>Connection refused, timeout, or TLS handshake failure. <strong>Verdict: UNEXPECTED.</strong></td>
                    </tr>
                </tbody>
            </table>

            <h3>Verdict to Grade Mapping</h3>
            <table class="scenario-table" style="max-width:700px">
                <thead>
                    <tr><th>Verdict</th><th>Severity</th><th>Grade Impact</th></tr>
                </thead>
                <tbody>
                    <tr><td>AS EXPECTED</td><td>Any</td><td style="color:var(--success)"><strong>PASS</strong> &mdash; no impact on grade</td></tr>
                    <tr><td>UNEXPECTED</td><td>Critical</td><td style="color:var(--danger)"><strong>FAIL</strong> &mdash; drops grade to F</td></tr>
                    <tr><td>UNEXPECTED</td><td>High</td><td style="color:var(--danger)"><strong>FAIL</strong> &mdash; drops grade to D or lower</td></tr>
                    <tr><td>UNEXPECTED</td><td>Medium</td><td style="color:var(--warning)"><strong>FAIL</strong> &mdash; drops grade to C or lower</td></tr>
                    <tr><td>UNEXPECTED</td><td>Low / Info</td><td style="color:var(--text-dim)"><strong>WARN</strong> &mdash; noted but minimal grade impact</td></tr>
                </tbody>
            </table>

            <h3>Overall Grade Scale</h3>
            <table class="scenario-table" style="max-width:700px">
                <thead>
                    <tr><th>Grade</th><th>Meaning</th><th>Criteria</th></tr>
                </thead>
                <tbody>
                    <tr><td style="color:var(--success);font-size:1.2rem;font-weight:bold">A</td><td>Excellent</td><td>All tests pass, no crashes, no unexpected behavior</td></tr>
                    <tr><td style="color:#22d3ee;font-size:1.2rem;font-weight:bold">B</td><td>Good</td><td>No critical or high-severity failures</td></tr>
                    <tr><td style="color:var(--warning);font-size:1.2rem;font-weight:bold">C</td><td>Fair</td><td>No critical failures, some high/medium issues</td></tr>
                    <tr><td style="color:#f97316;font-size:1.2rem;font-weight:bold">D</td><td>Poor</td><td>High-severity failures present</td></tr>
                    <tr><td style="color:var(--danger);font-size:1.2rem;font-weight:bold">F</td><td>Failing</td><td>Critical CVE accepted, host crashed, or widespread failures</td></tr>
                </tbody>
            </table>
        </section>
`;

// Footer
html += `
        <div class="footer">
            Protocol Fuzzer — Test Scenario Reference &bull; ${totalScenarios.toLocaleString()} scenarios &bull; Generated ${new Date().toISOString().slice(0,10)} &bull; Auto-generated from scenario definitions
        </div>
    </div>
</body>
</html>
`;

const outPath = path.join(__dirname, 'test-scenarios.html');
fs.writeFileSync(outPath, html, 'utf8');
console.log(`Generated ${outPath}`);
console.log(`  Total scenarios: ${totalScenarios}`);
console.log(`  Total categories: ${sortedCats.length}`);
console.log(`  File size: ${(Buffer.byteLength(html) / 1024).toFixed(0)} KB`);
