#!/usr/bin/env node
// Generate test-scenarios.md and test-scenarios.html from scenario source files
'use strict';

const path = require('path');
const fs = require('fs');

// ── Load all scenario sources ────────────────────────────────────────────────

const { SCENARIOS, CATEGORIES, CATEGORY_SEVERITY } = require('../lib/scenarios');
const { HTTP2_SCENARIOS, HTTP2_CATEGORIES, HTTP2_CATEGORY_SEVERITY } = require('../lib/http2-scenarios');
const { QUIC_SCENARIOS, QUIC_CATEGORIES, QUIC_CATEGORY_SEVERITY } = require('../lib/quic-scenarios');
const { TCP_SCENARIOS, TCP_CATEGORIES, TCP_CATEGORY_SEVERITY } = require('../lib/tcp-scenarios');
const { SCAN_SCENARIOS, SCAN_CATEGORIES } = require('../lib/scan-scenarios');
const { QUIC_SCAN_SCENARIOS, QUIC_SCAN_CATEGORIES } = require('../lib/quic-scan-scenarios');

// ── Severity emoji mapping ──────────────────────────────────────────────────

const SEVERITY_EMOJI = {
  critical: '\u{1F534}',  // red circle
  high:     '\u{1F7E0}',  // orange circle
  medium:   '\u{1F7E1}',  // yellow circle
  low:      '\u{1F7E2}',  // green circle
  info:     '\u26AA',      // white circle
};

// ── Severity reason descriptions (used for pass/fail criteria) ──────────────

const SEVERITY_REASONS = {
  A:   'handshake order violations (protocol state machine bypass)',
  C:   'parameter mutation (downgrade/mismatch attacks)',
  D:   'alert injection (protocol confusion)',
  E:   'TCP manipulation abuse',
  F:   'record layer violations (fundamental protocol violations)',
  G:   'CCS attacks (CVE-2014-0224 vector)',
  H:   'extension fuzzing (parser robustness)',
  I:   'known vulnerability vectors (CVE detection)',
  J:   'invalid PQC key material',
  K:   'SNI evasion and fragmentation attacks',
  L:   'ALPN protocol confusion',
  M:   'extension malformation (parser crash/memory corruption)',
  N:   'parameter reneging (mid-stream downgrade/confusion attacks)',
  O:   'invalid TLS 1.3 early data and PSK abuse',
  P:   'advanced handshake record malformation',
  Q:   'ClientHello field mutations (body-level corruption)',
  R:   'malformed extension inner structures (sub-field corruption)',
  S:   'record layer byte attacks (header-level mutations)',
  T:   'alert & CCS byte-level attacks (message format corruption)',
  U:   'handshake type & legacy protocol attacks',
  V:   'cipher suite & signature algorithm attacks',
  X:   'client certificate abuse (unsolicited/malformed certs)',
  Z:   'well-behaved traffic patterns',
  FV:  'functional validation failures',
  FW:  'firewall detection (known malicious payloads)',
  SB:  'sandbox detection (malicious JS/dynamic content)',
  SRV: 'server-side protocol violations',
  SCAN: 'compatibility scanning',
  PAN: 'PAN-OS URL category SNI probes',
  'PAN-PQC': 'PAN-OS PQC + SNI evasion probes',
  AA:  'HTTP/2 CVE & rapid attack vectors',
  AB:  'HTTP/2 flood / resource exhaustion',
  AC:  'HTTP/2 stream & flow control violations',
  AD:  'HTTP/2 frame structure & header attacks',
  AE:  'HTTP/2 stream abuse extensions',
  AF:  'HTTP/2 extended frame attacks',
  AG:  'HTTP/2 flow control attacks',
  AH:  'HTTP/2 connectivity & TLS probes',
  AI:  'HTTP/2 general frame mutation',
  AJ:  'HTTP/2 server-to-client attacks',
  AK:  'HTTP/2 server protocol violations',
  AL:  'HTTP/2 server header violations',
  AM:  'HTTP/2 functional validation',
  AN:  'HTTP/2 firewall detection',
  AO:  'HTTP/2 sandbox detection',
  H2S: 'HTTP/2 server-side fuzzing',
  QA:  'QUIC handshake & connection initial attacks',
  QB:  'QUIC transport parameter & ALPN attacks',
  QC:  'QUIC resource exhaustion & DoS',
  QD:  'QUIC flow control & stream errors',
  QE:  'QUIC connection migration & path attacks',
  QF:  'QUIC frame structure & mutation',
  QG:  'QUIC-TLS handshake order & state violations',
  QH:  'QUIC-TLS parameter & extension fuzzing',
  QI:  'QUIC-TLS record & alert injection',
  QJ:  'QUIC-TLS known CVEs & PQC attacks',
  QK:  'QUIC-TLS certificate fuzzing',
  QL:  'QUIC server-to-client attacks',
  QS:  'QUIC server-side fuzzing',
  QSCAN: 'QUIC compatibility scanning',
  RA:  'TCP SYN attacks',
  RB:  'TCP RST injection',
  RC:  'TCP sequence/ACK manipulation',
  RD:  'TCP window attacks',
  RE:  'TCP segment reordering & overlap',
  RF:  'TCP urgent pointer attacks',
  RG:  'TCP state machine fuzzing',
  RH:  'TCP option fuzzing',
  RX:  'advanced TLS/H2 TCP fuzzing',
};

// ── Build pass/fail criteria string ─────────────────────────────────────────

// Infer expected value when not explicitly set.
// Security categories (critical, high, medium) default to DROPPED.
// Low/info categories default to PASSED unless the scenario is server-side fuzzing.
function inferExpected(scenario, allSeverity) {
  if (scenario.expected) return scenario.expected;
  const sev = allSeverity[scenario.category];
  if (sev === 'info' || sev === 'low') return 'PASSED';
  // Security categories default to DROPPED
  return 'DROPPED';
}

function buildPassFailCriteria(scenario, allSeverity) {
  const expected = inferExpected(scenario, allSeverity);
  const reason = scenario.expectedReason;
  const cat = scenario.category;
  const catReason = SEVERITY_REASONS[cat];

  if (expected === 'DROPPED') {
    if (reason) {
      return `\u2705 if rejected; \u274C if accepted. ${reason}`;
    }
    return `\u2705 if rejected; \u274C if accepted. Must reject ${catReason || 'malformed input'}`;
  }
  if (expected === 'PASSED') {
    if (reason) {
      return `\u2705 if accepted; \u26A0\uFE0F if rejected. ${reason}`;
    }
    return `\u2705 if accepted; \u26A0\uFE0F if rejected. Server responds if it supports this combination`;
  }
  if (expected === 'CONNECTED') {
    if (reason) {
      return `\u2705 if connected. ${reason}`;
    }
    return `\u2705 if connected. Connection should succeed`;
  }
  if (expected === 'FAILED_CONNECTION') {
    if (reason) {
      return `\u2705 if connection fails. ${reason}`;
    }
    return `\u2705 if connection fails. Target should reject this connection`;
  }
  if (expected === 'TIMEOUT') {
    if (reason) {
      return `\u2705 if timeout/no response. ${reason}`;
    }
    return `\u2705 if timeout/no response. Target should not respond`;
  }
  // No expected value
  if (reason) {
    return reason;
  }
  if (catReason) {
    return `Must reject ${catReason}`;
  }
  return 'Behavior observed for analysis';
}

// ── Side indicator ──────────────────────────────────────────────────────────

function sideArrow(side) {
  return side === 'server' ? '\u2190' : '\u2192';
}

function sideLabel(side) {
  return side === 'server' ? 'Server \u2192 Client' : 'Client \u2192 Server';
}

// ── Slugify for anchor links ────────────────────────────────────────────────

function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .trim();
}

// ── Group scenarios by category ─────────────────────────────────────────────

function groupByCategory(scenarios) {
  const groups = {};
  for (const s of scenarios) {
    if (!groups[s.category]) groups[s.category] = [];
    groups[s.category].push(s);
  }
  return groups;
}

// ── Count sides ─────────────────────────────────────────────────────────────

function countSides(scenarios) {
  let client = 0, server = 0;
  for (const s of scenarios) {
    if (s.side === 'server') server++;
    else client++;
  }
  return { client, server };
}

function sideBreakdown(scenarios) {
  const { client, server } = countSides(scenarios);
  const parts = [];
  if (client > 0) parts.push(`${client} Client \u2192 Server`);
  if (server > 0) parts.push(`${server} Server \u2192 Client`);
  return parts.join(', ');
}

// ── Protocol sections definition ────────────────────────────────────────────

// Define all protocol sections with their scenarios, categories, and severity maps.
// The order of categoryOrder defines the display order of categories within each section.

function buildProtocolSections() {
  // Build TLS scenarios: SCENARIOS (minus those in SCAN) + FW_TLS + SB_TLS
  // Note: FW_TLS and SB_TLS are already included in SCENARIOS via the push in scenarios.js
  // Let's verify by checking categories
  const tlsGroups = groupByCategory(SCENARIOS);

  // TLS category order: A through Z, then FV, FW, SB, SRV, PAN, PAN-PQC
  const tlsCategoryOrder = [
    'A', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'X', 'Z',
    'FV', 'FW', 'SB', 'SRV', 'PAN', 'PAN-PQC',
  ];

  // HTTP/2 category order
  const h2CategoryOrder = [
    'AA', 'AB', 'AC', 'AD', 'AE', 'AF', 'AG', 'AH', 'AI',
    'AJ', 'AK', 'AL',
    'AM', 'AN', 'AO', 'H2S', 'PAN', 'PAN-PQC',
  ];

  // QUIC category order
  const quicCategoryOrder = [
    'QA', 'QB', 'QC', 'QD', 'QE', 'QF',
    'QG', 'QH', 'QI', 'QJ', 'QK',
    'QL', 'QS', 'PAN',
  ];

  // Merge all category names and severities
  const allCategories = { ...CATEGORIES, ...HTTP2_CATEGORIES, ...QUIC_CATEGORIES, ...TCP_CATEGORIES, ...SCAN_CATEGORIES, ...QUIC_SCAN_CATEGORIES };
  const allSeverity = { ...CATEGORY_SEVERITY, ...HTTP2_CATEGORY_SEVERITY, ...QUIC_CATEGORY_SEVERITY, ...TCP_CATEGORY_SEVERITY };

  const h2Groups = groupByCategory(HTTP2_SCENARIOS);
  const quicGroups = groupByCategory(QUIC_SCENARIOS);
  const tcpGroups = groupByCategory(TCP_SCENARIOS);
  const scanGroups = groupByCategory(SCAN_SCENARIOS);
  const quicScanGroups = groupByCategory(QUIC_SCAN_SCENARIOS);

  return {
    sections: [
      {
        id: 'tls-scenarios',
        title: 'TLS Scenarios',
        prefix: 'TLS',
        groups: tlsGroups,
        categoryOrder: tlsCategoryOrder,
        categories: { ...CATEGORIES },
        severity: { ...CATEGORY_SEVERITY },
      },
      {
        id: 'tls-scan-scenarios',
        title: 'TLS Scan Scenarios',
        prefix: 'TLS Scan',
        groups: scanGroups,
        categoryOrder: ['SCAN'],
        categories: SCAN_CATEGORIES,
        severity: { SCAN: 'info' },
      },
      {
        id: 'http-2-scenarios',
        title: 'HTTP/2 Scenarios',
        prefix: 'HTTP/2',
        groups: h2Groups,
        categoryOrder: h2CategoryOrder,
        categories: HTTP2_CATEGORIES,
        severity: HTTP2_CATEGORY_SEVERITY,
      },
      {
        id: 'quic-scenarios',
        title: 'QUIC Scenarios',
        prefix: 'QUIC',
        groups: quicGroups,
        categoryOrder: quicCategoryOrder,
        categories: QUIC_CATEGORIES,
        severity: QUIC_CATEGORY_SEVERITY,
      },
      {
        id: 'quic-scan-scenarios',
        title: 'QUIC Scan Scenarios',
        prefix: 'QUIC Scan',
        groups: quicScanGroups,
        categoryOrder: ['QSCAN'],
        categories: QUIC_SCAN_CATEGORIES,
        severity: { QSCAN: 'info' },
      },
      {
        id: 'raw-tcp-scenarios',
        title: 'Raw TCP Scenarios',
        prefix: 'Raw TCP',
        groups: tcpGroups,
        categoryOrder: ['RA', 'RB', 'RC', 'RD', 'RE', 'RF', 'RG', 'RH', 'RX'],
        categories: TCP_CATEGORIES,
        severity: TCP_CATEGORY_SEVERITY,
      },
    ],
    allCategories,
    allSeverity,
  };
}

// ── Generate Markdown ───────────────────────────────────────────────────────

function generateMarkdown() {
  const { sections, allCategories, allSeverity } = buildProtocolSections();

  // Count total tests across all protocols
  let totalTests = 0;
  const protocolCounts = [];

  for (const section of sections) {
    let sectionTotal = 0;
    for (const cat of section.categoryOrder) {
      const scenarios = section.groups[cat];
      if (scenarios && scenarios.length > 0) {
        sectionTotal += scenarios.length;
      }
    }
    totalTests += sectionTotal;
    protocolCounts.push({ prefix: section.prefix, count: sectionTotal });
  }

  const numProtocols = sections.length;

  const lines = [];

  // ── Header ──
  lines.push('# Test Scenario Reference');
  lines.push('');
  lines.push(`Complete catalog of all fuzzer test scenarios across **${totalTests} tests** in **${numProtocols} protocols**.`);
  lines.push('');

  // ── How to Read ──
  lines.push('## How to Read This Document');
  lines.push('');
  lines.push('Each test sends crafted protocol data and checks the target\'s response:');
  lines.push('');
  lines.push('| Term | Meaning |');
  lines.push('|------|---------|');
  lines.push('| **Expected = DROPPED** | Target SHOULD reject this input (security test) |');
  lines.push('| **Expected = PASSED** | Target SHOULD accept this input (compatibility test) |');
  lines.push('| **PASS** | Behavior matched expectations |');
  lines.push('| **FAIL** | Target accepted malicious input it should have rejected, or crashed |');
  lines.push('| **WARN** | Target was stricter than expected (rejected valid input) |');
  lines.push('| **INFO** | No expected value set, or scenario errored/aborted |');
  lines.push('');
  lines.push('**Side** indicates who sends the test data:');
  lines.push('- **Client \u2192 Server** \u2014 Fuzzer connects to target and sends malformed data');
  lines.push('- **Server \u2192 Client** \u2014 Fuzzer acts as server and sends malformed responses to connecting client');
  lines.push('');

  // ── Table of Contents ──
  lines.push('## Table of Contents');
  lines.push('');

  for (const section of sections) {
    let sectionTotal = 0;
    const catEntries = [];
    for (const cat of section.categoryOrder) {
      const scenarios = section.groups[cat];
      if (!scenarios || scenarios.length === 0) continue;
      sectionTotal += scenarios.length;
      const catName = section.categories[cat] || allCategories[cat] || cat;
      const label = `${cat}: ${catName}`;
      const anchor = slugify(`${cat} ${catName}`);
      catEntries.push({ label, count: scenarios.length, anchor });
    }
    if (sectionTotal === 0) continue;

    const sectionAnchor = section.id;
    lines.push(`- [**${section.prefix}** (${sectionTotal} tests)](#${sectionAnchor})`);
    for (const entry of catEntries) {
      lines.push(`  - [${entry.label} (${entry.count})](#${entry.anchor})`);
    }
  }

  lines.push('');
  lines.push('---');
  lines.push('');

  // ── Protocol Sections ──
  for (const section of sections) {
    let sectionHasContent = false;
    for (const cat of section.categoryOrder) {
      if (section.groups[cat] && section.groups[cat].length > 0) {
        sectionHasContent = true;
        break;
      }
    }
    if (!sectionHasContent) continue;

    lines.push(`## ${section.title}`);
    lines.push('');

    for (const cat of section.categoryOrder) {
      const scenarios = section.groups[cat];
      if (!scenarios || scenarios.length === 0) continue;

      const catName = section.categories[cat] || allCategories[cat] || cat;
      const severity = section.severity[cat] || allSeverity[cat] || 'info';
      const emoji = SEVERITY_EMOJI[severity] || '\u26AA';
      const sides = sideBreakdown(scenarios);

      lines.push(`### ${cat}: ${catName}`);
      lines.push('');
      lines.push(`> ${emoji} ${severity} \u00B7 ${scenarios.length} tests \u00B7 ${sides}`);
      lines.push('');
      lines.push('| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |');
      lines.push('|--:|----------|:----:|-------------|:--------:|-------------------|');

      for (let i = 0; i < scenarios.length; i++) {
        const s = scenarios[i];
        const num = i + 1;
        const arrow = sideArrow(s.side);
        const expected = inferExpected(s, allSeverity);
        const criteria = buildPassFailCriteria(s, allSeverity);
        lines.push(`| ${num} | \`${s.name}\` | ${arrow} | ${s.description} | ${expected} | ${criteria} |`);
      }

      lines.push('');
    }

    lines.push('---');
    lines.push('');
  }

  // ── Footer ──
  const today = new Date().toISOString().split('T')[0];
  lines.push(`*Generated from scenario definitions on ${today}. ${totalTests} scenarios across ${numProtocols} protocols.*`);

  return lines.join('\n');
}

// ── Generate HTML ───────────────────────────────────────────────────────────

function generateHTML(markdown) {
  // Simple markdown-to-HTML converter for this specific format
  const lines = markdown.split('\n');
  const htmlLines = [];

  htmlLines.push('<!DOCTYPE html>');
  htmlLines.push('<html lang="en">');
  htmlLines.push('<head>');
  htmlLines.push('  <meta charset="UTF-8">');
  htmlLines.push('  <meta name="viewport" content="width=device-width, initial-scale=1.0">');
  htmlLines.push('  <title>Test Scenario Reference</title>');
  htmlLines.push('  ');
  htmlLines.push('  <style>');
  htmlLines.push('    body {');
  htmlLines.push('      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";');
  htmlLines.push('      line-height: 1.6;');
  htmlLines.push('      color: #333;');
  htmlLines.push('      max-width: 1400px;');
  htmlLines.push('      margin: 0 auto;');
  htmlLines.push('      padding: 2rem;');
  htmlLines.push('      background: #f8f9fa;');
  htmlLines.push('    }');
  htmlLines.push('    .container {');
  htmlLines.push('      background: #ffffff;');
  htmlLines.push('      padding: 3rem 4rem;');
  htmlLines.push('      border-radius: 12px;');
  htmlLines.push('      box-shadow: 0 4px 15px rgba(0,0,0,0.05);');
  htmlLines.push('    }');
  htmlLines.push('    h1 { color: #2c3e50; font-size: 2.5em; border-bottom: 2px solid #eaeaea; padding-bottom: 0.3em; margin-bottom: 1em; }');
  htmlLines.push('    h2 { color: #34495e; font-size: 2em; border-bottom: 1px solid #eaeaea; padding-bottom: 0.3em; margin-top: 1.5em; margin-bottom: 1em; }');
  htmlLines.push('    h3 { color: #495057; font-size: 1.5em; margin-top: 1.5em; }');
  htmlLines.push('    table { width: 100%; border-collapse: separate; border-spacing: 0; margin: 1.5em 0; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; }');
  htmlLines.push('    th, td { border-bottom: 1px solid #e0e0e0; border-right: 1px solid #e0e0e0; padding: 12px 16px; text-align: left; }');
  htmlLines.push('    th:last-child, td:last-child { border-right: none; }');
  htmlLines.push('    tr:last-child td { border-bottom: none; }');
  htmlLines.push('    th { background-color: #f1f3f5; color: #495057; font-weight: 600; text-transform: uppercase; font-size: 0.9em; letter-spacing: 0.5px; }');
  htmlLines.push('    tr:nth-child(even) { background-color: #fcfcfc; }');
  htmlLines.push('    tr:hover { background-color: #f8f9fa; }');
  htmlLines.push('    code { background-color: #f1f3f5; padding: 0.2em 0.4em; border-radius: 4px; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; color: #d63384; font-size: 0.9em; }');
  htmlLines.push('    blockquote { background: #f8f9fa; border-left: 5px solid #4dabf7; margin: 1.5em 0; padding: 1em 1.5em; border-radius: 0 8px 8px 0; color: #495057; }');
  htmlLines.push('    a { color: #228be6; text-decoration: none; }');
  htmlLines.push('    a:hover { text-decoration: underline; color: #1c7ed6; }');
  htmlLines.push('    .expected-dropped { color: #e03131; font-weight: bold; background-color: #fff5f5; padding: 4px 8px; border-radius: 4px; display: inline-block; }');
  htmlLines.push('    .expected-passed { color: #2f9e44; font-weight: bold; background-color: #ebfbee; padding: 4px 8px; border-radius: 4px; display: inline-block; }');
  htmlLines.push('    .expected-connected { color: #1971c2; font-weight: bold; background-color: #e7f5ff; padding: 4px 8px; border-radius: 4px; display: inline-block; }');
  htmlLines.push('    .expected-failed { color: #e8590c; font-weight: bold; background-color: #fff4e6; padding: 4px 8px; border-radius: 4px; display: inline-block; }');
  htmlLines.push('    ul { padding-left: 1.5em; }');
  htmlLines.push('    li { margin-bottom: 0.5em; }');
  htmlLines.push('  </style>');
  htmlLines.push('  ');
  htmlLines.push('</head>');
  htmlLines.push('<body>');
  htmlLines.push('  <div class="container">');

  let inTable = false;
  let inTbody = false;
  let inList = false;
  let inSubList = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Close list if we're not in a list item
    if (inSubList && !line.startsWith('  - ')) {
      htmlLines.push('</ul>');
      htmlLines.push('</li>');
      inSubList = false;
    }
    if (inList && !line.startsWith('- ') && !line.startsWith('  - ')) {
      htmlLines.push('</ul>');
      inList = false;
    }

    // Close table if leaving table
    if (inTable && !line.startsWith('|')) {
      if (inTbody) { htmlLines.push('</tbody>'); inTbody = false; }
      htmlLines.push('</table>');
      inTable = false;
    }

    // Horizontal rule
    if (line === '---') {
      htmlLines.push('<hr>');
      continue;
    }

    // Headers
    const h1Match = line.match(/^# (.+)$/);
    if (h1Match) {
      htmlLines.push(`    <h1>${escapeHtml(h1Match[1])}</h1>`);
      continue;
    }
    const h2Match = line.match(/^## (.+)$/);
    if (h2Match) {
      const id = slugify(h2Match[1]);
      htmlLines.push(`<h2 id="${id}">${escapeHtml(h2Match[1])}</h2>`);
      continue;
    }
    const h3Match = line.match(/^### (.+)$/);
    if (h3Match) {
      const id = slugify(h3Match[1]);
      htmlLines.push(`<h3 id="${id}">${escapeHtml(h3Match[1])}</h3>`);
      continue;
    }

    // Blockquote
    if (line.startsWith('> ')) {
      htmlLines.push(`<blockquote><p>${escapeHtml(line.substring(2))}</p></blockquote>`);
      continue;
    }

    // Table rows
    if (line.startsWith('|')) {
      // Skip separator row
      if (line.match(/^\|[-:\s|]+\|$/)) {
        continue;
      }

      const cells = line.split('|').slice(1, -1).map(c => c.trim());

      if (!inTable) {
        htmlLines.push('<table>');
        htmlLines.push('<thead>');
        htmlLines.push('<tr>');
        for (const cell of cells) {
          htmlLines.push(`<th>${formatInline(cell)}</th>`);
        }
        htmlLines.push('</tr>');
        htmlLines.push('</thead>');
        inTable = true;
        continue;
      }

      if (!inTbody) {
        htmlLines.push('<tbody>');
        inTbody = true;
      }

      htmlLines.push('<tr>');
      for (let j = 0; j < cells.length; j++) {
        let cellContent = formatInline(cells[j]);
        // Apply expected value styling
        if (j === 4) { // Expected column
          cellContent = styleExpected(cells[j].trim());
        }
        htmlLines.push(`<td>${cellContent}</td>`);
      }
      htmlLines.push('</tr>');
      continue;
    }

    // List items (top-level)
    if (line.startsWith('- ')) {
      if (!inList) {
        htmlLines.push('<ul>');
        inList = true;
      }
      const content = formatInline(line.substring(2));
      // Check if next line is a sub-list
      if (i + 1 < lines.length && lines[i + 1].startsWith('  - ')) {
        htmlLines.push(`<li>${content}`);
        htmlLines.push('<ul>');
        inSubList = true;
      } else {
        htmlLines.push(`<li>${content}</li>`);
      }
      continue;
    }

    // Sub-list items
    if (line.startsWith('  - ')) {
      const content = formatInline(line.substring(4));
      htmlLines.push(`<li>${content}</li>`);
      continue;
    }

    // Italic footer
    if (line.startsWith('*') && line.endsWith('*')) {
      htmlLines.push(`<p><em>${escapeHtml(line.slice(1, -1))}</em></p>`);
      continue;
    }

    // Paragraph
    if (line.trim() === '') {
      continue;
    }

    // Regular text (with inline formatting)
    htmlLines.push(`<p>${formatInline(line)}</p>`);
  }

  // Close any open elements
  if (inTbody) htmlLines.push('</tbody>');
  if (inTable) htmlLines.push('</table>');
  if (inSubList) { htmlLines.push('</ul>'); htmlLines.push('</li>'); }
  if (inList) htmlLines.push('</ul>');

  htmlLines.push('  </div>');
  htmlLines.push('</body>');
  htmlLines.push('</html>');

  return htmlLines.join('\n');
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatInline(text) {
  // Bold
  text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Code
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Links
  text = text.replace(/\[([^\]]+)\]\(#([^)]+)\)/g, '<a href="#$2">$1</a>');
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  // HTML entities for special chars
  text = text.replace(/—/g, '&mdash;');
  return text;
}

function styleExpected(value) {
  if (value === 'DROPPED') return '<span class="expected-dropped">DROPPED</span>';
  if (value === 'PASSED') return '<span class="expected-passed">PASSED</span>';
  if (value === 'CONNECTED') return '<span class="expected-connected">CONNECTED</span>';
  if (value === 'FAILED_CONNECTION') return '<span class="expected-failed">FAILED_CONNECTION</span>';
  if (value === 'TIMEOUT') return '<span class="expected-dropped">TIMEOUT</span>';
  return escapeHtml(value);
}

// ── Main ────────────────────────────────────────────────────────────────────

const docsDir = path.join(__dirname, '..', 'docs');
if (!fs.existsSync(docsDir)) {
  fs.mkdirSync(docsDir, { recursive: true });
}

console.log('Generating test-scenarios.md ...');
const md = generateMarkdown();
fs.writeFileSync(path.join(docsDir, 'test-scenarios.md'), md);
console.log(`  Written: ${path.join(docsDir, 'test-scenarios.md')}`);

// Count scenarios for verification
const lineCount = md.split('\n').length;
const tableRows = md.split('\n').filter(l => l.match(/^\| \d/)).length;
console.log(`  Lines: ${lineCount}, table rows (scenarios): ${tableRows}`);

console.log('Generating test-scenarios.html ...');
const html = generateHTML(md);
fs.writeFileSync(path.join(docsDir, 'test-scenarios.html'), html);
console.log(`  Written: ${path.join(docsDir, 'test-scenarios.html')}`);

console.log('Done.');
