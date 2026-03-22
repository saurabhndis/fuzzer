// Security grading engine — analyzes fuzzer results and produces a pass/fail report
//
// Per-scenario finding:
//   PASS  — behavior matched expectations, target handled it securely
//   FAIL  — server accepted malicious input it should have rejected, or crashed
//   WARN  — server was stricter than expected (dropped when PASSED was expected)
//   INFO  — no expected value set, informational only
//
// Overall grade:
//   A — All tests pass, no crashes, all CVEs rejected
//   B — No critical/high failures, minor warnings only
//   C — No critical failures, some high/medium issues
//   D — High-severity failures present
//   F — Critical CVE accepted or host crashed

const { CATEGORY_SEVERITY } = require('./scenarios');
let LDAP_CATEGORY_SEVERITY;
try { LDAP_CATEGORY_SEVERITY = require('./ldap/scenarios').LDAP_CATEGORY_SEVERITY; } catch (_) { LDAP_CATEGORY_SEVERITY = {}; }

/**
 * Normalize a response string for comparison (strips length suffixes, whitespace, etc.)
 */
function normalizeResponse(res) {
  if (!res) return '';
  let s = res.trim();
  // Remove "(N bytes)" suffix
  s = s.replace(/\s*\(\d+\s+bytes\)/g, '');
  // Normalize handshake descriptions to core meaning for comparison
  // Old: "Handshake/SERVER_HELLO (TLS 1.0)" → New: "ServerHello(TLS 1.2, CIPHER)"
  s = s.replace(/^Handshake\/SERVER_HELLO\s*\([^)]*\).*/, 'ServerHello');
  s = s.replace(/^ServerHello\([^)]*\)/, 'ServerHello');
  s = s.replace(/^Handshake\/CLIENT_HELLO\s*\([^)]*\).*/, 'ClientHello');
  s = s.replace(/^ClientHello\([^)]*\)/, 'ClientHello');
  s = s.replace(/^Handshake completed$/, 'ClientHello');
  return s.trim();
}

/**
 * Classify a response string into a behavioral category for semantic matching.
 * Returns 'accepted', 'rejected', or 'unknown'.
 *
 * - 'accepted': server completed the handshake (ServerHello, ClientHello, Handshake completed, PASSED)
 * - 'rejected': server refused the input (Alert, Connection closed, Encrypted alert, DROPPED, TIMEOUT)
 * - 'unknown': cannot determine behavior
 */
function classifyBehavior(response, status) {
  if (!response && !status) return 'unknown';
  const r = (response || '').trim();
  const s = (status || '').trim();

  // Rejection signals
  if (s === 'DROPPED' || s === 'TIMEOUT' || s === 'tls-alert-server' || s === 'tls-alert-client') return 'rejected';
  if (/^Alert\b/i.test(r)) return 'rejected';
  if (/Connection closed/i.test(r)) return 'rejected';
  if (/Encrypted alert/i.test(r)) return 'rejected';
  if (/^Connection reset/i.test(r)) return 'rejected';
  if (/H2 GOAWAY/i.test(r)) return 'rejected';
  if (/H2 RST_STREAM/i.test(r)) return 'rejected';
  if (/QUIC Stateless Reset/i.test(r)) return 'rejected';
  if (/QUIC.*CONNECTION_CLOSE/i.test(r)) return 'rejected';
  // LDAP rejection signals
  if (/invalidCredentials/i.test(r)) return 'rejected';
  if (/protocolError/i.test(r)) return 'rejected';
  if (/unwillingToPerform/i.test(r)) return 'rejected';
  if (/insufficientAccessRights/i.test(r)) return 'rejected';
  if (/authMethodNotSupported/i.test(r)) return 'rejected';
  if (/strongerAuthRequired/i.test(r)) return 'rejected';
  if (/operationsError/i.test(r)) return 'rejected';
  if (s === 'ldap-error-response') return 'rejected';

  // Acceptance signals
  if (s === 'PASSED') return 'accepted';
  if (/ServerHello/i.test(r)) return 'accepted';
  if (/ClientHello/i.test(r)) return 'accepted';
  if (/Handshake completed/i.test(r)) return 'accepted';
  if (/ChangeCipherSpec/i.test(r)) return 'accepted';
  if (/H2 SETTINGS/i.test(r) && !/H2 GOAWAY/i.test(r)) return 'accepted';
  // LDAP acceptance signals
  if (/BindResponse\(success\)/i.test(r)) return 'accepted';
  if (/SearchResultDone\(success\)/i.test(r)) return 'accepted';
  if (/SearchResultEntry/i.test(r)) return 'accepted';

  return 'unknown';
}

/**
 * Analyze a single scenario result and produce a security finding
 */
function gradeResult(result, scenarioMeta) {
  const category = scenarioMeta ? scenarioMeta.category : null;
  const severity = category ? (CATEGORY_SEVERITY[category] || LDAP_CATEGORY_SEVERITY[category] || 'low') : 'low';
  const expected = result.expected || (scenarioMeta ? scenarioMeta.expected : null);
  const status = result.status;
  const effective = status === 'TIMEOUT' ? 'DROPPED' : status;

  // Host crashed — always a critical failure
  if (result.hostDown) {
    return {
      grade: 'FAIL',
      severity: 'critical',
      reason: 'Target became unreachable — possible crash/DoS',
    };
  }

  // Health degraded — TCP up but HTTPS down
  if (result.probe && result.probe.tcp && result.probe.tcp.alive &&
      result.probe.https && !result.probe.https.alive) {
    return {
      grade: 'FAIL',
      severity: 'high',
      reason: `Service degraded after scenario — TCP open but HTTPS failed (${result.probe.https.error})`,
    };
  }

  // No expected value — informational
  if (!expected) {
    return { grade: 'INFO', severity, reason: 'No expected value defined' };
  }

  // Differential Fuzzing: Check if target matches our reference implementation (OpenSSL)
  // Use semantic matching — both accepted or both rejected counts as a match
  const normResponse = normalizeResponse(result.response || result.status);
  const normBaseline = normalizeResponse(result._baselineResponse);
  const exactMatch = result.scenario && normBaseline && (normResponse === normBaseline);
  const behaviorMatch = result.scenario && result._baselineResponse &&
    classifyBehavior(result.response || result.status, result.status) !== 'unknown' &&
    classifyBehavior(result.response || result.status, result.status) === classifyBehavior(result._baselineResponse, null);
  const matchesBaseline = exactMatch || behaviorMatch;

  // Aborted / Error — skip grading
  if (status === 'ERROR' || status === 'ABORTED') {
    return { grade: 'INFO', severity, reason: `Scenario ${status.toLowerCase()}` };
  }

  // TLS alert statuses — server/client responded per protocol, always PASS
  if (status === 'tls-alert-server') {
    return { grade: 'PASS', severity, reason: 'Server correctly sent fatal alert (protocol rejection)' };
  }
  if (status === 'tls-alert-client') {
    return { grade: 'PASS', severity, reason: 'Client correctly sent fatal alert (protocol rejection)' };
  }

  // Server accepted input it should have rejected — security failure
  // But coherent TLS responses (ServerHello) are proper behavior
  if (expected === 'DROPPED' && effective === 'PASSED') {
    const r = (result.response || '').trim();
    // ServerHello = server accepted, but responded coherently (edge case input)
    if (/^ServerHello\(/i.test(r) || matchesBaseline) {
      return { grade: 'WARN', severity, reason: 'Server accepted input (coherent response) — verify if input is truly malformed' };
    }
    return {
      grade: 'FAIL',
      severity,
      reason: 'Server accepted malicious/malformed input that should be rejected',
    };
  }

  // Server rejected input it should have accepted — compatibility issue, not security
  if (expected === 'PASSED' && effective === 'DROPPED') {
    // If it matches OpenSSL, it's a common/standard rejection, just INFO
    if (matchesBaseline) {
      return { grade: 'PASS', severity, reason: 'Matched baseline rejection behavior' };
    }
    return {
      grade: 'WARN',
      severity,
      reason: 'Server rejected valid input — stricter than expected',
    };
  }

  // Matched expectations — also check protocol compliance
  const finding = { grade: 'PASS', severity, reason: null };
  if (result.compliance) {
    finding.compliance = result.compliance;
    if (result.compliance.level === 'non-compliant' && !matchesBaseline) {
      finding.complianceNote = 'Server response was not protocol-compliant (no proper TLS Alert)';
    } else if (result.compliance.level === 'concerning' && !matchesBaseline) {
      finding.complianceNote = result.compliance.details;
    }
  }
  return finding;
}

/**
 * Compute overall grade from all graded results
 *
 * Returns { grade: 'A'|'B'|'C'|'D'|'F', label, findings[], stats }
 */
function computeOverallGrade(gradedResults) {
  const stats = { pass: 0, fail: 0, warn: 0, info: 0 };
  const failsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const findings = [];

  for (const r of gradedResults) {
    const g = r.finding;
    if (!g || typeof g === 'string') {
      // Server-side results may have string findings like 'pass', 'timeout', 'error'
      const mapped = (typeof g === 'string') ? g : 'info';
      const gradeKey = (mapped === 'pass') ? 'pass' : (mapped === 'error' || mapped === 'timeout') ? 'fail' : 'info';
      stats[gradeKey] = (stats[gradeKey] || 0) + 1;
      if (gradeKey === 'fail') {
        failsBySeverity['medium'] = (failsBySeverity['medium'] || 0) + 1;
        findings.push({
          scenario: r.scenario,
          severity: 'medium',
          reason: r.response || mapped,
          status: r.status,
          category: r.category,
        });
      }
      continue;
    }
    const grade = g.grade || 'INFO';
    stats[grade.toLowerCase()] = (stats[grade.toLowerCase()] || 0) + 1;
    if (grade === 'FAIL') {
      failsBySeverity[g.severity || 'medium'] = (failsBySeverity[g.severity || 'medium'] || 0) + 1;
      findings.push({
        scenario: r.scenario,
        severity: g.severity || 'medium',
        reason: g.reason || 'Unknown failure',
        status: r.status,
        category: r.category,
      });
    }
  }

  // Sort findings by severity weight
  const sevWeight = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => sevWeight[a.severity] - sevWeight[b.severity]);

  let grade, label;

  if (failsBySeverity.critical > 0) {
    grade = 'F';
    label = 'Critical vulnerabilities detected';
  } else if (gradedResults.some(r => r.hostDown)) {
    grade = 'F';
    label = 'Target crashed during testing';
  } else if (failsBySeverity.high > 0) {
    grade = 'D';
    label = 'High-severity protocol violations accepted';
  } else if (failsBySeverity.medium > 2) {
    grade = 'C';
    label = 'Multiple medium-severity issues';
  } else if (failsBySeverity.medium > 0 || failsBySeverity.low > 2) {
    grade = 'B';
    label = 'Minor issues detected';
  } else if (stats.warn > gradedResults.length * 0.3) {
    grade = 'B';
    label = 'Mostly secure, some strict rejections';
  } else {
    grade = 'A';
    label = 'All tests passed — robust TLS implementation';
  }

  // Compliance statistics
  const complianceStats = { ideal: 0, acceptable: 0, concerning: 0, 'non-compliant': 0, 'N/A': 0 };
  for (const r of gradedResults) {
    if (r.compliance && r.compliance.level) {
      complianceStats[r.compliance.level] = (complianceStats[r.compliance.level] || 0) + 1;
    }
  }

  return { grade, label, findings, stats, failsBySeverity, complianceStats };
}

module.exports = { gradeResult, computeOverallGrade, CATEGORY_SEVERITY, normalizeResponse, classifyBehavior };
