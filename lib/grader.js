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

/**
 * Analyze a single scenario result and produce a security finding
 */
function gradeResult(result, scenarioMeta) {
  const category = scenarioMeta ? scenarioMeta.category : null;
  const severity = category ? (CATEGORY_SEVERITY[category] || 'low') : 'low';
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

  // Aborted / Error — skip grading
  if (status === 'ERROR' || status === 'ABORTED') {
    return { grade: 'INFO', severity, reason: `Scenario ${status.toLowerCase()}` };
  }

  // Server accepted input it should have rejected — security failure
  // This is the dangerous direction: expected DROPPED but got PASSED
  if (expected === 'DROPPED' && effective === 'PASSED') {
    return {
      grade: 'FAIL',
      severity,
      reason: 'Server accepted malicious/malformed input that should be rejected',
    };
  }

  // Server rejected input it should have accepted — compatibility issue, not security
  // This is the safe direction: expected PASSED but got DROPPED
  if (expected === 'PASSED' && effective === 'DROPPED') {
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
    if (result.compliance.level === 'non-compliant') {
      finding.complianceNote = 'Server response was not protocol-compliant (no proper TLS Alert)';
    } else if (result.compliance.level === 'concerning') {
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
    stats[g.grade.toLowerCase()] = (stats[g.grade.toLowerCase()] || 0) + 1;
    if (g.grade === 'FAIL') {
      failsBySeverity[g.severity] = (failsBySeverity[g.severity] || 0) + 1;
      findings.push({
        scenario: r.scenario,
        severity: g.severity,
        reason: g.reason,
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

module.exports = { gradeResult, computeOverallGrade, CATEGORY_SEVERITY };
