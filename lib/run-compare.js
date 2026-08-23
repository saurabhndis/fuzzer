// Run comparison — pure diff of two history records from the same suite.
// Joins per-scenario results by name and classifies each scenario's movement
// between the two runs. No I/O; callers load the records themselves.

// ERROR sits between INFO and WARN: a scenario that never ran is worse than
// one that ran without an assertion, but it is not a security finding.
const GRADE_RANK = { PASS: 0, INFO: 1, ERROR: 2, WARN: 3, FAIL: 4 };

const CLASS_ORDER = ['regressed', 'new', 'status-changed', 'improved', 'removed', 'match'];

function gradeOf(entry) {
  return entry && entry.finding ? entry.finding.grade : null;
}

function gradeRank(entry) {
  const g = gradeOf(entry);
  return GRADE_RANK[g] !== undefined ? GRADE_RANK[g] : 0;
}

// A run can contain the same scenario more than once (loopCount > 1, or the
// client/server halves of a distributed pair). Collapse to the worst
// occurrence so a single flaky iteration still surfaces as a regression.
function indexByScenario(results) {
  const map = new Map();
  for (const r of results || []) {
    if (!r || !r.scenario) continue;
    const prev = map.get(r.scenario);
    if (!prev || worse(r, prev)) map.set(r.scenario, r);
  }
  return map;
}

function worse(a, b) {
  if (gradeRank(a) !== gradeRank(b)) return gradeRank(a) > gradeRank(b);
  const aUnexpected = a.verdict === 'UNEXPECTED';
  const bUnexpected = b.verdict === 'UNEXPECTED';
  if (aUnexpected !== bUnexpected) return aUnexpected;
  return a.status !== 'PASSED' && b.status === 'PASSED';
}

function cell(entry) {
  return {
    status: entry.status || null,
    verdict: entry.verdict || null,
    grade: entry.finding ? entry.finding.grade : null,
  };
}

function classify(prev, curr) {
  if (!prev) return 'new';
  if (!curr) return 'removed';

  // A scenario that stopped running is a regression regardless of what it
  // used to report — losing coverage is never an improvement, so this can't
  // be left to the rank comparison (FAIL outranks ERROR).
  const prevErrored = gradeOf(prev) === 'ERROR';
  const currErrored = gradeOf(curr) === 'ERROR';
  if (currErrored && !prevErrored) return 'regressed';

  const rankDelta = gradeRank(curr) - gradeRank(prev);
  const wentUnexpected = prev.verdict === 'AS EXPECTED' && curr.verdict === 'UNEXPECTED';
  const wentExpected = prev.verdict === 'UNEXPECTED' && curr.verdict === 'AS EXPECTED';
  if (rankDelta > 0 || (rankDelta === 0 && wentUnexpected)) return 'regressed';
  if (rankDelta < 0 || (rankDelta === 0 && wentExpected)) return 'improved';
  if (prev.status !== curr.status) return 'status-changed';
  return 'match';
}

// -> { rows, summary }
//   rows: [{ scenario, category, expected, prev, curr, classification }]
//         sorted regressed, new, status-changed, improved, removed, match
//   summary: { counts, common, prevGrade, currGrade, headline }
function compareRuns(prevRecord, currRecord) {
  const prevMap = indexByScenario(prevRecord.results);
  const currMap = indexByScenario(currRecord.results);

  const names = [...new Set([...prevMap.keys(), ...currMap.keys()])];
  const rows = names.map((scenario) => {
    const prev = prevMap.get(scenario) || null;
    const curr = currMap.get(scenario) || null;
    const meta = curr || prev;
    return {
      scenario,
      category: meta.category || '',
      expected: meta.expected || null,
      prev: prev ? cell(prev) : null,
      curr: curr ? cell(curr) : null,
      classification: classify(prev, curr),
    };
  });

  rows.sort((a, b) => {
    const order = CLASS_ORDER.indexOf(a.classification) - CLASS_ORDER.indexOf(b.classification);
    return order !== 0 ? order : a.scenario.localeCompare(b.scenario);
  });

  const counts = { match: 0, regressed: 0, improved: 0, statusChanged: 0, new: 0, removed: 0 };
  for (const row of rows) {
    const key = row.classification === 'status-changed' ? 'statusChanged' : row.classification;
    counts[key]++;
  }
  const common = names.filter((n) => prevMap.has(n) && currMap.has(n)).length;
  const prevGrade = prevRecord.report ? prevRecord.report.grade : null;
  const currGrade = currRecord.report ? currRecord.report.grade : null;

  const parts = [];
  if (counts.regressed) parts.push(`${counts.regressed} regressed`);
  if (counts.improved) parts.push(`${counts.improved} improved`);
  if (counts.statusChanged) parts.push(`${counts.statusChanged} status-changed`);
  if (counts.new) parts.push(`${counts.new} new`);
  if (counts.removed) parts.push(`${counts.removed} removed`);
  const movement = parts.length ? parts.join(', ') : 'no changes';
  const gradePart = prevGrade || currGrade ? `Grade ${prevGrade || '?'} → ${currGrade || '?'} · ` : '';
  const headline = `${gradePart}${movement} (${common} common scenario${common === 1 ? '' : 's'})`;

  return { rows, summary: { counts, common, prevGrade, currGrade, headline } };
}

module.exports = { compareRuns, GRADE_RANK, CLASS_ORDER };
