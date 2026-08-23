// Turns a finished run into a signed receipt and the block a developer pastes
// into their PR. Sits between the pure core (lib/attestation.js) and the
// collectors (lib/attestation-evidence.js) so cli.js and main.js each stay
// a few lines.

const path = require('path');
const crypto = require('crypto');
const A = require('./attestation');
const E = require('./attestation-evidence');
const S = require('./attestation-store');

const TOOL_ROOT = path.join(__dirname, '..');

// Everything a receipt needs, captured at the end of a run. Kept durable by
// attestation-store so `cli.js attest` can be run later, separately.
function buildRunRecord({
  runId, startedAt, finishedAt, protocol, mode, distributed = false,
  aborted = false, abortReason = null, host, port, localServer = false,
  requestedScenarios, scenarios, results, report, pcapFile = null, dutIdentity = null,
}) {
  const executed = (results || []).length;
  const requested = requestedScenarios || executed;
  return {
    runId,
    startedAt,
    finishedAt,
    protocol,
    mode,
    distributed,
    aborted,
    abortReason,
    target: { host, port, localServer },
    requestedScenarios: requested,
    executedScenarios: executed,
    // Permille, not a float: canonical JSON refuses non-integers so the
    // digest is reproducible by a verifier in any language.
    coveragePermille: requested > 0 ? Math.round((executed / requested) * 1000) : 0,
    scenarioSet: E.scenarioSetDigest(scenarios),
    resultsDigest: E.resultsDigest(results),
    report: report || null,
    pcapFile,
    dutIdentity,
  };
}

// Build + sign + chain + append. Returns the envelope and the paste block.
async function attestRun(runRecord, { cwd = process.cwd(), signer = null } = {}) {
  const repo = E.collectRepoInfo(cwd);
  const repoId = repo.available ? repo.repoId : 'no-repo';

  const pcapPath = runRecord.pcapFile;
  const keylogPath = pcapPath
    ? `${pcapPath.replace(/\.pcap$/i, '')}.keylog`
    : null;
  const pcap = pcapPath ? E.inspectPcap(pcapPath) : null;
  const keylog = keylogPath ? E.inspectKeylog(keylogPath) : null;
  const binding = keylog && pcapPath ? E.bindKeylogToPcap(keylog, pcapPath) : null;

  // The keylog's client randoms are not recorded — only their count and the
  // binding verdict. They are session key material, not evidence to publish.
  const keylogSummary = keylog
    ? { sha256: keylog.sha256, bytes: keylog.bytes, lines: keylog.lines,
        labels: keylog.labels, clientRandoms: keylog.clientRandoms.length }
    : null;

  const { privateKeyPem, keyId } = S.loadPrivateKey();
  const prev = S.tailLedger(repoId);
  const { chainSeq, prevReceiptHash } = A.chainNext(prev);

  const gitName = E.git(['config', 'user.name'], cwd);
  const gitEmail = E.git(['config', 'user.email'], cwd);

  const report = runRecord.report || {};
  const receipt = A.buildReceipt({
    receiptId: crypto.randomUUID(),
    tool: E.collectToolInfo(TOOL_ROOT),
    repo,
    run: {
      runId: runRecord.runId,
      startedAt: runRecord.startedAt,
      finishedAt: runRecord.finishedAt,
      durationMs: runRecord.finishedAt - runRecord.startedAt,
      protocol: runRecord.protocol,
      mode: runRecord.mode,
      distributed: !!runRecord.distributed,
      aborted: !!runRecord.aborted,
      abortReason: runRecord.abortReason || null,
      requestedScenarios: runRecord.requestedScenarios,
      executedScenarios: runRecord.executedScenarios,
      coveragePermille: runRecord.coveragePermille,
      scenarioSetDigest: runRecord.scenarioSet ? runRecord.scenarioSet.digest : null,
      resultsDigest: runRecord.resultsDigest,
      grade: report.grade || null,
      gradeLabel: report.label || null,
      stats: report.stats || null,
      failsBySeverity: report.failsBySeverity || null,
    },
    target: {
      host: runRecord.target.host || null,
      port: runRecord.target.port || null,
      addressClass: await E.classifyAddress(runRecord.target.host),
      localServer: !!runRecord.target.localServer,
      dut: runRecord.dutIdentity || null,
    },
    evidence: { pcap, keylog: keylogSummary, binding },
    chain: { keyId, chainSeq, prevReceiptHash },
    signer: signer || { email: gitEmail, name: gitName },
  });

  const envelope = A.signReceipt(receipt, { privateKeyPem, keyId });
  S.appendToLedger(repoId, envelope);

  const verdict = A.verifyEnvelope(envelope, { publicKeyPem: S.keyStatus().publicKeyPem });
  return {
    envelope,
    warnings: verdict.warnings,
    block: A.encodeBlock(envelope, { human: renderHuman(receipt, verdict.warnings) }),
  };
}

function fmtDuration(ms) {
  if (!Number.isInteger(ms) || ms < 0) return '?';
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

function fmtBytes(n) {
  if (!Number.isInteger(n)) return '?';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

// The human half is decorative — the payload line is authoritative. It exists
// so a reviewer can judge the run without tooling, which is where most of the
// practical value sits: a loopback target or an aborted run is visible here.
function renderHuman(receipt, warnings = []) {
  const run = receipt.run || {};
  const repo = receipt.repo || {};
  const tgt = receipt.target || {};
  const ev = receipt.evidence || {};
  const s = run.stats || {};

  const rows = [];
  rows.push(['Tool', `${receipt.tool.name} ${receipt.tool.version || '?'}${receipt.tool.commit ? ` (${receipt.tool.commit.slice(0, 7)})` : ''}`]);
  rows.push(['Repo', repo.available
    ? `\`${repo.headSha.slice(0, 7)}\`${repo.branch ? ` on \`${repo.branch}\`` : ' (detached)'}, ${repo.dirty ? `**${repo.dirtyFileCount} uncommitted file(s)**` : 'clean tree'}`
    : '**not a git repository**']);
  rows.push(['Run', `${String(run.protocol || '').toUpperCase()} · ${run.mode}${run.distributed ? ' · distributed' : ''} · ${run.executedScenarios}/${run.requestedScenarios} scenarios (${((run.coveragePermille || 0) / 10).toFixed(1)}%) · ${fmtDuration(run.durationMs)}`]);
  rows.push(['Grade', run.grade
    ? `**${run.grade}** — ${run.gradeLabel || ''} (${s.pass || 0} pass / ${s.fail || 0} fail / ${s.warn || 0} warn${s.error ? ` / ${s.error} did not run` : ''})`
    : 'n/a']);
  rows.push(['Target', `${tgt.host || '?'}:${tgt.port || '?'} (${tgt.addressClass})${tgt.localServer ? ' · **tool\'s own server**' : ''}${tgt.dut && tgt.dut.certSha256 ? ` · cert ${tgt.dut.certSha256.slice(0, 8)}…` : ''}`]);
  rows.push(['Evidence', ev.pcap
    ? `pcap ${ev.pcap.packets} pkts, ${fmtBytes(ev.pcap.bytes)}, sha ${ev.pcap.sha256.slice(0, 8)}…${ev.binding ? ` · keylog ${ev.binding.matched}/${ev.binding.randoms} bound (${ev.binding.status})` : ''}`
    : '**none captured** (run without --pcap)']);
  rows.push(['Signed by', `${receipt.signer && receipt.signer.email ? receipt.signer.email : 'unknown'} · key \`${receipt.chain.keyId}\` · chain #${receipt.chain.chainSeq}`]);
  rows.push(['Finished', new Date(run.finishedAt).toISOString()]);
  if (warnings.length) rows.push(['⚠', warnings.map((w) => w.message).join(' · ')]);

  return [
    '<!-- wirestrike-attestation v1 -->',
    '**WireStrike run attestation**',
    '',
    '| | |',
    '|---|---|',
    ...rows.map(([k, v]) => `| ${k} | ${v} |`),
  ].join('\n');
}

module.exports = { buildRunRecord, attestRun, renderHuman, TOOL_ROOT };
