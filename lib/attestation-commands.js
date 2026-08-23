// `cli.js attest` and `cli.js verify`. Kept out of cli.js, which is already
// long, and out of the pure core, which a CI validator vendors on its own.

const fs = require('fs');
const path = require('path');
const A = require('./attestation');
const E = require('./attestation-evidence');
const S = require('./attestation-store');
const { attestRun } = require('./attestation-run');

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[90m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m',
};

function repoIdFor(cwd) {
  const repo = E.collectRepoInfo(cwd);
  return repo.available ? repo.repoId : 'no-repo';
}

async function runAttestCommand(args) {
  const cwd = process.cwd();

  if (args['init-key']) {
    let gen;
    try {
      gen = S.generateKeyPair({ force: !!args.force });
    } catch (err) {
      console.error(`${C.red}${err.message}${C.reset}`);
      return 1;
    }
    const email = E.git(['config', 'user.email'], cwd);
    const name = E.git(['config', 'user.name'], cwd);
    const file = S.registryFileFor({ keyId: gen.keyId, publicKeyPem: gen.publicKeyPem, email, name });

    console.log(`${C.green}Attestation key created${C.reset}`);
    console.log(`  private  ${gen.privateKeyPath} ${C.dim}(mode 0600 — never leaves this machine)${C.reset}`);
    console.log(`  keyId    ${C.bold}${gen.keyId}${C.reset}`);
    console.log('');
    console.log(`${C.bold}Register it by committing this file:${C.reset}  ${C.cyan}${file.relPath}${C.reset}`);
    console.log('');
    console.log(file.content);
    console.log(`${C.dim}The reviewed commit that adds this file is what makes your receipts attributable.${C.reset}`);
    return 0;
  }

  const repoId = repoIdFor(cwd);

  if (args.list) {
    const { envelopes, errors } = S.readLedger(repoId);
    if (!envelopes.length) {
      console.log('No attestations recorded for this repository yet.');
      return 0;
    }
    for (const env of envelopes.slice().reverse()) {
      const r = env.receipt;
      const when = new Date(r.run.finishedAt).toISOString();
      const grade = r.run.grade || '?';
      console.log(`  #${String(r.chain.chainSeq).padStart(3)}  ${when}  ${String(r.run.protocol).toUpperCase().padEnd(7)} grade ${grade}  ${C.dim}${r.receiptId.slice(0, 8)}${C.reset}`);
    }
    if (errors.length) console.log(`${C.yellow}  ${errors.length} unreadable ledger line(s)${C.reset}`);
    return 0;
  }

  if (args['verify-ledger']) {
    const { envelopes, errors } = S.readLedger(repoId);
    const chain = A.verifyChain(envelopes);
    console.log(`Ledger: ${envelopes.length} receipt(s) for repo ${repoId}`);
    if (errors.length) console.log(`${C.yellow}  ${errors.length} unreadable line(s)${C.reset}`);
    if (chain.ok) {
      console.log(`${C.green}  chain intact${C.reset}`);
      return 0;
    }
    for (const b of chain.breaks) console.log(`${C.red}  break at #${b.index}: ${b.reason}${C.reset}`);
    return 1;
  }

  // Default: attest a run that already happened.
  const record = args.run ? S.loadRunRecord(repoId, args.run) : S.latestRunRecord(repoId);
  if (!record) {
    console.error(`${C.red}No run record found for this repository.${C.reset}`);
    console.error('Run the fuzzer once first — every run is recorded, with or without --attest.');
    return 1;
  }

  try {
    const { block, warnings } = await attestRun(record, { cwd });
    console.log(block);
    if (warnings.length) {
      console.error('');
      for (const w of warnings) console.error(`${C.yellow}⚠ ${w.message}${C.reset}`);
    }
    return 0;
  } catch (err) {
    console.error(`${C.red}${err.message}${C.reset}`);
    return 1;
  }
}

async function runVerifyCommand(args) {
  const cwd = process.cwd();
  const source = args._[1];

  let text = '';
  if (!source || source === '-') {
    text = fs.readFileSync(0, 'utf8');
  } else if (fs.existsSync(source)) {
    text = fs.readFileSync(source, 'utf8');
  } else {
    text = source;
  }

  const envelope = A.decodeBlock(text);
  if (!envelope) {
    console.error(`${C.red}No attestation block found.${C.reset} Expected a line beginning wsr1: or wsr1z:`);
    return 1;
  }

  const { byKeyId, errors: regErrors } = S.loadRegistry(cwd);
  const result = A.verifyEnvelope(envelope, {
    registry: byKeyId,
    maxAgeMs: args['max-age-days'] ? parseInt(args['max-age-days'], 10) * 86400000 : null,
  });

  if (args.json) {
    console.log(JSON.stringify({
      ok: result.ok,
      signatureValid: result.signatureValid,
      keyKnown: result.keyKnown,
      keyId: result.keyId,
      signer: result.signer,
      errors: result.errors,
      warnings: result.warnings,
      receipt: result.receipt,
    }, null, 2));
    return result.ok ? 0 : 1;
  }

  const r = result.receipt || {};
  const run = r.run || {};
  const repo = r.repo || {};
  console.log(`${C.bold}WireStrike attestation${C.reset}`);
  console.log(`  signer     ${r.signer && r.signer.email ? r.signer.email : '(none)'}  key ${result.keyId || '?'}  chain #${r.chain ? r.chain.chainSeq : '?'}`);
  console.log(`  repo       ${repo.available ? `${repo.headSha.slice(0, 8)} on ${repo.branch || 'detached'} · ${repo.dirty ? `${repo.dirtyFileCount} dirty` : 'clean'}` : 'not a git repo'}`);
  console.log(`  run        ${String(run.protocol).toUpperCase()} ${run.mode} · ${run.executedScenarios}/${run.requestedScenarios} scenarios · grade ${run.grade || '?'}`);
  console.log(`  finished   ${Number.isInteger(run.finishedAt) ? new Date(run.finishedAt).toISOString() : '?'}`);
  console.log('');
  console.log(`  signature  ${result.signatureValid ? `${C.green}valid${C.reset}`
    : result.signatureChecked ? `${C.red}INVALID${C.reset}`
    : `${C.yellow}not checked — no key to check it against${C.reset}`}`);
  console.log(`  key known  ${result.keyKnown ? `${C.green}yes${C.reset}` : `${C.red}no — not registered in .wirestrike/keys/${C.reset}`}`);

  if (regErrors.length) {
    console.log('');
    for (const e of regErrors) console.log(`${C.yellow}  registry: ${e.file} — ${e.error}${C.reset}`);
  }
  if (result.errors.length) {
    console.log('');
    for (const e of result.errors) console.log(`${C.red}  ✗ ${e.code}: ${e.message}${C.reset}`);
  }
  if (result.warnings.length) {
    console.log('');
    for (const w of result.warnings) console.log(`${C.yellow}  ⚠ ${w.code}: ${w.message}${C.reset}`);
  }
  console.log('');
  console.log(result.ok
    ? `${C.green}${C.bold}VERIFIED${C.reset} ${C.dim}— authentic and unmodified. This attests the run; it cannot prove the target was meaningful.${C.reset}`
    : `${C.red}${C.bold}NOT VERIFIED${C.reset}`);
  return result.ok ? 0 : 1;
}

// ── Central service: account / submit / verify-token ────────────────

function remote() {
  return require('./attestation-remote');
}

async function runAccountCommand(args) {
  const R = remote();

  if (args.create) {
    const email = args.email;
    if (!email) {
      console.error(`${C.red}--create needs --email you@paloaltonetworks.com${C.reset}`);
      return 1;
    }
    // Default the username to the email's local part, squeezed into the
    // charset the certificate subject and server accept.
    const username = (args.username || email.split('@')[0]).toLowerCase().replace(/[^a-z0-9_.-]/g, '.');
    try {
      const res = await R.enroll({ server: args.server, username, email, serverCertPath: args['server-cert'] });
      console.log(`${C.green}Account created — signed in as ${C.bold}${res.username}${C.reset}${C.green} (${res.email})${C.reset}`);
      console.log(`  keyId         ${res.keyId}`);
      console.log(`  client cert   ${R.clientCertPath()} ${C.dim}(valid until ${new Date(res.certExpiresAt).toISOString().slice(0, 10)})${C.reset}`);
      console.log(`${C.dim}Future runs authenticate to the server with this certificate (mTLS).${C.reset}`);
      return 0;
    } catch (err) {
      console.error(`${C.red}${err.message}${C.reset}`);
      return 1;
    }
  }

  if (args.login) {
    try {
      const res = await R.login({ server: args.server });
      console.log(`${C.green}Signed in as ${C.bold}${res.username}${C.reset}${C.green} (${res.email})${C.reset}`);
      return 0;
    } catch (err) {
      console.error(`${C.red}${err.message}${C.reset}`);
      return 1;
    }
  }

  if (args.logout) {
    R.logout();
    console.log('Signed out — the fuzzer is in anonymous mode. Your key and certificate stay on this machine; `account --login` signs back in.');
    return 0;
  }

  const st = R.accountStatus();
  if (st.mode === 'account') {
    console.log(`${C.green}Signed in${C.reset} as ${C.bold}${st.username}${C.reset} (${st.email})`);
  } else {
    console.log(`${C.yellow}Anonymous mode.${C.reset} Create an account with your work email to use the fuzzer for your PRs:`);
    console.log(`  node cli.js account --create --email you@paloaltonetworks.com --server <url>`);
  }
  if (st.enrolled) {
    console.log(`  certificate  ${st.certSubject || '?'}${st.certExpiresAt ? ` ${C.dim}(expires ${new Date(st.certExpiresAt).toISOString().slice(0, 10)})${C.reset}` : ''}`);
  }
  if (st.serverUrl) console.log(`  server       ${st.serverUrl}`);
  return 0;
}

async function runSubmitCommand(args) {
  const R = remote();
  if (!R.isSignedIn()) {
    console.error(`${C.red}Not signed in.${C.reset} Create an account with your work email to use the fuzzer for your PRs:`);
    console.error('  node cli.js account --create --email you@paloaltonetworks.com --server <url>');
    return 1;
  }

  // A pasted block or file wins; otherwise the latest receipt in the local
  // ledger — reused as-is rather than re-signed, so no duplicate chain entry.
  const source = args._[1];
  let envelope = null;
  if (source) {
    const text = fs.existsSync(source) ? fs.readFileSync(source, 'utf8') : source;
    envelope = A.decodeBlock(text);
  } else {
    envelope = S.tailLedger(repoIdFor(process.cwd()));
  }
  if (!envelope) {
    console.error(`${C.red}Nothing to submit — no wsr1: block given and no receipt in the local ledger. Run with --attest first.${C.reset}`);
    return 1;
  }

  const prNumber = args.pr !== undefined ? parseInt(args.pr, 10) : null;
  if (args.pr !== undefined && !Number.isInteger(prNumber)) {
    console.error(`${C.red}--pr must be an integer${C.reset}`);
    return 1;
  }
  try {
    const res = await R.submitRun({ envelope, prNumber, server: args.server });
    printToken(res);
    return 0;
  } catch (err) {
    console.error(`${C.red}${err.message}${C.reset}`);
    return 1;
  }
}

function printToken(res) {
  console.log('');
  console.log(`${C.green}Run recorded by the attestation server${C.reset} ${C.dim}(#${res.serial}${res.prNumber !== null && res.prNumber !== undefined ? `, PR ${res.prNumber}` : ''})${C.reset}`);
  console.log(`${C.bold}Paste this token into your PR:${C.reset}`);
  console.log('');
  console.log(res.token);
  if (res.warnings && res.warnings.length) {
    console.log('');
    for (const w of res.warnings) console.log(`${C.yellow}  ⚠ ${w.code}: ${w.message}${C.reset}`);
  }
}

async function runRunsCommand(args) {
  const R = remote();
  if (!R.isSignedIn()) {
    console.error(`${C.red}Not signed in.${C.reset} Create an account first: node cli.js account --create --email you@paloaltonetworks.com --server <url>`);
    return 1;
  }
  let data;
  try {
    data = await R.listRuns({ server: args.server });
  } catch (err) {
    console.error(`${C.red}${err.message}${C.reset}`);
    return 1;
  }
  if (args.json) {
    console.log(JSON.stringify(data, null, 2));
    return 0;
  }
  if (!data.runs.length) {
    console.log('No runs stored yet. Run with --attest while signed in.');
    return 0;
  }
  console.log(`${C.bold}Stored runs for ${data.username}${C.reset} ${C.dim}(most recent first, up to 100)${C.reset}`);
  console.log(`  ${'#'.padStart(5)}  ${'submitted'.padEnd(20)}  ${'proto'.padEnd(6)}  grade  ${'PR'.padEnd(7)}  receipt`);
  for (const r of data.runs) {
    console.log(`  ${String(r.serial).padStart(5)}  ${new Date(r.submittedAt).toISOString().slice(0, 19).replace('T', ' ')}  ${String(r.protocol || '?').padEnd(6)}  ${String(r.grade || '?').padEnd(5)}  ${(r.prNumber !== null ? `#${r.prNumber}` : '—').padEnd(7)}  ${r.receiptHash.slice(0, 12)}…`);
  }
  console.log('');
  console.log(`${C.dim}Compare two of them: node cli.js compare <serialA> <serialB>${C.reset}`);
  return 0;
}

// Pure field-by-field comparison of two stored runs. Each input is a run
// detail as returned by GET /runs/<serial> ({serial, prNumber, envelope}).
// Returns rows the CLI (or a test) can render without any network.
function compareRuns(a, b) {
  const ra = (a.envelope && a.envelope.receipt) || {};
  const rb = (b.envelope && b.envelope.receipt) || {};
  const fields = [
    ['repo commit', (r) => (r.repo || {}).headSha],
    ['branch', (r) => (r.repo || {}).branch],
    ['dirty tree', (r) => (r.repo || {}).dirty],
    ['protocol', (r) => (r.run || {}).protocol],
    ['mode', (r) => (r.run || {}).mode],
    ['grade', (r) => (r.run || {}).grade],
    ['coverage', (r) => (r.run || {}).coveragePermille],
    ['scenarios run', (r) => `${(r.run || {}).executedScenarios ?? '?'}/${(r.run || {}).requestedScenarios ?? '?'}`],
    ['scenario set', (r) => (r.run || {}).scenarioSetDigest],
    ['results digest', (r) => (r.run || {}).resultsDigest],
    ['pass/fail/warn/err', (r) => {
      const s = (r.run || {}).stats;
      return s ? `${s.pass ?? 0}/${s.fail ?? 0}/${s.warn ?? 0}/${s.error ?? 0}` : null;
    }],
    ['target', (r) => (r.target ? `${r.target.host}:${r.target.port}` : null)],
    ['finished', (r) => { const t = (r.run || {}).finishedAt; return Number.isInteger(t) ? new Date(t).toISOString() : null; }],
  ];
  const rows = [];
  // The PR number lives on the run row, not the receipt.
  rows.push({ label: 'PR', a: a.prNumber !== null && a.prNumber !== undefined ? `#${a.prNumber}` : '—', b: b.prNumber !== null && b.prNumber !== undefined ? `#${b.prNumber}` : '—', same: (a.prNumber ?? null) === (b.prNumber ?? null) });
  for (const [label, get] of fields) {
    const va = get(ra);
    const vb = get(rb);
    rows.push({ label, a: fmtVal(va), b: fmtVal(vb), same: JSON.stringify(va) === JSON.stringify(vb) });
  }
  return rows;
}

function fmtVal(v) {
  if (v === null || v === undefined) return '—';
  if (v === true) return 'yes';
  if (v === false) return 'no';
  return String(v);
}

async function runCompareCommand(args) {
  const R = remote();
  if (!R.isSignedIn()) {
    console.error(`${C.red}Not signed in.${C.reset} Create an account first: node cli.js account --create --email you@paloaltonetworks.com --server <url>`);
    return 1;
  }
  const sa = parseInt(args._[1], 10);
  const sb = parseInt(args._[2], 10);
  if (!Number.isInteger(sa) || !Number.isInteger(sb)) {
    console.error(`${C.red}Usage: node cli.js compare <serialA> <serialB>${C.reset} (serials from \`node cli.js runs\`)`);
    return 1;
  }
  let a, b;
  try {
    [a, b] = await Promise.all([R.getRun(sa, { server: args.server }), R.getRun(sb, { server: args.server })]);
  } catch (err) {
    console.error(`${C.red}${err.message}${C.reset}`);
    return 1;
  }
  const rows = compareRuns(a, b);
  if (args.json) {
    console.log(JSON.stringify({ a: sa, b: sb, rows }, null, 2));
    return 0;
  }
  const wLabel = Math.max(...rows.map((r) => r.label.length), 6);
  const wa = Math.max(...rows.map((r) => r.a.length), `#${sa}`.length);
  console.log(`${C.bold}Comparing run #${sa} vs #${sb}${C.reset}`);
  console.log(`  ${' '.repeat(wLabel)}   ${`#${sa}`.padEnd(wa)}   #${sb}`);
  for (const r of rows) {
    const mark = r.same ? `${C.dim}·${C.reset}` : `${C.yellow}≠${C.reset}`;
    const label = r.label.padEnd(wLabel);
    const aCell = r.same ? r.a.padEnd(wa) : `${C.yellow}${r.a.padEnd(wa)}${C.reset}`;
    const bCell = r.same ? r.b : `${C.yellow}${r.b}${C.reset}`;
    console.log(`  ${label} ${mark} ${aCell}   ${bCell}`);
  }
  const diffs = rows.filter((r) => !r.same).length;
  console.log('');
  console.log(diffs === 0
    ? `${C.green}Identical across all compared fields.${C.reset}`
    : `${C.yellow}${diffs} field(s) differ.${C.reset}`);
  return 0;
}

async function runVerifyTokenCommand(args) {
  const T = require('./attestation-token');
  const source = args._[1];
  let text = '';
  if (!source || source === '-') {
    text = fs.readFileSync(0, 'utf8');
  } else if (fs.existsSync(source)) {
    text = fs.readFileSync(source, 'utf8');
  } else {
    text = source;
  }

  const certPath = args['server-cert'] || path.join(process.cwd(), '.wirestrike', 'server', 'server.pem');
  let serverCertPem;
  try {
    serverCertPem = fs.readFileSync(certPath, 'utf8');
  } catch (_) {
    console.error(`${C.red}No server certificate at ${certPath}${C.reset} — pass --server-cert, or verify from a checkout that commits it`);
    return 1;
  }

  // A wsr1: block pasted alongside the token lets us also check the token
  // was issued for exactly that receipt.
  const envelope = A.decodeBlock(text);
  const result = T.verifyToken(text, { serverCertPem, envelope });

  let online = null;
  if (args.online && result.payload && Number.isInteger(result.payload.serial)) {
    try {
      const R = remote();
      const res = await R.fetchToken(result.payload.serial, { server: args.server });
      const decoded = T.decodeToken(text);
      online = { match: res.token === `wst1:${decoded.payloadB64}.${decoded.signature}`, prNumber: res.prNumber, username: res.username };
      if (!online.match) result.errors.push({ code: 'superseded', message: 'The server holds a different token for this run (re-bound or replaced)' });
    } catch (err) {
      result.warnings.push({ code: 'online-unavailable', message: `Online check failed: ${err.message}` });
    }
  }
  const ok = result.errors.length === 0;

  if (args.json) {
    console.log(JSON.stringify({ ok, payload: result.payload, online, errors: result.errors, warnings: result.warnings }, null, 2));
    return ok ? 0 : 1;
  }

  const p = result.payload || {};
  console.log(`${C.bold}WireStrike attestation token${C.reset}`);
  console.log(`  user       ${p.username || '?'} (${p.email || '?'})  key ${p.keyId || '?'}`);
  console.log(`  run        #${p.serial ?? '?'} · ${String(p.protocol || '?').toUpperCase()} · grade ${p.grade || '?'} · coverage ${Number.isInteger(p.coveragePermille) ? `${(p.coveragePermille / 10).toFixed(1)}%` : '?'}`);
  console.log(`  PR         ${Number.isInteger(p.prNumber) ? `#${p.prNumber}` : `${C.yellow}none claimed${C.reset}`}`);
  const receiptBound = envelope && !result.errors.some((e) => e.code === 'receipt-mismatch');
  console.log(`  receipt    ${p.receiptHash ? p.receiptHash.slice(0, 16) : '?'}…  ${envelope
    ? (receiptBound ? `${C.green}matches the wsr1 block alongside${C.reset}` : `${C.red}does NOT match the wsr1 block alongside${C.reset}`)
    : `${C.dim}no wsr1 block in input to cross-check${C.reset}`}`);
  console.log(`  issued     ${Number.isInteger(p.issuedAt) ? new Date(p.issuedAt).toISOString() : '?'}`);
  if (online) console.log(`  online     ${online.match ? `${C.green}server confirms this exact token${C.reset}` : `${C.red}server holds a DIFFERENT token${C.reset}`}`);
  if (result.errors.length) {
    console.log('');
    for (const e of result.errors) console.log(`${C.red}  ✗ ${e.code}: ${e.message}${C.reset}`);
  }
  if (result.warnings.length) {
    console.log('');
    for (const w of result.warnings) console.log(`${C.yellow}  ⚠ ${w.code}: ${w.message}${C.reset}`);
  }
  console.log('');
  console.log(ok
    ? `${C.green}${C.bold}TOKEN VERIFIED${C.reset} ${C.dim}— issued by the attestation server for this user's signed run.${C.reset}`
    : `${C.red}${C.bold}TOKEN NOT VERIFIED${C.reset}`);
  return ok ? 0 : 1;
}

module.exports = {
  runAttestCommand, runVerifyCommand,
  runAccountCommand, runSubmitCommand, runVerifyTokenCommand, printToken,
  runRunsCommand, runCompareCommand, compareRuns,
};
