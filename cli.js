#!/usr/bin/env node
// WireStrike — CLI Entry Point

const { FuzzerClient } = require('./lib/fuzzer-client');
const { FuzzerServer } = require('./lib/fuzzer-server');
const { UnifiedClient } = require('./lib/unified-client');
const { UnifiedServer } = require('./lib/unified-server');
const { Logger } = require('./lib/logger');
const { runBaseline } = require('./lib/baseline');
const { listScenarios, getScenario, getScenariosByCategory, getClientScenarios, getServerScenarios, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { listHttp2Scenarios, getHttp2Scenario, getHttp2ScenariosByCategory, listHttp2ClientScenarios, listHttp2ServerScenarios } = require('./lib/http2-scenarios');
const { listQuicScenarios, getQuicScenario, getQuicScenariosByCategory, listQuicClientScenarios, listQuicServerScenarios } = require('./lib/quic-scenarios');
const { getTcpScenario, getTcpScenariosByCategory, getTcpClientScenarios, getTcpServerScenarios, listTcpScenarios, TCP_CATEGORIES } = require('./lib/tcp-scenarios');
const { isRawAvailable } = require('./lib/raw-tcp');
const { generateServerCert } = require('./lib/cert-gen');

const USAGE = `
  WireStrike — Protocol Security Testing Suite

  Usage:
    node cli.js client <host> <port> [options]
    node cli.js server <port> [options]
    node cli.js list
    node cli.js pcap-test-cases               List saved PCAP test cases
    node cli.js delete-pcap-test-case <name>  Delete a PCAP test case
    node cli.js migrate-pcap-tests            Convert legacy pcap-tests/*.json to pcap-test-cases/*.js

  Attestation & accounts:
    node cli.js attest --init-key             Create your local signing key
    node cli.js attest [--run <id>]           Emit a signed wsr1: block for a recorded run
    node cli.js verify [block|file|-]         Verify a wsr1: block against .wirestrike/keys/
    node cli.js account --create --email you@paloaltonetworks.com --server <url>
                                              Create an account (issues your 2-year client cert)
    node cli.js account --login|--logout|--status
    node cli.js submit [block|file] --pr <n>  Send a signed run to the central server for a PR token
    node cli.js verify-token [token|file|-]   Verify a wst1: PR token (add --online to ask the server)
    node cli.js runs                          List your stored runs on the server
    node cli.js compare <serialA> <serialB>   Compare two of your stored runs field by field

  Options:
    --scenario <name|all>        Run specific scenario or all
    --category <A-Y|PCAP-CASE>   Run all scenarios in a category (PCAP-CASE = saved test cases)
    --hostname <name>       Server cert CN/SAN (default: localhost)
    --delay <ms>            Delay between actions (default: 100)
    --timeout <ms>          Connection timeout (default: 5000)
    --protocol <type>       Protocol: tls (default), h2, quic, raw-tcp
    --verbose               Show hex dumps of all packets
    --json                  Output results as JSON
    --pcap <file.pcap>      Record packets to PCAP file
    --merge-pcap            Merge all scenarios into a single PCAP file
    --ingest-pcap <file>    Ingest PCAP, save as test, and run it
    --pcap-stream <index>   Select a specific stream from the PCAP (default: 0)
    --list-streams          List all streams found in the PCAP
    --pcap-name <name>      Test name for the saved .js file (prompts in TTY if omitted)
    --no-save               Don't save the ingested PCAP test (run only)
    --distributed           Run ingested PCAP scenario in distributed mode (requires agents)
    --client-agent <h:p>    Client agent host:port for distributed mode (default: localhost:9200)
    --server-agent <h:p>    Server agent host:port for distributed mode (default: localhost:9201)
    --no-baseline           Skip OpenSSL/baseline comparison testing
    --attest                Sign a receipt for this run (and submit it when signed in)
    --pr <n>                PR number to bind into the attestation token (prompts in TTY if omitted)
    --no-submit             Keep an --attest run local; don't send it to the central server

  PCAP Test Workflow:
    1. Ingest:  node cli.js client host 443 --ingest-pcap capture.pcap
                (Names the test; saves pcap-test-cases/<name>.js — a self-contained
                Node.js scenario you can read, edit, diff, and commit.)
    2. List:    node cli.js pcap-test-cases
    3. Run:     node cli.js client host 443 --scenario <name>
    4. Run all: node cli.js client host 443 --category PCAP-CASE

  Examples:
    node cli.js list
    node cli.js client google.com 443 --scenario duplicate-client-hello --verbose
    node cli.js client google.com 443 --category D --verbose --pcap fuzz.pcap
    node cli.js client google.com 443 --scenario all
    node cli.js server 4433 --scenario server-hello-before-client-hello
    node cli.js client example.com 443 --ingest-pcap capture.pcap
    node cli.js client example.com 443 --ingest-pcap capture.pcap --distributed
`;

// Persist a durable record of the run, and emit a signed attestation block
// when --attest was passed. Never fatal: a bookkeeping problem must not fail
// a run that already produced results.
async function recordAndMaybeAttest(ctx) {
  const {
    args, logger, runId, startedAt, protocol, mode, host, port, localServer,
    requestedScenarios, scenarios, results, report, pcapFile, client, aborted, abortReason,
    prNumber = null,
  } = ctx;
  try {
    const { buildRunRecord, attestRun } = require('./lib/attestation-run');
    const E = require('./lib/attestation-evidence');
    const S = require('./lib/attestation-store');

    const repo = E.collectRepoInfo(process.cwd());
    const repoId = repo.available ? repo.repoId : 'no-repo';
    const record = buildRunRecord({
      runId, startedAt, finishedAt: Date.now(), protocol, mode,
      aborted, abortReason, host, port, localServer,
      requestedScenarios, scenarios, results, report, pcapFile,
      dutIdentity: E.collectDutIdentity(client),
    });
    S.saveRunRecord(repoId, record);

    if (!args.attest) return;
    if (!S.keyStatus().exists) {
      logger.error('--attest needs a signing key: run `node cli.js attest --init-key` first');
      return;
    }
    const { envelope, block, warnings } = await attestRun(record, { cwd: process.cwd() });
    console.log('');
    console.log(block);
    for (const w of warnings) logger.error(`Attestation caveat — ${w.message}`);

    // Signed in: hand the receipt to the central server, which stores the
    // run and issues the PR token. Same never-fatal contract as above.
    if (!args['no-submit']) {
      try {
        const remote = require('./lib/attestation-remote');
        if (remote.isSignedIn()) {
          const res = await remote.submitRun({ envelope, prNumber });
          require('./lib/attestation-commands').printToken(res);
        }
      } catch (err) {
        logger.error(`Central submission failed (receipt is still in your local ledger — retry with \`node cli.js submit\`): ${err.message}`);
      }
    }
  } catch (err) {
    logger.error(`Attestation failed: ${err.message}`);
  }
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      if (key === 'verbose' || key === 'json' || key === 'merge-pcap' || key === 'distributed' || key === 'list-streams' || key === 'no-save'
        || key === 'attest' || key === 'attest-hash-target' || key === 'init-key' || key === 'force'
        || key === 'list' || key === 'verify-ledger'
        || key === 'create' || key === 'login' || key === 'logout' || key === 'status'
        || key === 'online' || key === 'no-submit') {
        args[key] = true;
      } else if (key === 'no-baseline') {
        args.baseline = false;
      } else if (i + 1 < argv.length) {
        args[key] = argv[++i];
      }
    } else {
      args._.push(argv[i]);
    }
  }
  
  // Default baseline to true only for TLS protocol
  const protocol = args.protocol || 'tls';
  if (args.baseline === undefined) {
    args.baseline = (protocol === 'tls');
  }

  return args;
}

/**
 * Prompt the user for a test name with `defaultValue` pre-filled. Returns
 * the trimmed reply, or `defaultValue` on empty input. Only call when
 * `process.stdin.isTTY` — readline will hang non-interactively.
 */
function promptName(defaultValue) {
  return new Promise((resolve) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(
      `\x1b[36m  Test name [\x1b[0m\x1b[90m${defaultValue}\x1b[0m\x1b[36m]: \x1b[0m`,
      (answer) => {
        rl.close();
        const trimmed = (answer || '').trim();
        resolve(trimmed.length > 0 ? trimmed : defaultValue);
      }
    );
  });
}

/**
 * Ask which PR this run is for. Optional — empty input means "no PR" — but
 * if given, it is bound into the attestation token. Only called when the
 * user is signed in and stdin is a TTY; `--pr` skips the prompt entirely.
 */
function promptPrNumber() {
  return new Promise((resolve) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(
      '\x1b[36m  PR number for this run (optional, becomes part of the attestation token): \x1b[0m',
      (answer) => {
        rl.close();
        const trimmed = (answer || '').trim();
        if (!trimmed) return resolve(null);
        const n = parseInt(trimmed, 10);
        if (!Number.isInteger(n) || String(n) !== trimmed) {
          console.log('\x1b[33m  Not a number — continuing without a PR binding.\x1b[0m');
          return resolve(null);
        }
        resolve(n);
      }
    );
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (!command || command === 'help') {
    console.log(USAGE);
    process.exit(0);
  }

  if (command === 'list') {
    const { categories, scenarios } = listScenarios();
    console.log('\n  TLS/TCP Fuzzer — Available Scenarios\n');
    for (const [cat, label] of Object.entries(categories)) {
      const items = scenarios[cat] || [];
      const disabledNote = CATEGORY_DEFAULT_DISABLED.has(cat) ? ' \x1b[33m[opt-in]\x1b[0m' : '';
      console.log(`  \x1b[1m\x1b[35m${cat}: ${label}\x1b[0m (${items.length} scenarios)${disabledNote}`);
      for (const s of items) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }

    // HTTP/2 scenarios
    const h2Groups = listHttp2Scenarios();
    console.log('  \x1b[1m\x1b[33mHTTP/2 Scenarios\x1b[0m\n');
    for (const [cat, items] of Object.entries(h2Groups.scenarios)) {
      console.log(`  \x1b[1m\x1b[35m${cat}: ${h2Groups.categories[cat]}\x1b[0m (${items.length} scenarios)`);
      for (const s of items) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }

    // QUIC scenarios
    const quicGroups = listQuicScenarios();
    console.log('  \x1b[1m\x1b[33mQUIC Scenarios\x1b[0m\n');
    for (const [cat, items] of Object.entries(quicGroups.scenarios)) {
      console.log(`  \x1b[1m\x1b[35m${cat}: ${quicGroups.categories[cat]}\x1b[0m (${items.length} scenarios)`);
      for (const s of items) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }

    // TCP scenarios
    const tcpGroups = listTcpScenarios();
    const rawStatus = isRawAvailable() ? '\x1b[32m[available]\x1b[0m' : '\x1b[31m[unavailable — needs CAP_NET_RAW]\x1b[0m';
    console.log(`  \x1b[1m\x1b[33mRaw TCP Scenarios\x1b[0m ${rawStatus}\n`);
    for (const [cat, group] of Object.entries(tcpGroups)) {
      console.log(`  \x1b[1m\x1b[35m${cat}: ${group.label}\x1b[0m (${group.scenarios.length} scenarios) \x1b[33m[opt-in]\x1b[0m`);
      for (const s of group.scenarios) {
        const side = s.side === 'client' ? '\x1b[36mclient\x1b[0m' : '\x1b[33mserver\x1b[0m';
        console.log(`    ${s.name.padEnd(40)} [${side}] \x1b[90m${s.description}\x1b[0m`);
      }
      console.log('');
    }
    process.exit(0);
  }

  // ─── PCAP Test Case Management Commands ─────────────────────────────────
  if (command === 'pcap-test-cases' || command === 'pcap-tests') {
    // `pcap-tests` is accepted as a back-compat alias for one release cycle.
    if (command === 'pcap-tests') {
      console.error('\x1b[33m  Note: "pcap-tests" is deprecated; use "pcap-test-cases" instead.\x1b[0m');
    }
    const { listAllTestCases, PCAP_TEST_CASES_DIR } = require('./lib/pcap-test-cases');
    const tests = listAllTestCases();
    console.log(`\n  PCAP Test Cases (${tests.length} saved in ${PCAP_TEST_CASES_DIR})\n`);
    if (tests.length === 0) {
      console.log('  No PCAP test cases saved yet.');
      console.log('  Use: node cli.js client <host> <port> --ingest-pcap <file.pcap>\n');
    } else {
      const fs = require('fs');
      for (const t of tests) {
        const natTag = t.scenario.pcapParams?.natMerged ? ' \x1b[33m[NAT]\x1b[0m' : '';
        const re = t.scenario.pcapParams?.reassembly;
        const reTotal = re ? (re.c2s.retransmits + re.s2c.retransmits + re.c2s.partialOverlaps + re.s2c.partialOverlaps) : 0;
        const reTag = reTotal > 0 ? ` \x1b[33m[${reTotal} retransmit${reTotal === 1 ? '' : 's'}]\x1b[0m` : '';
        const stats = fs.statSync(t.filePath);
        console.log(`  \x1b[36m${t.name}\x1b[0m${natTag}${reTag}`);
        if (t.scenario.description) console.log(`    ${t.scenario.description}`);
        console.log(`    File: ${t.filePath} (${stats.size} bytes)`);
        console.log(`    Modified: ${stats.mtime.toISOString()}`);
        console.log('');
      }
      console.log(`  To run:    node cli.js client <host> <port> --scenario <name>`);
      console.log(`  To run all: node cli.js client <host> <port> --category PCAP-CASE`);
      console.log(`  To edit:   open the .js file directly — it's a normal Node.js module.\n`);
    }
    process.exit(0);
  }

  if (command === 'delete-pcap-test-case' || command === 'delete-pcap-test') {
    if (command === 'delete-pcap-test') {
      console.error('\x1b[33m  Note: "delete-pcap-test" is deprecated; use "delete-pcap-test-case" instead.\x1b[0m');
    }
    const testName = args._[1];
    if (!testName) {
      console.error('Usage: node cli.js delete-pcap-test-case <name>');
      process.exit(1);
    }
    const { deletePcapTestCase } = require('./lib/pcap-test-cases');
    const ok = deletePcapTestCase(testName);
    if (ok) {
      console.log(`\x1b[32m  ✓ Test case "${testName}" deleted.\x1b[0m`);
    } else {
      console.error(`  Test case "${testName}" not found.`);
      process.exit(1);
    }
    process.exit(0);
  }

  if (command === 'migrate-pcap-tests') {
    const fs = require('fs');
    const path = require('path');
    const legacyDir = path.join(__dirname, 'pcap-tests');
    if (!fs.existsSync(legacyDir)) {
      console.log('  No legacy pcap-tests/ directory found — nothing to migrate.\n');
      process.exit(0);
    }
    const { deserializePcapScenario } = require('./lib/pcap-parser');
    const { saveTestCase, PCAP_TEST_CASES_DIR } = require('./lib/pcap-test-cases');
    const files = fs.readdirSync(legacyDir).filter(f => f.endsWith('.json'));
    if (files.length === 0) {
      console.log('  pcap-tests/ is empty — nothing to migrate.\n');
      process.exit(0);
    }
    console.log(`\n  Migrating ${files.length} legacy test(s) → ${PCAP_TEST_CASES_DIR}\n`);
    let ok = 0, failed = 0;
    for (const file of files) {
      const name = file.replace(/\.json$/, '');
      try {
        const raw = JSON.parse(fs.readFileSync(path.join(legacyDir, file), 'utf8'));
        const scenario = deserializePcapScenario(raw.scenario);
        const saved = saveTestCase(scenario, {
          hostname: 'localhost',
          sourceFile: raw.meta?.sourceFile,
          streamIndex: raw.meta?.streamIndex,
          name,
          overwrite: false,
        });
        console.log(`  \x1b[32m✓\x1b[0m ${name} → ${saved.filePath}`);
        ok++;
      } catch (err) {
        console.log(`  \x1b[31m✗\x1b[0m ${name}: ${err.message}`);
        failed++;
      }
    }
    console.log(`\n  Migrated: ${ok}    Failed: ${failed}`);
    console.log(`  Legacy pcap-tests/ left in place; delete it manually after reviewing the .js files.\n`);
    process.exit(0);
  }

  const logger = new Logger({ verbose: args.verbose, json: args.json });
  const delay = parseInt(args.delay) || 100;
  const timeout = parseInt(args.timeout) || 5000;
  const pcapFile = args.pcap || null;
  const mergePcap = args['merge-pcap'] || false;
  let protocol = args.protocol || 'tls';

  if (command === 'attest' || command === 'verify') {
    const { runAttestCommand, runVerifyCommand } = require('./lib/attestation-commands');
    process.exit(command === 'attest' ? await runAttestCommand(args) : await runVerifyCommand(args));
  }

  if (command === 'account' || command === 'submit' || command === 'verify-token'
    || command === 'runs' || command === 'compare') {
    const cmds = require('./lib/attestation-commands');
    const fn = {
      account: cmds.runAccountCommand, submit: cmds.runSubmitCommand,
      'verify-token': cmds.runVerifyTokenCommand, runs: cmds.runRunsCommand, compare: cmds.runCompareCommand,
    }[command];
    process.exit(await fn(args));
  }

  if (command === 'client') {
    const host = args._[1];
    const port = parseInt(args._[2]);
    if (!host || !port) {
      console.error('Error: client requires <host> <port>');
      console.log(USAGE);
      process.exit(1);
    }

    // Account banner, and the optional PR number that gets bound into the
    // attestation token. Never fatal: account state must not block a run.
    let prNumber = null;
    try {
      const remote = require('./lib/attestation-remote');
      if (remote.isSignedIn()) {
        const acct = remote.loadConfig();
        if (!args.json) console.log(`\x1b[32m  Signed in as ${acct.username}\x1b[0m \x1b[90m(${acct.email})\x1b[0m`);
        if (args.pr !== undefined) {
          const n = parseInt(args.pr, 10);
          if (Number.isInteger(n)) prNumber = n;
        } else if (process.stdin.isTTY && !args.json) {
          prNumber = await promptPrNumber();
        }
      } else if (!args.json) {
        console.log('\x1b[33m  Anonymous mode\x1b[0m \x1b[90m— create an account with your @paloaltonetworks.com work email to use the fuzzer for your PRs:\x1b[0m');
        console.log('\x1b[90m    node cli.js account --create --email you@paloaltonetworks.com --server <url>\x1b[0m');
      }
    } catch (_) {}

    const useRawTcp = protocol === 'raw-tcp';

    if (useRawTcp && !isRawAvailable()) {
      console.error('\x1b[33mWarning: Raw sockets not available. Requires CAP_NET_RAW on Linux.\x1b[0m');
      console.error('  Run: sudo setcap cap_net_raw+ep $(which node)');
      console.error('  Raw TCP scenarios will be skipped.\n');
    }

    // Determine which scenarios to run
    let scenarios;
    if (args['ingest-pcap']) {
      const { parsePcapToScenario, readPcap, groupStreams, analyzeStream } = require('./lib/pcap-parser');
      try {
        const streamIdx = parseInt(args['pcap-stream'] || 0);
        if (args['list-streams']) {
          const packets = readPcap(args['ingest-pcap']);
          const streams = groupStreams(packets);
          const natCount = streams.filter(s => s.natMerged).length;
          console.log(`\n  Streams found in ${args['ingest-pcap']}: (${streams.length} streams${natCount > 0 ? `, ${natCount} NAT-merged` : ''})\n`);
          streams.forEach((s, idx) => {
            const analysis = analyzeStream(s);
            if (analysis.natMerged) {
              console.log(`    \x1b[33m[${idx}]\x1b[0m ${analysis.description}`);
            } else {
              console.log(`    [${idx}] ${analysis.description}`);
            }
          });
          if (natCount > 0) {
            console.log(`\n  \x1b[33mNote:\x1b[0m ${natCount} stream(s) were auto-merged from NAT-split captures.`);
            console.log(`  Streams marked \x1b[33m[NAT-merged]\x1b[0m had client/server traffic with different IPs (NAT rewrite).`);
          }
          process.exit(0);
        }
        const scenario = parsePcapToScenario(args['ingest-pcap'], streamIdx);
        console.log(`\x1b[32m  Ingested scenario from PCAP: ${scenario.description}\x1b[0m`);
        console.log(`\x1b[90m  Explanation: ${scenario.explanation}\x1b[0m\n`);

        // ── Auto-save the PCAP test (unless --no-save) ─────────────────
        if (!args['no-save']) {
          const { saveTestCase } = require('./lib/pcap-test-cases');
          let chosenName = args['pcap-name'];
          if (!chosenName && process.stdin.isTTY) {
            // Interactive prompt: pre-fill with the auto-name and let the
            // user accept or replace it. Non-TTY runs (CI, scripts) skip
            // this and fall back to the auto-name.
            chosenName = await promptName(scenario.name);
          }
          if (!chosenName) chosenName = scenario.name;
          const saved = saveTestCase(scenario, {
            hostname: host,
            sourceFile: args['ingest-pcap'],
            streamIndex: streamIdx,
            name: chosenName,
          });
          console.log(`\x1b[36m  Saved PCAP test case: ${saved.name}\x1b[0m`);
          console.log(`\x1b[90m  File: ${saved.filePath}\x1b[0m`);
          console.log(`\x1b[90m  Review the .js file and commit it when you're ready.\x1b[0m\n`);
        }

        // ── Distributed mode: serialize and push to remote agents ──────
        if (args.distributed) {
          const { serializePcapScenario } = require('./lib/pcap-parser');
          const http = require('http');

          // Parse agent addresses
          const clientAgentStr = args['client-agent'] || 'localhost:9200';
          const serverAgentStr = args['server-agent'] || 'localhost:9201';
          const [clientAgentHost, clientAgentPort] = clientAgentStr.split(':');
          const [serverAgentHost, serverAgentPort] = serverAgentStr.split(':');

          const serialized = serializePcapScenario(scenario, { hostname: host });
          console.log(`  \x1b[36mDistributed mode:\x1b[0m pushing scenario to agents...`);
          console.log(`    Client agent: ${clientAgentHost}:${clientAgentPort}`);
          console.log(`    Server agent: ${serverAgentHost}:${serverAgentPort}`);
          console.log(`    Client actions: ${serialized.clientActions.length}`);
          console.log(`    Server actions: ${serialized.serverActions.length}\n`);

          // Helper for HTTP requests
          function agentRequest(agentHost, agentPort, method, urlPath, body, reqTimeout = 30000) {
            return new Promise((resolve, reject) => {
              const payload = body ? JSON.stringify(body) : null;
              const opts = {
                hostname: agentHost, port: parseInt(agentPort), path: urlPath, method, timeout: reqTimeout,
                headers: { 'Content-Type': 'application/json' },
              };
              if (payload) opts.headers['Content-Length'] = Buffer.byteLength(payload);
              const req = http.request(opts, (res) => {
                let buf = '';
                res.on('data', d => buf += d);
                res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
              });
              req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
              req.on('error', reject);
              if (payload) req.write(payload);
              req.end();
            });
          }

          try {
            // Stop any running tests
            try { await agentRequest(clientAgentHost, clientAgentPort, 'POST', '/stop', {}); } catch (_) {}
            try { await agentRequest(serverAgentHost, serverAgentPort, 'POST', '/stop', {}); } catch (_) {}
            await new Promise(r => setTimeout(r, 500));

            // Configure server agent
            const serverConfig = await agentRequest(serverAgentHost, serverAgentPort, 'POST', '/configure', {
              config: { bindAddress: '0.0.0.0', host: '0.0.0.0', port, hostname: host, protocol: scenario.protocol || 'tls', workers: 1, timeout, delay, baseline: false },
              scenarios: [],
              pcapScenarios: [{ ...serialized, name: serialized.name + '-server', side: 'server' }],
            });
            console.log(`  Server configured: ${serverConfig.scenarioCount} scenario(s)`);

            // Configure client agent
            const clientConnectHost = serverAgentHost === 'localhost' ? '127.0.0.1' : serverAgentHost;
            const clientConfig = await agentRequest(clientAgentHost, clientAgentPort, 'POST', '/configure', {
              config: { host: clientConnectHost, port, protocol: scenario.protocol || 'tls', workers: 1, timeout, delay, baseline: false },
              scenarios: [],
              pcapScenarios: [{ ...serialized, name: serialized.name + '-client', side: 'client' }],
            });
            console.log(`  Client configured: ${clientConfig.scenarioCount} scenario(s)`);

            // Run server first, then client (stepped mode)
            console.log(`\n  Running scenario in distributed mode...\n`);
            const serverRunPromise = agentRequest(serverAgentHost, serverAgentPort, 'POST', '/run-scenario', { index: 0 }, 120000)
              .catch(err => ({ error: err.message }));
            await new Promise(r => setTimeout(r, 500));
            const clientRunPromise = agentRequest(clientAgentHost, clientAgentPort, 'POST', '/run-scenario', { index: 0 }, 120000)
              .catch(err => ({ error: err.message }));

            const [serverResult, clientResult] = await Promise.all([serverRunPromise, clientRunPromise]);

            // Finish
            try { await agentRequest(serverAgentHost, serverAgentPort, 'POST', '/finish', {}); } catch (_) {}
            try { await agentRequest(clientAgentHost, clientAgentPort, 'POST', '/finish', {}); } catch (_) {}
            await new Promise(r => setTimeout(r, 500));

            // Collect results
            let clientResults = [], serverResults = [];
            try { clientResults = await agentRequest(clientAgentHost, clientAgentPort, 'GET', '/results', null); } catch (_) {}
            try { serverResults = await agentRequest(serverAgentHost, serverAgentPort, 'GET', '/results', null); } catch (_) {}

            console.log(`  ═══════════════════════════════════════════════`);
            console.log(`  PCAP DISTRIBUTED RESULTS`);
            console.log(`  ═══════════════════════════════════════════════`);
            console.log(`  Client results: ${Array.isArray(clientResults) ? clientResults.length : 0}`);
            if (Array.isArray(clientResults)) {
              for (const r of clientResults) console.log(`    ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status} ${r.response || ''}`);
            }
            console.log(`  Server results: ${Array.isArray(serverResults) ? serverResults.length : 0}`);
            if (Array.isArray(serverResults)) {
              for (const r of serverResults) console.log(`    ${r.status === 'PASSED' ? '✓' : '✗'} ${r.scenario}: ${r.status} ${r.response || ''}`);
            }
            if (clientResult.error) console.log(`  Client error: ${clientResult.error}`);
            if (serverResult.error) console.log(`  Server error: ${serverResult.error}`);
            console.log(`  ═══════════════════════════════════════════════\n`);

            // Cleanup
            try { await agentRequest(clientAgentHost, clientAgentPort, 'POST', '/stop', {}); } catch (_) {}
            try { await agentRequest(serverAgentHost, serverAgentPort, 'POST', '/stop', {}); } catch (_) {}
          } catch (err) {
            console.error(`  Distributed mode failed: ${err.message}`);
            console.error(`  Make sure agents are running:`);
            console.error(`    Client: node cli.js client-agent --control-port ${clientAgentPort}`);
            console.error(`    Server: node cli.js server-agent --control-port ${serverAgentPort}`);
          }
          process.exit(0);
        }

        // ── Local mode (default) ───────────────────────────────────────
        scenarios = [scenario];
        protocol = scenario.protocol || protocol;
      } catch (err) {
        console.error(`Failed to ingest PCAP: ${err.message}`);
        process.exit(1);
      }
    } else if (args.category) {
      if (useRawTcp) scenarios = getTcpScenariosByCategory(args.category);
      else if (protocol === 'h2') scenarios = getHttp2ScenariosByCategory(args.category);
      else if (protocol === 'quic') scenarios = getQuicScenariosByCategory(args.category);
      else scenarios = getScenariosByCategory(args.category);

      scenarios = scenarios.filter(s => s.side === 'client');
      if (scenarios.length === 0) {
        console.error(`No client scenarios in category ${args.category}`);
        process.exit(1);
      }
    } else if (args.scenario === 'all') {
      if (useRawTcp) {
        scenarios = getTcpClientScenarios();
      } else if (protocol === 'h2') {
        scenarios = listHttp2ClientScenarios();
      } else if (protocol === 'quic') {
        scenarios = listQuicClientScenarios();
      } else {
        scenarios = getClientScenarios().filter(s => !CATEGORY_DEFAULT_DISABLED.has(s.category));
      }
      if (scenarios.length === 0) {
        console.error('No enabled client scenarios found');
        process.exit(1);
      }
    } else if (args.scenario) {
      let s;
      if (useRawTcp) s = getTcpScenario(args.scenario);
      else if (protocol === 'h2') s = getHttp2Scenario(args.scenario);
      else if (protocol === 'quic') s = getQuicScenario(args.scenario);
      
      if (!s) s = getScenario(args.scenario);

      if (!s) {
        console.error(`Unknown scenario: ${args.scenario}`);
        process.exit(1);
      }
      if (s.side !== 'client') {
        console.error(`Scenario "${args.scenario}" is a server-side scenario. Use: node cli.js server`);
        process.exit(1);
      }
      scenarios = [s];
    } else {
      console.error('Error: specify --scenario <name|all> or --category <A-H|RA-RG>');
      console.log(USAGE);
      process.exit(1);
    }


    // Use UnifiedClient for raw-tcp (or h2/quic), FuzzerClient for plain TLS
    // One id shared by the run record, the manifest and the receipt, so the
    // three can be correlated after the fact.
    const runId = require('crypto').randomUUID();
    const startedAt = Date.now();

    const client = (useRawTcp || protocol === 'h2' || protocol === 'quic')
      ? new UnifiedClient({ host, port, timeout, delay, logger, pcapFile, mergePcap })
      : new FuzzerClient({ host, port, timeout, delay, logger, pcapFile, mergePcap });

    const originalRunScenario = client.runScenario.bind(client);
    client.runScenario = async (scenario) => {
      if (args.baseline) {
        if (!logger.json) console.log(`\x1b[90m    [baseline] testing against local OpenSSL...\x1b[0m`);
        const baselineRes = await runBaseline(scenario, protocol);
        scenario._baselineResponse = baselineRes.response;
      }
      return originalRunScenario(scenario);
    };

    const originalResult = logger.result.bind(logger);
    logger.result = (scenarioName, status, response, verdict, expectedReason, hostDown, finding, compliance) => {
      const s = scenarios.find(x => x.name === scenarioName);
      const baselineResponse = s ? s._baselineResponse : null;
      if (!logger.json && baselineResponse) {
        if (baselineResponse === response) {
          console.log(`\x1b[32m    ✓ Response matches OpenSSL baseline\x1b[0m`);
        } else {
          console.log(`\x1b[33m    ⚠ Differs from OpenSSL! OpenSSL response: ${baselineResponse}\x1b[0m`);
        }
      }
      originalResult(scenarioName, status, response, verdict, expectedReason, hostDown, finding, compliance);
    };

    // Ctrl+C: ask the run to stop, then let runScenarios return normally so
    // the partial results and report survive. Exiting from the handler both
    // discarded every result and reported success — an interrupted run must
    // never look like a clean pass.
    let abortReason = null;
    let sigintCount = 0;
    process.on('SIGINT', () => {
      if (++sigintCount > 1) {
        logger.error('Interrupted again — exiting now, results discarded');
        process.exit(130);
      }
      abortReason = 'sigint';
      logger.info('Interrupted — finishing the current scenario, then writing results...');
      client.abort();
      // The per-scenario safety timeout is far longer than anyone will wait
      // on a Ctrl-C, so bound it here.
      const watchdog = setTimeout(() => {
        logger.error('Scenario did not settle within 10s — exiting');
        process.exit(130);
      }, 10000);
      watchdog.unref();
    });

    // Report this run to the attestation server (if signed in) so it shows as
    // a running test in the operator console. Never fatal.
    let reporter = { stop() {} };
    try {
      reporter = require('./lib/run-reporter').startReporting({
        runId, protocol, targetHost: host, targetPort: port, mode: 'client', requestedScenarios: scenarios.length,
      });
    } catch (_) {}

    let results;
    let report;
    try {
      ({ results, report } = await client.runScenarios(scenarios));
    } finally {
      reporter.stop();
    }

    // Send graceful shutdown signal to fuzzer server
    if (client.shutdown) {
      await client.shutdown(protocol);
    }

    client.close();

    if (pcapFile) {
      logger.info(`PCAP saved to: ${pcapFile}`);
    }

    // Every run is recorded, with or without --attest: a plain CLI run used to
    // leave nothing durable behind, so there was nothing to attest afterwards.
    await recordAndMaybeAttest({
      args, logger, runId, startedAt, protocol, mode: 'client',
      host, port, localServer: false,
      requestedScenarios: scenarios.length, scenarios, results, report,
      pcapFile, client, aborted: abortReason !== null, abortReason, prNumber,
    });

    // Exit with non-zero if any failures, errors, or host went down
    const hasErrors = results.some(r => r.status === 'ERROR');
    const hostWentDown = results.some(r => r.hostDown);
    const hasFails = report && report.stats.fail > 0;
    if (abortReason === 'sigint') process.exit(130);
    process.exit(hasErrors || hostWentDown || hasFails ? 1 : 0);

  } else if (command === 'server') {
    const port = parseInt(args._[1]);
    if (!port) {
      console.error('Error: server requires <port>');
      console.log(USAGE);
      process.exit(1);
    }

    const useRawTcp = protocol === 'raw-tcp';

    // Determine which scenarios to run
    let scenarios;
    if (args.category) {
      if (useRawTcp) scenarios = getTcpScenariosByCategory(args.category);
      else if (protocol === 'h2') scenarios = getHttp2ScenariosByCategory(args.category);
      else if (protocol === 'quic') scenarios = getQuicScenariosByCategory(args.category);
      else scenarios = getScenariosByCategory(args.category);

      scenarios = scenarios.filter(s => s.side === 'server');
    } else if (args.scenario === 'all') {
      if (useRawTcp) {
        scenarios = getTcpServerScenarios();
      } else if (protocol === 'h2') {
        scenarios = listHttp2ServerScenarios();
      } else if (protocol === 'quic') {
        scenarios = listQuicServerScenarios();
      } else {
        scenarios = getServerScenarios().filter(s => !CATEGORY_DEFAULT_DISABLED.has(s.category));
      }
      if (scenarios.length === 0) {
        console.error('No enabled server scenarios found');
        process.exit(1);
      }
    } else if (args.scenario) {
      let s;
      if (useRawTcp) s = getTcpScenario(args.scenario);
      else if (protocol === 'h2') s = getHttp2Scenario(args.scenario);
      else if (protocol === 'quic') s = getQuicScenario(args.scenario);
      
      if (!s) s = getScenario(args.scenario);

      if (!s) {
        console.error(`Unknown scenario: ${args.scenario}`);
        process.exit(1);
      }
      if (s.side !== 'server') {
        console.error(`Scenario "${args.scenario}" is a client-side scenario. Use: node cli.js client`);
        process.exit(1);
      }
      scenarios = [s];
    } else {
      console.error('Error: specify --scenario <name|all> or --category <A-H|RA-RG>');
      console.log(USAGE);
      process.exit(1);
    }

    const hostname = args.hostname || 'localhost';
    const certInfo = generateServerCert(hostname);
    const fp = (certInfo.fingerprint.match(/.{2}/g) || []).join(':').toUpperCase();
    logger.info(`Server certificate: CN=${hostname} | SHA256=${fp}`);

    // UnifiedServer handles all protocols and fallback logic
    const server = new UnifiedServer({
      port, hostname, timeout, delay, logger, pcapFile, mergePcap,
      cert: certInfo.certDER,
      certInfo,
    });

    const originalRunScenario = server.runScenario.bind(server);
    server.runScenario = async (scenario) => {
      if (args.baseline) {
        if (!logger.json) console.log(`\x1b[90m    [baseline] testing against local OpenSSL...\x1b[0m`);
        const baselineRes = await runBaseline(scenario, protocol);
        scenario._baselineResponse = baselineRes.response;
      }
      return originalRunScenario(scenario);
    };

    const originalResult = logger.result.bind(logger);
    logger.result = (scenarioName, status, response, verdict, expectedReason, hostDown, finding, compliance) => {
      const s = scenarios.find(x => x.name === scenarioName);
      const baselineResponse = s ? s._baselineResponse : null;
      if (!logger.json && baselineResponse) {
        if (baselineResponse === response) {
          console.log(`\x1b[32m    ✓ Response matches OpenSSL baseline\x1b[0m`);
        } else {
          console.log(`\x1b[33m    ⚠ Differs from OpenSSL! OpenSSL response: ${baselineResponse}\x1b[0m`);
        }
      }
      originalResult(scenarioName, status, response, verdict, expectedReason, hostDown, finding, compliance);
    };

    // See the client branch: exiting from the handler discarded the results
    // and reported success. Abort, let runScenarios return, then exit 130.
    let abortReason = null;
    let sigintCount = 0;
    process.on('SIGINT', () => {
      if (++sigintCount > 1) {
        logger.error('Interrupted again — exiting now, results discarded');
        process.exit(130);
      }
      abortReason = 'sigint';
      logger.info('Interrupted — finishing the current scenario, then writing results...');
      server.abort();
      const watchdog = setTimeout(() => {
        logger.error('Scenario did not settle within 10s — exiting');
        process.exit(130);
      }, 10000);
      watchdog.unref();
    });

    const { results, report } = await server.runScenarios(scenarios);
    server.close();

    if (pcapFile) {
      logger.info(`PCAP saved to: ${pcapFile}`);
    }

    const hasErrors = results.some(r => r.status === 'ERROR');
    const hasFails = report && report.stats.fail > 0;
    if (abortReason === 'sigint') process.exit(130);
    process.exit(hasErrors || hasFails ? 1 : 0);

  } else {
    console.error(`Unknown command: ${command}`);
    console.log(USAGE);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
