#!/usr/bin/env node
'use strict';

// cert-verify-server.js — WireStrike certificate-verification test server
//
// Runs three services on the server machine:
//   1. TLS server (port 44300) — presents cert chains with CRL/OCSP URLs
//   2. CRL server (port 18888) — serves DER-encoded CRLs over HTTP
//   3. OCSP server (port 18889) — serves OCSP responses over HTTP
//
// The firewall under test sits between the client and this server.
// It fetches CRL/OCSP URLs from the certs and decides whether to allow the session.
//
// Usage:
//   node cert-verify-server.js [options]
//
// Options:
//   --server-ip <ip>      IP address embedded in CRL/OCSP URLs (default: 127.0.0.1)
//   --tls-port  <port>    TLS server port (default: 44300)
//   --crl-port  <port>    CRL HTTP server port (default: 18888)
//   --ocsp-port <port>    OCSP HTTP server port (default: 18889)
//   --scenario  <name|n>  Run a specific scenario by name or index (default: all)
//   --loop                Loop through scenarios repeatedly
//   --verbose             Enable verbose logging
//   --list                Print all scenarios and exit
//   --pki-dir <path>      Custom PKI storage directory (default: ~/.wirestrike-cv)

const { PKI }                 = require('./lib/cert-verify/pki');
const { CrlServer }           = require('./lib/cert-verify/crl-server');
const { OcspServer }          = require('./lib/cert-verify/ocsp-server');
const { SCENARIOS }           = require('./lib/cert-verify/scenarios');
const { CertVerifyTLSServer } = require('./lib/cert-verify/tls-server');

function parseArgs(argv) {
  const args = {
    serverIp: '127.0.0.1',
    tlsPort:  44300,
    crlPort:  18888,
    ocspPort: 18889,
    scenario:    null,
    loop:        false,
    verbose:     false,
    list:        false,
    pkiDir:      null,
    // serialNonce removed — serials are now random per cert
  };

  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--loop')    { args.loop    = true; continue; }
    if (a === '--verbose') { args.verbose = true; continue; }
    if (a === '--list')    { args.list    = true; continue; }

    const eq  = a.indexOf('=');
    const key = eq >= 0 ? a.slice(0, eq) : a;
    const val = eq >= 0 ? a.slice(eq + 1) : argv[++i];

    if (key === '--server-ip')    args.serverIp    = val;
    if (key === '--tls-port')     args.tlsPort     = parseInt(val, 10);
    if (key === '--crl-port')     args.crlPort     = parseInt(val, 10);
    if (key === '--ocsp-port')    args.ocspPort    = parseInt(val, 10);
    if (key === '--scenario')     args.scenario    = val;
    if (key === '--pki-dir')      args.pkiDir      = val;
  }

  return args;
}

function listScenarios() {
  console.log(`\nCert-Verification Scenarios (${SCENARIOS.length} total)\n`);

  const groups = {};
  for (const s of SCENARIOS) {
    if (!groups[s.group]) groups[s.group] = [];
    groups[s.group].push(s);
  }

  for (const [group, list] of Object.entries(groups)) {
    console.log(`\n[${group}] — ${list.length} scenario(s)`);
    for (const s of list) {
      const idx  = String(s.index).padStart(3, ' ');
      const name = s.name.padEnd(50);
      console.log(`  #${idx} ${name} expected: ${s.expected}`);
    }
  }
  console.log('');
}

async function main() {
  const args = parseArgs(process.argv);

  if (args.list) {
    listScenarios();
    process.exit(0);
  }

  // Select scenario(s) to cycle through
  let toRun;
  if (args.scenario !== null) {
    const s = isNaN(args.scenario)
      ? SCENARIOS.find(x => x.name === args.scenario)
      : SCENARIOS[parseInt(args.scenario, 10)];
    if (!s) {
      console.error(`[CV] Scenario not found: ${args.scenario}`);
      process.exit(1);
    }
    toRun = [s];
  } else {
    toRun = SCENARIOS;
  }

  // ── PKI ─────────────────────────────────────────────────────────────────
  console.log('[CV] Initializing PKI…');
  const pki = new PKI();
  pki.init({
    serverIP: args.serverIp,
    crlPort:  args.crlPort,
    ocspPort: args.ocspPort,
    pkiDir:   args.pkiDir,
  });
  console.log(`[CV] Root CA: ${pki.pkiDir}/root-ca.pem`);

  // ── Revocation servers ───────────────────────────────────────────────────
  const crlServer  = new CrlServer({ port: args.crlPort,  host: '0.0.0.0' });
  const ocspServer = new OcspServer({ port: args.ocspPort, host: '0.0.0.0' });

  crlServer.setCA({
    rootKeyPEM:     pki.getRootKeyPEM(),
    rootSubjectDER: pki.getRootSubjectDER(),
    interKeyPEM:    pki.getInterKeyPEM(),
  });
  ocspServer.setCA({
    rootKeyPEM:        pki.getRootKeyPEM(),
    rootSubjectDER:    pki.getRootSubjectDER(),
    rootPublicKeyDER:  pki.rootPublicKeyDER,
    interKeyPEM:       pki.getInterKeyPEM(),
    interPublicKeyDER: pki.getInterPublicKeyDER(),
  });

  // Register every intermediate's subject DER so CRL server can sign correctly
  for (const chain of [...pki.chains, ...pki.deadCrlChains, ...pki.deadOcspChains]) {
    crlServer.setInterSubject(chain.interSerialHex, chain.interSubjectDER);
  }

  await Promise.all([crlServer.start(), ocspServer.start()]);

  // ── TLS server ───────────────────────────────────────────────────────────
  const tlsServer = new CertVerifyTLSServer({
    port:    args.tlsPort,
    host:    '0.0.0.0',
    verbose: args.verbose,
  });
  tlsServer.init(pki, crlServer, ocspServer);
  await tlsServer.start();

  console.log('[CV] ─────────────────────────────────────────────────────');
  console.log(`[CV] TLS  server : 0.0.0.0:${args.tlsPort}`);
  console.log(`[CV] CRL  server : 0.0.0.0:${args.crlPort}`);
  console.log(`[CV] OCSP server : 0.0.0.0:${args.ocspPort}`);
  console.log(`[CV] Server IP in certs: ${args.serverIp}`);
  console.log(`[CV] Scenarios   : ${toRun.length} loaded`);
  console.log('[CV] ─────────────────────────────────────────────────────');

  // ── Scenario cycling ─────────────────────────────────────────────────────
  let scenarioIdx = 0;
  let completed   = 0;

  function activateScenario() {
    const s = toRun[scenarioIdx];
    tlsServer.setScenario(s);
    console.log(`[CV] Active: #${String(s.index).padStart(3, '0')} ${s.name}  (expected: ${s.expected})`);
  }

  tlsServer.setOnResult((scenario, result) => {
    const status = result.success ? 'OK' : `FAIL(${result.error})`;
    console.log(`[CV] Done:   #${String(scenario.index).padStart(3, '0')} ${scenario.name}  → ${status}`);
    completed++;

    if (args.loop || toRun.length > 1) {
      scenarioIdx = (scenarioIdx + 1) % toRun.length;

      if (!args.loop && scenarioIdx === 0) {
        console.log(`[CV] All ${completed} scenario(s) served. Server still running — Ctrl+C to exit.`);
        return;
      }
      activateScenario();
    }
  });

  activateScenario();

  // ── Shutdown ─────────────────────────────────────────────────────────────
  async function shutdown() {
    console.log('\n[CV] Shutting down…');
    await Promise.all([crlServer.stop(), ocspServer.stop(), tlsServer.stop()]);
    process.exit(0);
  }

  process.on('SIGINT',  () => shutdown());
  process.on('SIGTERM', () => shutdown());
}

main().catch(err => {
  console.error('[CV] Fatal:', err.message);
  process.exit(1);
});
