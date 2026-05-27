#!/usr/bin/env node
'use strict';

// cv-agent.js — cert-verify client agent.
// Deployed to the client machine. Exposes an HTTP control API so the
// controller can verify readiness, then streams TLS connection results
// for each cert-verify scenario back to the orchestrator.
//
// Endpoints:
//   GET /status          → { ok: true, role: 'client' }
//   GET /run-cv?host=&port=&timeout=&delay=  → NDJSON stream of results

const http = require('http');
const tls  = require('tls');

// Resolve scenarios relative to this file's location in the bundle
const { SCENARIOS } = require('./scenarios');

const args = process.argv.slice(2);
let controlPort = 9200;
let token = '';
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--control-port') controlPort = parseInt(args[++i], 10);
  if (args[i] === '--token')        token = args[++i];
}

function connectTLS(host, port, timeoutMs) {
  return new Promise(resolve => {
    let done = false;
    const finish = r => { if (!done) { done = true; resolve(r); } };

    const timer = setTimeout(() => {
      try { socket.destroy(); } catch (_) {}
      finish({ allowed: false, error: 'timeout' });
    }, timeoutMs);

    const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {
      clearTimeout(timer);
      socket.destroy();
      finish({ allowed: true });
    });
    socket.on('error', err => {
      clearTimeout(timer);
      finish({ allowed: false, error: err.code || err.message });
    });
  });
}

let running = false;

const server = http.createServer(async (req, res) => {
  const auth = req.headers['authorization'] || '';
  if (token && auth !== `Bearer ${token}`) {
    res.writeHead(401); res.end('Unauthorized'); return;
  }

  if (req.method === 'GET' && req.url === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, role: 'client', protocol: 'cert-verify', running }));
    return;
  }

  if (req.method === 'GET' && req.url.startsWith('/run-cv')) {
    if (running) {
      res.writeHead(409); res.end('Already running'); return;
    }
    running = true;

    const qs  = new URL('http://localhost' + req.url).searchParams;
    const host      = qs.get('host')    || '127.0.0.1';
    const port      = parseInt(qs.get('port')    || '44300', 10);
    const timeoutMs = parseInt(qs.get('timeout') || '10000', 10);
    const delayMs   = parseInt(qs.get('delay')   || '300',   10);

    res.writeHead(200, {
      'Content-Type': 'application/x-ndjson',
      'Transfer-Encoding': 'chunked',
      'Cache-Control': 'no-cache',
    });

    try {
      for (const s of SCENARIOS) {
        const result = await connectTLS(host, port, timeoutMs);
        const actual = result.allowed ? 'ALLOWED' : 'BLOCKED';
        // Map WireStrike expected (PASSED/DROPPED) to connection terms (ALLOWED/BLOCKED)
        const expectedNorm = s.expected.toUpperCase() === 'PASSED' ? 'ALLOWED' : 'BLOCKED';
        res.write(JSON.stringify({
          index:    s.index,
          name:     s.name,
          expected: s.expected.toUpperCase(),
          actual,
          pass:     actual === expectedNorm,
          error:    result.error || null,
        }) + '\n');
        if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs));
      }
    } finally {
      running = false;
      res.end();
    }
    return;
  }

  res.writeHead(404); res.end('Not Found');
});

server.listen(controlPort, '0.0.0.0', () => {
  console.log(`[CV-Agent] Listening on port ${controlPort}`);
});
