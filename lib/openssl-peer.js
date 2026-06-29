// OpenSSL-based well-behaved counterparts for the distributed TLS harness.
//
// Used by run-tls-openssl-compare.js to swap the Node well-behaved counterpart
// for a genuine OpenSSL peer and diff the per-scenario verdicts:
//
//   • startOpenSSLEchoServer() — client-side fuzzing target. `openssl s_server`
//     cannot echo dynamically, so we terminate TLS with `socat OPENSSL-LISTEN`
//     (real OpenSSL stack) and forward plaintext to a tiny Node HTTP backend that
//     mirrors lib/well-behaved-server.js app semantics: GET /→"OK",
//     GET /?size=N→N bytes of 0x42, POST/PUT→echo body, HEAD→headers only.
//
//   • startOpenSSLClient() — server-side fuzzing peer: a plain `openssl s_client`
//     that completes a handshake and sends a GET, mirroring
//     lib/well-behaved-client.js connectTLS().
//
// PQC note: socat exposes no -groups/-curve option, so the OpenSSL front offers
// whatever the linked OpenSSL (3.6) negotiates by default (MLKEM included).

const { spawn, execSync } = require('child_process');
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Share the same cert/key the baseline.js OpenSSL helpers use.
const certPath = path.join(os.tmpdir(), 'fuzzer-openssl-cert.pem');
const keyPath = path.join(os.tmpdir(), 'fuzzer-openssl-key.pem');

function ensureCert() {
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    execSync(
      `openssl req -x509 -newkey rsa:2048 -nodes -keyout ${keyPath} -out ${certPath} -days 1 -subj '/CN=localhost'`,
      { stdio: 'ignore' },
    );
  }
  return { certPath, keyPath };
}

// Detect PQC/hybrid groups the local OpenSSL binary advertises (for s_client).
// Probe the authoritative `-tls-groups` list and offer every PQC/hybrid group it
// actually supports, so `pqc:true` exercises the full set (MLKEM512/768/1024 and
// the hybrids) rather than a hardcoded subset.
let _opensslGroups = null;
const PQC_GROUP_CANDIDATES = [
  'X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'X448MLKEM1024',
  'MLKEM512', 'MLKEM768', 'MLKEM1024',
];
function getOpenSSLGroups() {
  if (_opensslGroups !== null) return _opensslGroups;
  try {
    const out = execSync('openssl list -tls-groups 2>/dev/null', { encoding: 'utf8', timeout: 5000 });
    const lower = out.toLowerCase();
    const groups = ['X25519', 'P-256', 'P-384', 'P-521'];
    for (const g of PQC_GROUP_CANDIDATES) {
      if (lower.includes(g.toLowerCase())) groups.push(g);
    }
    _opensslGroups = groups.join(':');
  } catch {
    _opensslGroups = '';
  }
  return _opensslGroups;
}

// Plaintext HTTP echo backend mirroring lib/well-behaved-server.js startTLS().
function startEchoBackend() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.method === 'GET' || req.method === 'HEAD') {
        let size = 0;
        try {
          const u = new URL(req.url, 'http://localhost');
          size = parseInt(u.searchParams.get('size') || '0', 10);
        } catch (_) {}
        const body = size > 0 ? Buffer.alloc(size, 0x42) : Buffer.from('OK');
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-length': body.length,
          connection: 'close',
        });
        res.end(req.method === 'HEAD' ? undefined : body);
      } else {
        const chunks = [];
        req.on('data', (d) => chunks.push(d));
        req.on('end', () => {
          const b = Buffer.concat(chunks); // echo the payload
          res.writeHead(200, {
            'content-type': 'application/octet-stream',
            'content-length': b.length,
            connection: 'close',
          });
          res.end(b);
        });
      }
    });
    server.on('error', () => {});
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function waitForListen(port, timeoutMs = 5000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(); });
      s.on('error', () => {
        s.destroy();
        if (Date.now() - start > timeoutMs) reject(new Error(`socat not listening on ${port} after ${timeoutMs}ms`));
        else setTimeout(tryOnce, 100);
      });
    };
    tryOnce();
  });
}

// Turn raw OpenSSL s_client/s_server diagnostics (e.g.
// "…:tls_process_server_hello:bad extension:…") into a one-line reason that
// explains the handshake outcome, so callers can report something meaningful
// instead of the verbose error stack. Returns '' when nothing notable is found.
function translatePeerError(raw) {
  if (!raw) return '';
  const t = raw.toLowerCase();
  // Ordered most-specific → least-specific.
  if (t.includes('bad extension') || t.includes('0a00006e')) {
    return 'peer rejected the ServerHello as malformed (illegal/unexpected TLS extension — e.g. a key_share for a group the client never offered, or a synthetic/invalid key_share)';
  }
  if (t.includes('alert number 40') || t.includes('handshake failure') || t.includes('no shared cipher') || t.includes('no shared groups')) {
    return 'peer aborted with handshake_failure (no common version/cipher/group could be negotiated)';
  }
  if (t.includes('alert number 47') || t.includes('illegal parameter') || t.includes('illegal_parameter')) {
    return 'peer aborted with illegal_parameter (a negotiated parameter was invalid, e.g. an un-offered key-exchange group)';
  }
  if (t.includes('alert number 70') || t.includes('protocol version') || t.includes('unsupported protocol') || t.includes('wrong ssl version')) {
    return 'peer aborted with protocol_version (the offered TLS version is not supported)';
  }
  if (t.includes('wrong version number') || t.includes('http request') || t.includes('record layer failure')) {
    return 'peer received non-TLS / unexpected-version bytes (server did not speak TLS as expected)';
  }
  if (t.includes('certificate verify failed') || t.includes('unable to get local issuer') || t.includes('self-signed') || t.includes('self signed')) {
    return ''; // cert-chain noise on a self-signed test cert is benign — not an error
  }
  if (t.includes('connection refused') || t.includes('connect:errno')) {
    return 'could not connect to the target (connection refused)';
  }
  // Fall back to the first non-cosmetic OpenSSL error line, sans the hex prefix.
  const line = raw.split('\n').map((l) => l.trim()).find((l) => /error:/i.test(l) && !/shutdown while in init/i.test(l));
  if (line) {
    const parts = line.split(':');
    return parts[parts.length - 1] || parts[parts.length - 2] || 'peer reported a TLS error';
  }
  return '';
}

// Start an OpenSSL-terminated TLS echo server on `port` (or a random high port).
// Returns { port, stop() }.
async function startOpenSSLEchoServer({ port } = {}) {
  ensureCert();
  const backend = await startEchoBackend();
  const backendPort = backend.address().port;
  const listenPort = port || (40000 + Math.floor(Math.random() * 20000));

  const addr = `OPENSSL-LISTEN:${listenPort},cert=${certPath},key=${keyPath},verify=0,reuseaddr,fork`;
  const socat = spawn('socat', [addr, `TCP:127.0.0.1:${backendPort}`], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  socat.stderr.on('data', (d) => { stderr += d.toString(); });
  socat.on('error', () => {});

  await waitForListen(listenPort, 5000);

  return {
    port: listenPort,
    stop() {
      try { socat.kill('SIGKILL'); } catch (_) {}
      try { backend.close(); } catch (_) {}
    },
    stderr: () => stderr,
  };
}

// Spawn a well-behaved `openssl s_client` peer that connects, sends a GET, and
// stays connected until stop(). Returns { process, stop() }.
function startOpenSSLClient({ port, host = 'localhost', pqc = false, servername = 'localhost' } = {}) {
  const args = ['s_client', '-connect', `${host}:${port}`, '-servername', servername, '-ign_eof', '-quiet'];
  if (pqc) {
    const groups = getOpenSSLGroups();
    if (groups) args.push('-groups', groups);
  }
  // Capture stderr so the handshake outcome can be translated into a meaningful
  // reason (see translatePeerError) instead of leaking the raw OpenSSL stack.
  const client = spawn('openssl', args, { stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  client.stderr.on('data', (d) => { stderr += d.toString(); });
  client.stdout.on('data', () => {}); // drain so the pipe never blocks s_client
  client.on('error', () => {});
  // Mirror WellBehavedClient: send a GET after connecting. Keep stdin open so
  // s_client holds the connection until we kill it.
  try { client.stdin.write('GET / HTTP/1.1\r\nHost: ' + servername + '\r\nConnection: close\r\n\r\n'); } catch (_) {}

  return {
    process: client,
    stop() { try { client.kill('SIGKILL'); } catch (_) {} },
    stderr: () => stderr,
    // Human-readable handshake outcome ('' when the handshake was clean).
    reason: () => translatePeerError(stderr),
  };
}

module.exports = { startOpenSSLEchoServer, startOpenSSLClient, getOpenSSLGroups, ensureCert, translatePeerError };
