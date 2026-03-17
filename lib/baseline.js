const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const { generateServerCert } = require('./cert-gen');
const { FuzzerClient } = require('./fuzzer-client');
const { UnifiedClient } = require('./unified-client');
const { QuicFuzzerClient } = require('./quic-fuzzer-client');
const { Http2FuzzerClient } = require('./http2-fuzzer-client');
const { FuzzerServer } = require('./fuzzer-server');
const { UnifiedServer } = require('./unified-server');
const { QuicFuzzerServer } = require('./quic-fuzzer-server');
const { Http2FuzzerServer } = require('./http2-fuzzer-server');
const { WellBehavedServer } = require('./well-behaved-server');
const { WellBehavedClient } = require('./well-behaved-client');
const fs = require('fs');

class DummyLogger {
  verbose = false;
  json = true;
  events = [];
  onEvent() { return () => {}; }
  _emit() {}
  timestamp() { return ''; }
  scenario() {}
  sent() {}
  received() {}
  info() {}
  warn() {}
  error() {}
  fuzz() {}
  tcpEvent() {}
  healthProbe() {}
  hostDown() {}
  result() {}
}

const certPath = path.join(os.tmpdir(), 'fuzzer-openssl-cert.pem');
const keyPath = path.join(os.tmpdir(), 'fuzzer-openssl-key.pem');

// Detect which PQC groups the local OpenSSL supports
let _opensslGroups = null;
function getOpenSSLGroups() {
  if (_opensslGroups !== null) return _opensslGroups;
  try {
    const out = execSync('openssl list -kem-algorithms 2>/dev/null', { encoding: 'utf8', timeout: 5000 });
    const groups = [];
    // Standard curves (always supported)
    groups.push('X25519', 'P-256', 'P-384', 'P-521');
    // PQC/hybrid groups — only add if OpenSSL reports them
    if (out.includes('X25519MLKEM768')) groups.push('X25519MLKEM768');
    if (out.includes('SecP256r1MLKEM768')) groups.push('SecP256r1MLKEM768');
    if (out.includes('SecP384r1MLKEM1024')) groups.push('SecP384r1MLKEM1024');
    if (out.includes('MLKEM768')) groups.push('MLKEM768');
    if (out.includes('MLKEM1024')) groups.push('MLKEM1024');
    if (out.includes('MLKEM512')) groups.push('MLKEM512');
    _opensslGroups = groups.join(':');
  } catch {
    _opensslGroups = '';
  }
  return _opensslGroups;
}

// Helper to spawn OpenSSL Server
function startOpenSSLServer(port) {
  try {
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout ${keyPath} -out ${certPath} -days 1 -subj '/CN=localhost'`, { stdio: 'ignore' });
    }
  } catch (e) {
    return null;
  }

  const args = [
    's_server',
    '-cert', certPath,
    '-key', keyPath,
    '-accept', port.toString(),
    '-www',
    '-alpn', 'h2,http/1.1',
    '-ign_eof'
  ];

  // Enable PQC groups if supported
  const groups = getOpenSSLGroups();
  if (groups) args.push('-groups', groups);

  const server = spawn('openssl', args);

  return new Promise((resolve) => {
    let started = false;
    server.stdout.on('data', (data) => {
      if (!started && data.toString().includes('ACCEPT')) {
        started = true;
        resolve(server);
      }
    });
    server.on('error', () => { if (!started) resolve(null); });
    setTimeout(() => { if (!started) resolve(server); }, 500); // fallback timeout
  });
}

  // Helper to run OpenSSL Client
function runOpenSSLClient(port, protocol) {
  const args = ['s_client', '-connect', `localhost:${port}`, '-ign_eof'];
  if (protocol === 'h2') args.push('-alpn', 'h2');
  if (protocol === 'quic') args.push('-quic');
  
  const client = spawn('openssl', args);
  // Send some dummy data to keep it alive or trigger server reaction
  client.stdin.write("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
  
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(client);
    }, 200); // give it time to connect
  });
}

async function runBaseline(scenario, protocol = 'tls') {
  const port = 44333 + Math.floor(Math.random() * 1000); // random port to avoid collisions
  const useRawTcp = protocol === 'raw-tcp';
  const dummyLogger = new DummyLogger();

  // QUIC baseline uses Node.js dgram-based server/client instead of OpenSSL
  // (openssl s_server/s_client don't support -quic in most builds)
  if (protocol === 'quic') {
    return runQuicBaseline(scenario, port, dummyLogger);
  }

  if (scenario.side === 'client') {
    // Target is an OpenSSL server
    const sslServer = await startOpenSSLServer(port);
    if (!sslServer) return { response: 'Failed to start OpenSSL baseline server', command: 'openssl s_server ...' };

    const groups = getOpenSSLGroups();
    const command = `openssl s_server -cert ${certPath} -key ${keyPath} -accept ${port} -www -alpn h2,http/1.1 -ign_eof` + (groups ? ` -groups ${groups}` : '');

    let client;
    if (useRawTcp || protocol === 'h2') {
      client = new UnifiedClient({ host: '127.0.0.1', port, timeout: 2000, delay: 50, logger: dummyLogger });
    } else {
      client = new FuzzerClient({ host: '127.0.0.1', port, timeout: 2000, delay: 50, logger: dummyLogger });
    }

    try {
      const res = await client.runScenario(scenario);
      return { response: res.response || res.status, command };
    } catch (e) {
      return { response: 'Baseline Error: ' + e.message, command };
    } finally {
      sslServer.kill('SIGKILL');
      if (client.close) client.close();
    }
  } else {
    // Server scenario: Target is an OpenSSL client
    let server;
    if (useRawTcp || protocol === 'h2') {
      server = new UnifiedServer({ port, timeout: 2000, delay: 50, logger: dummyLogger });
    } else {
      server = new FuzzerServer({ port, timeout: 2000, delay: 50, logger: dummyLogger });
    }

    const args = ['s_client', '-connect', `localhost:${port}`, '-ign_eof'];
    if (protocol === 'h2') args.push('-alpn', 'h2');
    const command = `openssl ${args.join(' ')}`;

    // Spawn openssl client in background shortly after server starts listening
    // runScenario binds the port, so give it 50ms to bind before spawning s_client
    let sslClient;
    setTimeout(async () => {
      sslClient = await runOpenSSLClient(port, protocol);
    }, 50);

    try {
      const res = await server.runScenario(scenario);
      return { response: res.response || res.status, command };
    } catch (e) {
      return { response: 'Baseline Error: ' + e.message, command };
    } finally {
      if (sslClient) sslClient.kill('SIGKILL');
      if (server.close) server.close();
      if (server.stop) await server.stop();
      if (server.server) server.server.close();
    }
  }
}

async function runQuicBaseline(scenario, port, dummyLogger) {
  if (scenario.side === 'client') {
    // Client scenario: start a Node.js QUIC responder as the baseline target
    const wbServer = new WellBehavedServer({ port, hostname: 'localhost' });
    await wbServer.startQuic();
    const command = `[Node.js QUIC responder on UDP :${wbServer.actualPort}]`;

    const client = new UnifiedClient({ host: '127.0.0.1', port: wbServer.actualPort, timeout: 2000, delay: 50, logger: dummyLogger });

    try {
      const res = await client.runScenario(scenario);
      return { response: res.response || res.status, command };
    } catch (e) {
      return { response: 'Baseline Error: ' + e.message, command };
    } finally {
      wbServer.stop();
      if (client.close) client.close();
    }
  } else {
    // Server scenario: start the fuzzer's QUIC server and send a well-behaved QUIC Initial
    const server = new UnifiedServer({ port, timeout: 2000, delay: 50, logger: dummyLogger });
    const command = `[Node.js QUIC client → UDP :${port}]`;

    // Spawn a well-behaved QUIC client after a short delay
    const wbClient = new WellBehavedClient({ host: '127.0.0.1', port });
    setTimeout(() => {
      wbClient.connectQuic().catch(() => {});
    }, 50);

    try {
      const res = await server.runScenario(scenario);
      return { response: res.response || res.status, command };
    } catch (e) {
      return { response: 'Baseline Error: ' + e.message, command };
    } finally {
      wbClient.stop();
      if (server.close) server.close();
    }
  }
}

module.exports = { runBaseline };
