
const http = require('http');
const fs = require('fs');
const { startAgent } = require('./lib/agent');
const { WellBehavedServer } = require('./lib/well-behaved-server');

const SERVER_PORT = 4436;
const AGENT_PORT = 9253;
const LOG_FILE = 'rapid-reset.log';
const logStream = fs.createWriteStream(LOG_FILE);

function httpPost(port, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ hostname: 'localhost', port, path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function httpGet(port, path) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: 'localhost', port, path }, (res) => {
      let buf = '';
      res.on('data', d => buf += d);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve(buf); } });
    }).on('error', reject);
  });
}

function startLogCollector(port) {
  const req = http.get({ hostname: 'localhost', port, path: '/events' }, (res) => {
    res.on('data', (chunk) => {
      chunk.toString().split('\n').forEach(line => {
        if (!line.trim()) return;
        try {
          const event = JSON.parse(line);
          if (event.type === 'logger') {
            const e = event.event;
            if (e.type === 'sent') {
              logStream.write(`${e.ts} → ${e.label} (${e.size} bytes)\n`);
            } else if (e.type === 'received') {
              logStream.write(`${e.ts} ← ${e.label} (${e.size} bytes)\n`);
            } else if (e.type === 'tcp') {
              const arrow = e.direction === 'sent' ? '→' : '←';
              logStream.write(`${e.ts} ${arrow} [TCP] ${e.event}\n`);
            } else if (e.type === 'info') {
              logStream.write(`${e.ts} ℹ ${e.message}\n`);
            }
          } else if (event.type === 'result') {
            logStream.write(`\nRESULT: ${event.result.status} (${event.result.response || ''})\n`);
          }
        } catch (e) {}
      });
    });
  });
  return req;
}

async function run() {
  console.log('Starting server and agent...');
  const server = new WellBehavedServer({ hostname: 'localhost', port: SERVER_PORT, logger: null });
  await server.startH2();
  const actualPort = server._actualPort || SERVER_PORT;

  const agent = startAgent('client', { controlPort: AGENT_PORT });
  await new Promise(r => setTimeout(r, 1000));
  const collector = startLogCollector(AGENT_PORT);

  console.log('Configuring Rapid Reset scenario...');
  await httpPost(AGENT_PORT, '/configure', {
    config: { host: 'localhost', port: actualPort, protocol: 'h2', workers: 1, timeout: 5000, delay: 50, baseline: false },
    scenarios: ['h2-rapid-reset-cve-44487'],
  });

  console.log('Running...');
  await httpPost(AGENT_PORT, '/run', {});

  // Wait for result
  let done = false;
  while (!done) {
    const status = await httpGet(AGENT_PORT, '/status');
    if (status.status === 'done') done = true;
    await new Promise(r => setTimeout(r, 500));
  }

  console.log('Finished. Check rapid-reset.log');
  collector.destroy();
  server.stop();
  agent.close();
  process.exit(0);
}

run().catch(err => { console.error(err); process.exit(1); });
