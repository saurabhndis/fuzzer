const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { fork } = require('child_process');
const net = require('net');
const path = require('path');
const https = require('https');
const url = require('url');
const xml2js = require('xml2js');
const { UnifiedClient } = require('./lib/unified-client');
const { UnifiedServer } = require('./lib/unified-server');
const { Logger } = require('./lib/logger');
const { listScenarios, getScenario, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { listHttp2Scenarios, getHttp2Scenario, HTTP2_CATEGORY_DEFAULT_DISABLED } = require('./lib/http2-scenarios');
const { listQuicScenarios, getQuicScenario, QUIC_CATEGORY_DEFAULT_DISABLED } = require('./lib/quic-scenarios');
const { listTcpScenarios, getTcpScenario, TCP_CATEGORIES, TCP_CATEGORY_SEVERITY } = require('./lib/tcp-scenarios');
const { listLdapScenarios, getLdapScenario, LDAP_CATEGORIES, LDAP_CATEGORY_SEVERITY, LDAP_CATEGORY_DEFAULT_DISABLED } = require('./lib/ldap/scenarios');
const { isRawAvailable } = require('./lib/raw-tcp');
const { computeOverallGrade } = require('./lib/grader');
const { computeExpected } = require('./lib/compute-expected');
const { Controller } = require('./lib/controller');
const { runBaseline } = require('./lib/baseline');
const { WellBehavedServer } = require('./lib/well-behaved-server');
const { WellBehavedClient } = require('./lib/well-behaved-client');

let mainWindow;
let firewallWindow = null;
let activeClient = null;
let activeServer = null;
let controller = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 950,
    minWidth: 900,
    minHeight: 700,
    backgroundColor: '#0d1117',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
    title: 'Protocol Fuzzer',
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.on('closed', () => {
    if (firewallWindow && !firewallWindow.isDestroyed()) {
      firewallWindow.close();
    }
    firewallWindow = null;
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// List scenarios (strip actions functions — not serializable over IPC)
ipcMain.handle('list-scenarios', () => {
  // TLS scenarios
  const { categories, scenarios } = listScenarios();
  const stripped = {};
  for (const [cat, items] of Object.entries(scenarios)) {
    stripped[cat] = items.map(s => {
      const computed = computeExpected(s);
      return {
        name: s.name,
        category: s.category,
        description: s.description,
        side: s.side,
        requiresRaw: !!s.requiresRaw,
        expected: s.expected || computed.expected,
        expectedReason: s.expectedReason || computed.reason,
      };
    });
  }

  // HTTP/2 scenarios
  const { categories: h2Categories, scenarios: h2Scenarios } = listHttp2Scenarios();
  const h2Stripped = {};
  for (const [cat, items] of Object.entries(h2Scenarios)) {
    h2Stripped[cat] = items.map(s => {
      const computed = computeExpected(s);
      return {
        name: s.name,
        category: s.category,
        description: s.description,
        side: s.side,
        requiresRaw: !!s.requiresRaw,
        expected: s.expected || computed.expected,
        expectedReason: s.expectedReason || computed.reason,
      };
    });
  }

  // QUIC scenarios
  const { categories: quicCategories, scenarios: quicScenarios } = listQuicScenarios();
  const quicStripped = {};
  for (const [cat, items] of Object.entries(quicScenarios)) {
    quicStripped[cat] = items.map(s => {
      const computed = computeExpected(s);
      return {
        name: s.name,
        category: s.category,
        description: s.description,
        side: s.side,
        requiresRaw: !!s.requiresRaw,
        expected: s.expected || computed.expected,
        expectedReason: s.expectedReason || computed.reason,
      };
    });
  }

  // Raw TCP scenarios
  const tcpGroups = listTcpScenarios();
  const tcpStripped = {};
  for (const [cat, group] of Object.entries(tcpGroups)) {
    tcpStripped[cat] = group.scenarios.map(s => {
      const computed = computeExpected(s);
      return {
        name: s.name,
        category: cat,
        description: s.description,
        side: s.side,
        requiresRaw: !!s.requiresRaw,
        expected: s.expected || computed.expected,
        expectedReason: s.expectedReason || computed.reason,
      };
    });
  }

  // LDAP scenarios
  const { categories: ldapCategories, scenarios: ldapScenarios } = listLdapScenarios();
  const ldapStripped = {};
  for (const [cat, items] of Object.entries(ldapScenarios)) {
    ldapStripped[cat] = items.map(s => {
      const computed = computeExpected(s);
      return {
        name: s.name,
        category: s.category,
        description: s.description,
        side: s.side,
        requiresRaw: !!s.requiresRaw,
        expected: s.expected || computed.expected,
        expectedReason: s.expectedReason || computed.reason,
      };
    });
  }

  return {
    categories,
    scenarios: stripped,
    defaultDisabled: [...CATEGORY_DEFAULT_DISABLED],
    h2Categories,
    h2Scenarios: h2Stripped,
    h2DefaultDisabled: [...HTTP2_CATEGORY_DEFAULT_DISABLED],
    quicCategories,
    quicScenarios: quicStripped,
    quicDefaultDisabled: [...QUIC_CATEGORY_DEFAULT_DISABLED],
    tcpCategories: TCP_CATEGORIES,
    tcpScenarios: tcpStripped,
    rawAvailable: isRawAvailable(),
    ldapCategories,
    ldapScenarios: ldapStripped,
    ldapDefaultDisabled: [...LDAP_CATEGORY_DEFAULT_DISABLED],
  };
});

// Run fuzzer
ipcMain.handle('run-fuzzer', async (event, opts) => {
  const { mode, host, port, scenarioNames, delay, timeout, pcapFile, verbose, hostname, protocol, dut, loopCount: rawLoop, localMode, baseline, workers } = opts;
  const loopCount = Math.max(1, Math.min(1000, parseInt(rawLoop, 10) || 1));

  const send = (channel, data) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(channel, data);
    }
  };

  const logger = new Logger({ verbose });
  let currentScenarioPackets = [];
  logger.onEvent((evt) => {
    if (['sent', 'received', 'tcp', 'fuzz'].includes(evt.type)) {
      currentScenarioPackets.push(evt);
    }
    send('fuzzer-packet', evt);
  });

  const portNum = parseInt(port, 10);
  if (!portNum || portNum < 1 || portNum > 65535) {
    return { error: 'Invalid port' };
  }

  const results = [];

  // Resolve scenario objects from names (try TLS lookup, then HTTP/2, then QUIC, then LDAP)
  const lookup = (name) => {
    let s;
    if (protocol === 'raw-tcp') s = getTcpScenario(name);
    else if (protocol === 'quic') s = getQuicScenario(name);
    else if (protocol === 'h2') s = getHttp2Scenario(name);
    else if (protocol === 'ldap') s = getLdapScenario(name);

    if (!s) {
      s = getScenario(name) || getHttp2Scenario(name) || getQuicScenario(name) || getTcpScenario(name) || getLdapScenario(name);
    }
    return s;
  };
  const scenarios = (scenarioNames || []).map(lookup).filter(Boolean);

  // ── Client mode ───────────────────────────────────────────────────────────────
  if (mode === 'client') {
    if (!localMode && (typeof host !== 'string' || !/^[a-zA-Z0-9.\-]+$/.test(host))) {
      return { error: 'Invalid hostname' };
    }
    if (scenarios.length === 0) {
      return { error: 'No valid scenarios selected' };
    }

    // Local mode: start a well-behaved server as the target
    let localServer = null;
    let clientHost = host;
    let clientPort = portNum;

    if (localMode) {
      localServer = new WellBehavedServer({ port: portNum, hostname: 'localhost', logger });
      try {
        if (protocol === 'raw-tcp') await localServer.startTCP();
        else if (protocol === 'quic') await localServer.startQuic();
        else if (protocol === 'h2') await localServer.startH2();
        else await localServer.startTLS();
      } catch (err) {
        return { error: `Failed to start local server: ${err.message}` };
      }
      clientHost = 'localhost';
      clientPort = localServer.actualPort;
      send('fuzzer-packet', {
        type: 'info',
        message: `Local ${(protocol || 'tls').toUpperCase()} server started on port ${clientPort}`,
      });
    }

    const totalWithLoops = scenarios.length * loopCount;

    if (workers > 1) {
      send('fuzzer-packet', { type: 'info', message: `Forking ${workers} worker processes for concurrent client fuzzing...` });
      try {
        const queue = [];
        for (let loop = 0; loop < loopCount; loop++) {
          for (const s of scenarios) queue.push(s);
        }

        const numWorkers = Math.min(workers, queue.length);
        let activeWorkers = 0;

        await new Promise((resolve) => {
          for (let i = 0; i < numWorkers; i++) {
            const worker = fork(path.join(__dirname, 'lib', 'ui-worker.js'));
            activeWorkers++;

            worker.on('message', (msg) => {
              if (msg.type === 'ready') {
                if (queue.length > 0) {
                  const s = queue.shift();
                  send('fuzzer-progress', { scenario: s.name, total: totalWithLoops, current: results.length + 1 });
                  worker.send({
                    cmd: 'run', scenarioName: s.name, protocol, baseline
                  });
                } else {
                  worker.send({ cmd: 'abort' });
                }
              } else if (msg.type === 'result') {
                results.push(msg.result);
                send('fuzzer-result', msg.result);
                if (msg.result.packets) {
                  msg.result.packets.forEach(p => send('fuzzer-packet', p));
                }
              } else if (msg.type === 'log') {
                send('fuzzer-packet', msg.data);
              }
            });

            worker.on('exit', () => {
              activeWorkers--;
              if (activeWorkers === 0) resolve();
            });

            worker.send({
              cmd: 'init-client', host: clientHost, port: clientPort, timeout, delay, verbose, pcapFile, dut
            });
          }
        });
      } finally {
        if (localServer) localServer.stop();
      }
    } else {
      activeClient = new UnifiedClient({
        host: clientHost, port: clientPort,
        timeout: timeout || 5000, delay: delay || 100,
        logger, pcapFile: pcapFile || null,
        dut,
      });

      const originalClientRun = activeClient.runScenario.bind(activeClient);
      activeClient.runScenario = async (scenario) => {
        currentScenarioPackets = [];
        if (baseline) {
          send('fuzzer-packet', { type: 'info', message: `[baseline] testing against local OpenSSL...` });
          const baselineRes = await runBaseline(scenario, protocol);
          scenario._baselineResponse = baselineRes.response;
          scenario._baselineCommand = baselineRes.command;
          const result = await originalClientRun(scenario);
          result.baselineResponse = baselineRes.response;
          result.baselineCommand = baselineRes.command;
          result.packets = [...currentScenarioPackets];
          return result;
        }
        const result = await originalClientRun(scenario);
        result.packets = [...currentScenarioPackets];
        return result;
      };

      try {
        for (let loop = 0; loop < loopCount; loop++) {
          if (activeClient.aborted) break;
          if (loopCount > 1) {
            send('fuzzer-packet', { type: 'info', message: `── Loop ${loop + 1} / ${loopCount} ──` });
          }
          for (const scenario of scenarios) {
            if (activeClient.aborted) break;
            send('fuzzer-progress', { scenario: scenario.name, total: totalWithLoops, current: results.length + 1 });

            const result = await activeClient.runScenario(scenario);

            results.push(result);
            send('fuzzer-result', result);
            await new Promise(r => setTimeout(r, 300));
          }
        }
      } finally {
        activeClient.close();
        activeClient = null;
        if (localServer) localServer.stop();
      }
    }

    const report = computeOverallGrade(results);
    send('fuzzer-report', report);
    return { results };
  }

  // ── Server mode ───────────────────────────────────────────────────────────────
  if (mode === 'server') {
    const serverHostname = hostname || host || 'localhost';

    // Helper: spawn a well-behaved client for local mode server tests.
    // Waits for the server's _onListening callback before connecting,
    // so the client only connects after the server is actually ready.
    function spawnLocalClient(proto) {
      if (!localMode) return null;
      const client = new WellBehavedClient({ host: '127.0.0.1', port: portNum, logger });
      let connected = false;
      const promise = new Promise(resolve => {
        const connect = async () => {
          if (connected) return;
          connected = true;
          clearTimeout(safetyTimer);
          activeServer._onListening = null;
          try {
            if (proto === 'quic') await client.connectQuic();
            else if (proto === 'h2') await client.connectH2();
            else if (proto === 'ldap') await client.connectLDAP();
            else await client.connectTLS();
          } catch (_) {}
          resolve(client);
        };
        activeServer._onListening = connect;
        // Safety: if server errors before listening, don't hang forever
        const safetyTimer = setTimeout(connect, 35000);
      });
      return promise;
    }

    activeServer = new UnifiedServer({
      port: portNum, hostname: serverHostname,
      timeout: timeout || 10000, delay: delay || 100,
      logger, pcapFile: pcapFile || null,
      dut,
    });

    const originalServerRun = activeServer.runScenario.bind(activeServer);
    activeServer.runScenario = async (scenario) => {
      currentScenarioPackets = [];
      if (baseline) {
        send('fuzzer-packet', { type: 'info', message: `[baseline] testing against local OpenSSL...` });
        const baselineRes = await runBaseline(scenario, protocol);
        scenario._baselineResponse = baselineRes.response;
        scenario._baselineCommand = baselineRes.command;
        const result = await originalServerRun(scenario);
        result.baselineResponse = baselineRes.response;
        result.baselineCommand = baselineRes.command;
        result.packets = [...currentScenarioPackets];
        return result;
      }
      const result = await originalServerRun(scenario);
      result.packets = [...currentScenarioPackets];
      return result;
    };

    const certInfo = activeServer.getCertInfo();

    if (workers > 1 && scenarios.length > 0) {
      send('fuzzer-packet', { type: 'info', message: `Forking ${workers} worker processes for concurrent server fuzzing...` });

      // Serialize certInfo — Buffers must be base64 encoded for IPC
      const certInfoForIPC = {
        ...certInfo,
        certDER: certInfo.certDER ? certInfo.certDER.toString('base64') : undefined,
        keyDER: certInfo.keyDER ? certInfo.keyDER.toString('base64') : undefined,
      };

      try {
        const queue = [];
        for (let loop = 0; loop < loopCount; loop++) {
          for (const s of scenarios) queue.push(s);
        }
        const totalServerWithLoops = queue.length;
        const numWorkers = Math.min(workers, queue.length);

        // Primary owns the listening socket — pauseOnConnect ensures no data
        // is consumed before the socket is transferred to a worker
        const tcpServer = net.createServer({ allowHalfOpen: true, pauseOnConnect: true });
        await new Promise((res, rej) => {
          tcpServer.listen(portNum, '::', res);
          tcpServer.once('error', rej);
        });
        send('fuzzer-packet', { type: 'info', message: `Listening on [::]:${portNum} — dispatching to ${numWorkers} workers` });

        // Workers assigned a scenario wait for a socket; incoming connections
        // are paired with waiting workers. This allows true parallelism when
        // multiple clients connect simultaneously.
        const waitingForSocket = [];  // { worker, scenarioName, timer }
        const pendingSockets = [];
        let activeWorkers = 0;
        let onAllResults = null;
        const SOCKET_WAIT_TIMEOUT = 90000; // 90s — must exceed scenario safety timeout

        // Prune dead/destroyed sockets from the pending queue
        const pruneDeadSockets = () => {
          for (let i = pendingSockets.length - 1; i >= 0; i--) {
            if (pendingSockets[i].destroyed) {
              pendingSockets.splice(i, 1);
            }
          }
        };

        const tryPairSocketToWorker = () => {
          pruneDeadSockets();
          while (waitingForSocket.length > 0 && pendingSockets.length > 0) {
            const entry = waitingForSocket.shift();
            clearTimeout(entry.timer);
            const sock = pendingSockets.shift();
            try {
              entry.worker.send({ cmd: 'run-on-socket', scenarioName: entry.scenarioName, protocol }, sock);
            } catch (e) {
              // Worker may have crashed — destroy socket and report error
              sock.destroy();
              results.push({ scenario: entry.scenarioName, status: 'ERROR', response: `Worker IPC failed: ${e.message}` });
              send('fuzzer-result', results[results.length - 1]);
            }
          }
        };

        tcpServer.on('connection', (sock) => {
          pendingSockets.push(sock);
          // Auto-destroy pending sockets that sit unmatched for too long
          const sockTimeout = setTimeout(() => {
            const idx = pendingSockets.indexOf(sock);
            if (idx !== -1) {
              pendingSockets.splice(idx, 1);
              if (!sock.destroyed) sock.destroy();
            }
          }, SOCKET_WAIT_TIMEOUT);
          sock.on('close', () => clearTimeout(sockTimeout));
          tryPairSocketToWorker();
        });

        await new Promise((resolve) => {
          for (let i = 0; i < numWorkers; i++) {
            const worker = fork(path.join(__dirname, 'lib', 'ui-worker.js'));
            activeWorkers++;

            worker.on('message', (msg) => {
              if (msg.type === 'ready') {
                // Worker ready — assign next scenario from queue
                if (queue.length > 0) {
                  const s = queue.shift();
                  send('fuzzer-progress', { scenario: s.name, total: totalServerWithLoops, current: results.length + 1 });

                  // Timeout: if no client connects within SOCKET_WAIT_TIMEOUT, emit TIMEOUT and recycle the worker
                  const entry = { worker, scenarioName: s.name, timer: null };
                  entry.timer = setTimeout(() => {
                    const idx = waitingForSocket.indexOf(entry);
                    if (idx !== -1) {
                      waitingForSocket.splice(idx, 1);
                      send('fuzzer-packet', { type: 'info', message: `Socket-wait timeout for "${s.name}" — no client connected within ${SOCKET_WAIT_TIMEOUT / 1000}s` });
                      results.push({ scenario: s.name, status: 'TIMEOUT', response: `No client connection within ${SOCKET_WAIT_TIMEOUT / 1000}s` });
                      send('fuzzer-result', results[results.length - 1]);
                      if (results.length >= totalServerWithLoops && onAllResults) onAllResults();
                      // Re-feed the worker so it picks up the next scenario
                      else if (queue.length > 0) {
                        worker.send({ cmd: 'noop' }); // triggers ready cycle
                      } else {
                        // No more work — abort the idle worker so it exits
                        worker.send({ cmd: 'abort' });
                      }
                    }
                  }, SOCKET_WAIT_TIMEOUT);
                  waitingForSocket.push(entry);
                  tryPairSocketToWorker();

                  // In local mode, spawn a well-behaved client to connect
                  if (localMode) {
                    const client = new WellBehavedClient({ host: '127.0.0.1', port: portNum, logger });
                    const connectFn = protocol === 'quic' ? 'connectQuic'
                      : protocol === 'h2' ? 'connectH2'
                      : protocol === 'ldap' ? 'connectLDAP' : 'connectTLS';
                    client[connectFn]().catch(() => {}).then(() => client.stop());
                  }
                } else {
                  worker.send({ cmd: 'abort' });
                }
              } else if (msg.type === 'result') {
                results.push(msg.result);
                send('fuzzer-result', msg.result);
                if (msg.result.packets) {
                  msg.result.packets.forEach(p => send('fuzzer-packet', p));
                }
                // Check if all results are in
                if (results.length >= totalServerWithLoops && onAllResults) onAllResults();
              } else if (msg.type === 'log') {
                send('fuzzer-packet', msg.data);
              }
            });

            worker.on('exit', () => {
              activeWorkers--;
              // Safety: if all workers exit before all results, resolve anyway
              if (activeWorkers === 0 && onAllResults) onAllResults();
            });

            worker.send({
              cmd: 'init-server', hostname: serverHostname, port: portNum, timeout, delay, verbose, pcapFile, dut, certInfo: certInfoForIPC
            });
          }

          onAllResults = resolve;
        });

        // Clean up: cancel any pending socket-wait timers and destroy unmatched sockets
        for (const entry of waitingForSocket) clearTimeout(entry.timer);
        waitingForSocket.length = 0;
        for (const sock of pendingSockets) { if (!sock.destroyed) sock.destroy(); }
        pendingSockets.length = 0;

        tcpServer.close();
      } finally {
        if (activeServer) activeServer.close();
        activeServer = null;
      }
      const report = computeOverallGrade(results);
      send('fuzzer-report', report);
      return { results };
    }

    if (protocol === 'h2') {
      // Start the HTTP/2 server
      send('fuzzer-packet', {
        type: 'info',
        message: `HTTP/2 server starting on port ${portNum} | CN=${certInfo.hostname} | SHA256=${certInfo.h2Fingerprint.slice(0, 16)}...`,
      });

      try {
        await activeServer.startH2();
      } catch (err) {
        if (activeServer) activeServer.close();
        activeServer = null;
        return { error: `Failed to start HTTP/2 server: ${err.message}` };
      }

      if (scenarios.length > 0) {
        const totalH2WithLoops = scenarios.length * loopCount;
        // Run server-side scenarios (AJ) — each waits for a client to connect
        send('fuzzer-packet', {
          type: 'info',
          message: localMode
            ? `HTTP/2 server running server-side scenarios with local client on port ${portNum}`
            : `HTTP/2 server running server-side scenarios — connect an HTTP/2 client to port ${portNum}`,
        });

        try {
          for (let loop = 0; loop < loopCount; loop++) {
            if (activeServer.aborted) break;
            if (loopCount > 1) {
              send('fuzzer-packet', { type: 'info', message: `── Loop ${loop + 1} / ${loopCount} ──` });
            }
            for (const scenario of scenarios) {
              if (activeServer.aborted) break;
              send('fuzzer-progress', { scenario: scenario.name, total: totalH2WithLoops, current: results.length + 1 });
              const clientPromise = spawnLocalClient('h2');
              const result = await activeServer.runScenario(scenario);
              if (clientPromise) { const c = await clientPromise; c.stop(); }
              results.push(result);
              send('fuzzer-result', result);
              await new Promise(r => setTimeout(r, 500));
            }
          }
        } finally {
          if (activeServer) activeServer.close();
          activeServer = null;
        }
        const report = computeOverallGrade(results);
        send('fuzzer-report', report);
        return { results };
      }

      // Passive mode: just listen until stopped
      send('fuzzer-packet', {
        type: 'info',
        message: `HTTP/2 server is running — connect a fuzzing client to port ${portNum} (TLS+ALPN h2)`,
      });

      await activeServer.waitForStop();
      if (activeServer) activeServer.close();
      activeServer = null;

      const report = computeOverallGrade([]);
      send('fuzzer-report', report);
      return { results: [] };
    }

    if (protocol === 'ldap') {
      // Start the LDAP fuzzer server
      send('fuzzer-packet', {
        type: 'info',
        message: `LDAP fuzzer server starting on port ${portNum}`,
      });

      if (scenarios.length > 0) {
        const totalLdapWithLoops = scenarios.length * loopCount;
        send('fuzzer-packet', {
          type: 'info',
          message: localMode
            ? `LDAP server running server-side scenarios with local client on port ${portNum}`
            : `LDAP server running server-side scenarios — connect an LDAP client to port ${portNum}`,
        });

        try {
          for (let loop = 0; loop < loopCount; loop++) {
            if (activeServer.aborted) break;
            if (loopCount > 1) {
              send('fuzzer-packet', { type: 'info', message: `── Loop ${loop + 1} / ${loopCount} ──` });
            }
            for (const scenario of scenarios) {
              if (activeServer.aborted) break;
              send('fuzzer-progress', { scenario: scenario.name, total: totalLdapWithLoops, current: results.length + 1 });
              const clientPromise = spawnLocalClient('ldap');
              const result = await activeServer.runScenario(scenario);
              if (clientPromise) { const c = await clientPromise; c.stop(); }
              results.push(result);
              send('fuzzer-result', result);
              await new Promise(r => setTimeout(r, 500));
            }
          }
        } finally {
          if (activeServer) activeServer.close();
          activeServer = null;
        }
        const report = computeOverallGrade(results);
        send('fuzzer-report', report);
        return { results };
      }

      // Passive mode: listen until stopped
      send('fuzzer-packet', {
        type: 'info',
        message: `LDAP fuzzer server is running — connect an LDAP client to port ${portNum}`,
      });

      await activeServer.waitForStop();
      if (activeServer) activeServer.close();
      activeServer = null;

      const report = computeOverallGrade([]);
      send('fuzzer-report', report);
      return { results: [] };
    }

    if (protocol === 'quic') {
      // Start the QUIC server
      send('fuzzer-packet', {
        type: 'info',
        message: `QUIC server starting on UDP port ${portNum} | hostname=${certInfo.hostname}`,
      });

      try {
        await activeServer.startQuic();
      } catch (err) {
        if (activeServer) activeServer.close();
        activeServer = null;
        return { error: `Failed to start QUIC server: ${err.message}` };
      }

      if (scenarios.length > 0) {
        const totalQuicWithLoops = scenarios.length * loopCount;
        send('fuzzer-packet', {
          type: 'info',
          message: localMode
            ? `QUIC server running server-side scenarios with local client on UDP port ${portNum}`
            : `QUIC server running server-side scenarios — connect a QUIC client to UDP port ${portNum}`,
        });

        try {
          for (let loop = 0; loop < loopCount; loop++) {
            if (activeServer.aborted) break;
            if (loopCount > 1) {
              send('fuzzer-packet', { type: 'info', message: `── Loop ${loop + 1} / ${loopCount} ──` });
            }
            for (const scenario of scenarios) {
              if (activeServer.aborted) break;
              send('fuzzer-progress', { scenario: scenario.name, total: totalQuicWithLoops, current: results.length + 1 });
              const clientPromise = spawnLocalClient('quic');
              const result = await activeServer.runScenario(scenario);
              if (clientPromise) { const c = await clientPromise; c.stop(); }
              results.push(result);
              send('fuzzer-result', result);
              await new Promise(r => setTimeout(r, 500));
            }
          }
        } finally {
          if (activeServer) activeServer.close();
          activeServer = null;
        }
        const report = computeOverallGrade(results);
        send('fuzzer-report', report);
        return { results };
      }

      // Passive mode: listen until stopped
      send('fuzzer-packet', {
        type: 'info',
        message: `QUIC server is running — connect a QUIC client to UDP port ${portNum}`,
      });

      await activeServer.waitForStop();
      if (activeServer) activeServer.close();
      activeServer = null;

      const report = computeOverallGrade([]);
      send('fuzzer-report', report);
      return { results: [] };
    }

    // TLS server mode
    if (scenarios.length === 0) {
      return { error: 'No valid scenarios selected' };
    }

    send('fuzzer-packet', {
      type: 'info',
      message: `Server certificate: CN=${serverHostname} | SHA256=${certInfo.fingerprint}`,
    });

    const totalTlsWithLoops = scenarios.length * loopCount;

    try {
      for (let loop = 0; loop < loopCount; loop++) {
        if (activeServer.aborted) break;
        if (loopCount > 1) {
          send('fuzzer-packet', { type: 'info', message: `── Loop ${loop + 1} / ${loopCount} ──` });
        }
        for (const scenario of scenarios) {
          if (activeServer.aborted) break;
          const idx = results.length + 1;
          send('fuzzer-progress', { scenario: scenario.name, total: totalTlsWithLoops, current: idx });
          // Periodic resource diagnostics to detect leaks approaching hang threshold
          if (idx % 200 === 0) {
            try {
              const fs = require('fs');
              const fdCount = fs.readdirSync('/dev/fd').length;
              send('fuzzer-packet', { type: 'info', message: `[diag] Test #${idx}: open FDs=${fdCount}, activeSockets=${activeServer.activeSockets.size}, heapMB=${Math.round(process.memoryUsage().heapUsed / 1048576)}` });
            } catch (_) {
              send('fuzzer-packet', { type: 'info', message: `[diag] Test #${idx}: activeSockets=${activeServer.activeSockets.size}, heapMB=${Math.round(process.memoryUsage().heapUsed / 1048576)}` });
            }
          }
          // Clean up between scenarios to prevent resource accumulation
          if (activeServer._cleanupBetweenScenarios) activeServer._cleanupBetweenScenarios();
          const clientPromise = spawnLocalClient('tls');
          const result = await activeServer.runScenario(scenario);
          if (clientPromise) { const c = await clientPromise; c.stop(); }
          results.push(result);
          send('fuzzer-result', result);
          await new Promise(r => setTimeout(r, 300));
        }
      }
    } finally {
      if (activeServer) activeServer.close();
      activeServer = null;
    }

    const report = computeOverallGrade(results);
    send('fuzzer-report', report);
    return { results };
  }

  return { error: 'Unknown mode' };
});

// Stop fuzzer
ipcMain.handle('stop-fuzzer', () => {
  if (activeClient) activeClient.abort();
  if (activeServer) activeServer.abort();
  return { stopped: true };
});

// File save dialog for PCAP
ipcMain.handle('save-pcap-dialog', async () => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Save PCAP File',
    defaultPath: `fuzz-${Date.now()}.pcap`,
    filters: [{ name: 'PCAP Files', extensions: ['pcap'] }],
  });
  return result.canceled ? null : result.filePath;
});

// Save Log to specific file path
ipcMain.handle('save-log-to-file', async (event, filePath, content) => {
  try {
    require('fs').appendFileSync(filePath, content);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// --- Distributed Mode IPC Handlers ---

const send = (channel, data) => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
};

// Connect to remote agents
ipcMain.handle('distributed-connect', async (_event, opts) => {
  const { clientHost, clientPort, clientToken, serverHost, serverPort, serverToken } = opts;

  // Clean up previous controller if any
  if (controller) {
    controller.disconnect();
  }
  controller = new Controller();

  const result = {};
  const promises = [];

  if (clientHost && clientPort) {
    promises.push(
      controller.connect('client', clientHost, parseInt(clientPort), clientToken)
        .then(status => { result.client = status; })
        .catch(err => { result.clientError = err.message; })
    );
  }
  if (serverHost && serverPort) {
    promises.push(
      controller.connect('server', serverHost, parseInt(serverPort), serverToken)
        .then(status => { result.server = status; })
        .catch(err => { result.serverError = err.message; })
    );
  }

  await Promise.all(promises);
  return result;
});

// Configure remote agents with scenarios
ipcMain.handle('distributed-configure', async (_event, opts) => {
  if (!controller) return { error: 'Not connected' };
  const { clientScenarios, serverScenarios, clientConfig, serverConfig } = opts;
  try {
    const configured = await controller.configureAll(clientScenarios, serverScenarios, clientConfig, serverConfig);
    if (!configured.client && !configured.server) {
      return { error: 'No agents were configured — check connections' };
    }
    return { ok: true, configured };
  } catch (err) {
    return { error: err.message };
  }
});

// Start distributed execution — subscribe to events and trigger both agents
ipcMain.handle('distributed-run', async () => {
  if (!controller) return { error: 'Not connected' };

  // Subscribe to all events from both agents and relay via IPC
  controller.onEvent((role, event) => {
    switch (event.type) {
      case 'logger':
        send('fuzzer-packet', { ...event.event, agentRole: role });
        break;
      case 'progress':
        send('fuzzer-progress', { ...event, agentRole: role });
        break;
      case 'result':
        send('fuzzer-result', { ...event.result, agentRole: role });
        break;
      case 'report':
        send('fuzzer-report', { ...event.report, agentRole: role });
        break;
      case 'done':
        send('distributed-agent-done', { role });
        break;
      case 'status':
        send('distributed-agent-status', { role, ...event });
        break;
      case 'error':
        send('fuzzer-packet', { type: 'error', message: event.message, agentRole: role });
        break;
    }
  });

  try {
    await controller.runAll();
    return { ok: true };
  } catch (err) {
    return { error: err.message };
  }
});

// Stop distributed execution
ipcMain.handle('distributed-stop', async () => {
  if (!controller) return { error: 'Not connected' };
  try {
    await controller.stopAll();
    return { ok: true };
  } catch (err) {
    return { error: err.message };
  }
});

// Get agent status
ipcMain.handle('distributed-status', async (_event, role) => {
  if (!controller) return null;
  try {
    return await controller.getStatus(role);
  } catch (err) {
    return { error: err.message };
  }
});

// Get agent results
ipcMain.handle('distributed-results', async (_event, role) => {
  if (!controller) return null;
  try {
    return await controller.getResults(role);
  } catch (err) {
    return { error: err.message };
  }
});

// Disconnect from all agents
ipcMain.handle('distributed-disconnect', () => {
  if (controller) {
    controller.disconnect();
    controller = null;
  }
  return { ok: true };
});

// ═══════════════════════════════════════════════════════════════════════════════
// Firewall (PAN-OS) Monitor — embedded from firewall project
// ═══════════════════════════════════════════════════════════════════════════════

// Disable certificate validation for self-signed firewall certs
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

function createFirewallWindow(dutConfig) {
  if (firewallWindow && !firewallWindow.isDestroyed()) {
    firewallWindow.focus();
    return;
  }

  firewallWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
    backgroundColor: '#0f1117',
    title: 'DUT Firewall Monitor',
    show: false,
  });

  firewallWindow.loadFile(path.join(__dirname, 'renderer', 'firewall.html'));

  firewallWindow.once('ready-to-show', () => {
    firewallWindow.show();
    // Send DUT config so the firewall UI can auto-connect
    if (dutConfig && dutConfig.ip) {
      firewallWindow.webContents.send('dut-config', dutConfig);
    }
  });

  firewallWindow.on('closed', () => {
    firewallWindow = null;
  });
}

// Open/close firewall window from renderer
ipcMain.handle('open-firewall', (_event, dutConfig) => {
  createFirewallWindow(dutConfig);
  return { ok: true };
});

ipcMain.handle('close-firewall', () => {
  if (firewallWindow && !firewallWindow.isDestroyed()) {
    firewallWindow.close();
    firewallWindow = null;
  }
  return { ok: true };
});

// --- PAN-OS Utility: make an HTTPS request to the firewall ---
function panosRequest(host, params) {
  return new Promise((resolve, reject) => {
    // SSRF Protection: strict hostname/IP validation
    if (!host || typeof host !== 'string' || !/^[a-zA-Z0-9.\-:\[\]]+$/.test(host)) {
      return reject(new Error('Invalid firewall hostname or IP address'));
    }

    let hostname = host;
    let port = 443;

    // Support host:port format
    if (host.includes(':') && !host.startsWith('[')) {
      const parts = host.split(':');
      hostname = parts[0];
      port = parseInt(parts[1], 10) || 443;
    } else if (host.startsWith('[') && host.includes(']:')) {
      // IPv6 with port [::1]:443
      const parts = host.split(']:');
      hostname = parts[0].slice(1);
      port = parseInt(parts[1], 10) || 443;
    }

    const postBody = new url.URLSearchParams(params).toString();
    const options = {
      hostname,
      port,
      path: '/api/',
      method: 'POST',
      timeout: 15000,
      rejectUnauthorized: false,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postBody),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out (15s). Check the IP and that the firewall is reachable.'));
    });

    req.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        reject(new Error(`Connection refused to ${host}:443. Verify the IP address and that HTTPS management is enabled.`));
      } else if (err.code === 'ENOTFOUND') {
        reject(new Error(`Host not found: ${host}. Check the IP address.`));
      } else {
        reject(new Error(`Network error: ${err.message}`));
      }
    });

    req.write(postBody);
    req.end();
  });
}

// --- Parse PAN-OS XML response ---
function parseXmlResponse(xmlString) {
  const statusMatch = xmlString.match(/status\s*=\s*['"]([^'"]+)['"]/);
  const status = statusMatch ? statusMatch[1] : 'unknown';

  if (status === 'error') {
    const msgMatch = xmlString.match(/<msg>([^<]+)<\/msg>/) ||
                     xmlString.match(/<line>([^<]+)<\/line>/);
    const msg = msgMatch ? msgMatch[1] : 'Unknown error from firewall';
    throw new Error(`Firewall error: ${msg}`);
  }

  return { status, raw: xmlString };
}

// --- Extract API key from keygen response ---
function extractApiKey(xmlString) {
  const { status } = parseXmlResponse(xmlString);
  if (status !== 'success') {
    throw new Error('Authentication failed. Check your username and password.');
  }
  const keyMatch = xmlString.match(/<key>([^<]+)<\/key>/);
  if (!keyMatch) throw new Error('Could not extract API key from response.');
  return keyMatch[1];
}

// --- Pretty-print XML for display ---
function formatXml(xmlString) {
  try {
    let indent = 0;
    const lines = [];
    let cleaned = xmlString
      .replace(/<\?xml[^>]*\?>/g, '')
      .replace(/>\s*</g, '>\n<')
      .trim();

    cleaned.split('\n').forEach((line) => {
      line = line.trim();
      if (!line) return;

      if (line.match(/^<\/[^>]+>$/)) {
        indent = Math.max(0, indent - 1);
      }

      lines.push('  '.repeat(indent) + line);

      if (line.match(/^<[^/!][^>]*[^/]>$/) && !line.match(/<[^>]+>[^<]+<\/[^>]+>/)) {
        indent++;
      }
    });

    return lines.join('\n');
  } catch {
    return xmlString;
  }
}

// --- Parse XML to JSON for structured rendering ---
async function parseXmlToJson(xmlString) {
  try {
    return await xml2js.parseStringPromise(xmlString, {
      explicitArray: false,
      trim: true,
      mergeAttrs: true,
    });
  } catch {
    return null;
  }
}

// --- PAN-OS IPC Handlers ---

ipcMain.handle('panos:ping', async (_event, { host }) => {
  const { spawn } = require('child_process');
  return new Promise((resolve) => {
    // Basic hostname/IP validation
    if (!host || typeof host !== 'string' || !/^[a-zA-Z0-9.\-:]+$/.test(host)) {
      return resolve({ reachable: false, output: 'Invalid hostname or IP address' });
    }

    const isWin = process.platform === 'win32';
    const flag = isWin ? '-n' : '-c';
    const args = [flag, '2', host];
    
    // Add timeout flag for non-windows (ping -W)
    if (!isWin) {
      args.splice(2, 0, '-W', '2');
    }

    const child = spawn('ping', args);
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => { stdout += data; });
    child.stderr.on('data', (data) => { stderr += data; });

    const timer = setTimeout(() => {
      child.kill();
      resolve({ reachable: false, output: 'Ping timed out' });
    }, 10000);

    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve({ reachable: true, output: stdout });
      } else {
        resolve({ reachable: false, output: stdout || stderr || `Ping failed with code ${code}` });
      }
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ reachable: false, output: `Failed to start ping: ${err.message}` });
    });
  });
});

ipcMain.handle('panos:getApiKey', async (_event, { host, username, password }) => {
  if (!host || typeof host !== 'string' || !/^[a-zA-Z0-9.\-:]+$/.test(host)) {
    throw new Error('Invalid firewall hostname or IP address');
  }
  if (!username || !password) {
    throw new Error('Host, username, and password are required.');
  }

  const xml = await panosRequest(host, {
    type: 'keygen',
    user: username,
    password: password,
  });

  const apiKey = extractApiKey(xml);
  return { apiKey };
});

ipcMain.handle('panos:runCommand', async (_event, { host, apiKey, command }) => {
  if (!host || typeof host !== 'string' || !/^[a-zA-Z0-9.\-:]+$/.test(host)) {
    throw new Error('Invalid firewall hostname or IP address');
  }
  if (!host || !apiKey || !command) {
    throw new Error('Host, API key, and command are required.');
  }

  const xml = await panosRequest(host, {
    type: 'op',
    cmd: command,
    key: apiKey,
  });

  parseXmlResponse(xml);
  const parsed = await parseXmlToJson(xml);

  return {
    raw: xml,
    formatted: formatXml(xml),
    parsed,
  };
});

ipcMain.handle('panos:runConfig', async (_event, { host, apiKey, action, xpath }) => {
  if (!host || typeof host !== 'string' || !/^[a-zA-Z0-9.\-:]+$/.test(host)) {
    throw new Error('Invalid firewall hostname or IP address');
  }
  if (!host || !apiKey) {
    throw new Error('Host and API key are required.');
  }

  const xml = await panosRequest(host, {
    type: 'config',
    action: action || 'show',
    xpath: xpath || '/',
    key: apiKey,
  });

  parseXmlResponse(xml);
  const parsed = await parseXmlToJson(xml);

  return {
    raw: xml,
    formatted: formatXml(xml),
    parsed,
  };
});

ipcMain.handle('panos:systemInfo', async (_event, { host, apiKey }) => {
  if (!host || typeof host !== 'string' || !/^[a-zA-Z0-9.\-:]+$/.test(host)) {
    throw new Error('Invalid firewall hostname or IP address');
  }
  const xml = await panosRequest(host, {
    type: 'op',
    cmd: '<show><system><info></info></system></show>',
    key: apiKey,
  });

  parseXmlResponse(xml);

  const extract = (tag) => {
    const m = xml.match(new RegExp(`<${tag}>([^<]+)</${tag}>`));
    return m ? m[1] : 'N/A';
  };

  const parsed = await parseXmlToJson(xml);

  return {
    hostname: extract('hostname'),
    model: extract('model'),
    serial: extract('serial'),
    swVersion: extract('sw-version'),
    appVersion: extract('app-version'),
    uptime: extract('uptime'),
    ipAddress: extract('ip-address'),
    raw: xml,
    formatted: formatXml(xml),
    parsed,
  };
});
