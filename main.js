const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { UnifiedClient } = require('./lib/unified-client');
const { UnifiedServer } = require('./lib/unified-server');
const { Logger } = require('./lib/logger');
const { listScenarios, getScenario, CATEGORY_DEFAULT_DISABLED } = require('./lib/scenarios');
const { listHttp2Scenarios, getHttp2Scenario, HTTP2_CATEGORY_DEFAULT_DISABLED } = require('./lib/http2-scenarios');
const { computeOverallGrade } = require('./lib/grader');
const { computeExpected } = require('./lib/compute-expected');
const { Controller } = require('./lib/controller');

let mainWindow;
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
  };
});

// Run fuzzer
ipcMain.handle('run-fuzzer', async (event, opts) => {
  const { mode, host, port, scenarioNames, delay, timeout, pcapFile, verbose, hostname, protocol } = opts;

  const send = (channel, data) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(channel, data);
    }
  };

  const logger = new Logger({ verbose });
  logger.onEvent((evt) => send('fuzzer-packet', evt));

  const portNum = parseInt(port, 10);
  if (!portNum || portNum < 1 || portNum > 65535) {
    return { error: 'Invalid port' };
  }

  const results = [];

  // Resolve scenario objects from names (try TLS lookup, then HTTP/2 lookup)
  const lookup = (name) => (protocol === 'h2' ? getHttp2Scenario(name) : getScenario(name))
    || getHttp2Scenario(name) || getScenario(name);
  const scenarios = (scenarioNames || []).map(lookup).filter(Boolean);

  // ── Client mode ───────────────────────────────────────────────────────────────
  if (mode === 'client') {
    if (typeof host !== 'string' || !/^[a-zA-Z0-9.\-]+$/.test(host)) {
      return { error: 'Invalid hostname' };
    }
    if (scenarios.length === 0) {
      return { error: 'No valid scenarios selected' };
    }

    activeClient = new UnifiedClient({
      host, port: portNum,
      timeout: timeout || 5000, delay: delay || 100,
      logger, pcapFile: pcapFile || null,
    });

    for (const scenario of scenarios) {
      if (activeClient.aborted) break;
      send('fuzzer-progress', { scenario: scenario.name, total: scenarios.length, current: results.length + 1 });
      const result = await activeClient.runScenario(scenario);
      results.push(result);
      send('fuzzer-result', result);
      await new Promise(r => setTimeout(r, 300));
    }

    activeClient.close();
    activeClient = null;

    const report = computeOverallGrade(results);
    send('fuzzer-report', report);
    return { results };
  }

  // ── Server mode ───────────────────────────────────────────────────────────────
  if (mode === 'server') {
    const serverHostname = hostname || host || 'localhost';

    activeServer = new UnifiedServer({
      port: portNum, hostname: serverHostname,
      timeout: timeout || 10000, delay: delay || 100,
      logger, pcapFile: pcapFile || null,
    });

    const certInfo = activeServer.getCertInfo();

    if (protocol === 'h2') {
      // Start the HTTP/2 server
      send('fuzzer-packet', {
        type: 'info',
        message: `HTTP/2 server starting on port ${portNum} | CN=${certInfo.hostname} | SHA256=${certInfo.h2Fingerprint.slice(0, 16)}...`,
      });

      try {
        await activeServer.startH2();
      } catch (err) {
        activeServer = null;
        return { error: `Failed to start HTTP/2 server: ${err.message}` };
      }

      if (scenarios.length > 0) {
        // Run server-side scenarios (AJ) — each waits for a client to connect
        send('fuzzer-packet', {
          type: 'info',
          message: `HTTP/2 server running server-side scenarios — connect an HTTP/2 client to port ${portNum}`,
        });

        for (const scenario of scenarios) {
          if (activeServer.aborted) break;
          send('fuzzer-progress', { scenario: scenario.name, total: scenarios.length, current: results.length + 1 });
          const result = await activeServer.runScenario(scenario);
          results.push(result);
          send('fuzzer-result', result);
          await new Promise(r => setTimeout(r, 500));
        }

        activeServer = null;
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

    for (const scenario of scenarios) {
      if (activeServer.aborted) break;
      send('fuzzer-progress', { scenario: scenario.name, total: scenarios.length, current: results.length + 1 });
      const result = await activeServer.runScenario(scenario);
      results.push(result);
      send('fuzzer-result', result);
      await new Promise(r => setTimeout(r, 300));
    }

    activeServer = null;

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

// --- Distributed Mode IPC Handlers ---

const send = (channel, data) => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
};

// Connect to remote agents
ipcMain.handle('distributed-connect', async (_event, opts) => {
  const { clientHost, clientPort, serverHost, serverPort } = opts;
  controller = new Controller();

  const result = {};
  if (clientHost && clientPort) {
    try {
      result.client = await controller.connect('client', clientHost, parseInt(clientPort));
    } catch (err) {
      result.clientError = err.message;
    }
  }
  if (serverHost && serverPort) {
    try {
      result.server = await controller.connect('server', serverHost, parseInt(serverPort));
    } catch (err) {
      result.serverError = err.message;
    }
  }
  return result;
});

// Configure remote agents with scenarios
ipcMain.handle('distributed-configure', async (_event, opts) => {
  if (!controller) return { error: 'Not connected' };
  const { clientScenarios, serverScenarios, clientConfig, serverConfig } = opts;
  try {
    await controller.configureAll(clientScenarios, serverScenarios, clientConfig, serverConfig);
    return { ok: true };
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
        send('distributed-agent-status', { role, status: event.status });
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
