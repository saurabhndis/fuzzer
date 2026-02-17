const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { FuzzerClient } = require('./lib/fuzzer-client');
const { FuzzerServer } = require('./lib/fuzzer-server');
const { Logger } = require('./lib/logger');
const { listScenarios, getScenario, getScenariosByCategory } = require('./lib/scenarios');
const { computeOverallGrade } = require('./lib/grader');
const { computeExpected } = require('./lib/compute-expected');

let mainWindow;
let activeClient = null;
let activeServer = null;

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
    title: 'TLS/TCP Protocol Fuzzer',
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
  return { categories, scenarios: stripped };
});

// Run fuzzer
ipcMain.handle('run-fuzzer', async (event, opts) => {
  const { mode, host, port, scenarioNames, delay, timeout, pcapFile, verbose } = opts;

  const send = (channel, data) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(channel, data);
    }
  };

  const logger = new Logger({ verbose });
  logger.onEvent((evt) => send('fuzzer-packet', evt));

  const scenarios = scenarioNames.map(n => getScenario(n)).filter(Boolean);
  if (scenarios.length === 0) {
    return { error: 'No valid scenarios selected' };
  }

  const results = [];

  if (mode === 'client') {
    if (typeof host !== 'string' || !/^[a-zA-Z0-9.\-]+$/.test(host)) {
      return { error: 'Invalid hostname' };
    }
    const portNum = parseInt(port, 10);
    if (!portNum || portNum < 1 || portNum > 65535) {
      return { error: 'Invalid port' };
    }

    activeClient = new FuzzerClient({
      host, port: portNum, timeout: timeout || 5000, delay: delay || 100,
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

  } else if (mode === 'server') {
    const portNum = parseInt(port, 10);
    if (!portNum || portNum < 1 || portNum > 65535) {
      return { error: 'Invalid port' };
    }

    activeServer = new FuzzerServer({
      port: portNum, timeout: timeout || 10000, delay: delay || 100,
      logger, pcapFile: pcapFile || null,
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
  }

  return { results };
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
