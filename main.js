const { app, BrowserWindow, ipcMain, dialog } = require('electron');
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
  };
});

// Run fuzzer
ipcMain.handle('run-fuzzer', async (event, opts) => {
  const { mode, host, port, scenarioNames, delay, timeout, pcapFile, verbose, hostname, protocol, dut, loopCount: rawLoop, localMode, baseline } = opts;
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

  // Resolve scenario objects from names (try TLS lookup, then HTTP/2, then QUIC)
  const lookup = (name) => {
    let s;
    if (protocol === 'raw-tcp') s = getTcpScenario(name);
    else if (protocol === 'quic') s = getQuicScenario(name);
    else if (protocol === 'h2') s = getHttp2Scenario(name);

    if (!s) {
      s = getScenario(name) || getHttp2Scenario(name) || getQuicScenario(name) || getTcpScenario(name);
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

    const report = computeOverallGrade(results);
    send('fuzzer-report', report);
    return { results };
  }

  // ── Server mode ───────────────────────────────────────────────────────────────
  if (mode === 'server') {
    const serverHostname = hostname || host || 'localhost';

    // Helper: spawn a well-behaved client for local mode server tests
    function spawnLocalClient(proto, delayMs) {
      if (!localMode) return null;
      const client = new WellBehavedClient({ host: 'localhost', port: portNum, logger });
      const promise = new Promise(resolve => {
        setTimeout(async () => {
          try {
            if (proto === 'quic') await client.connectQuic();
            else if (proto === 'h2') await client.connectH2();
            else await client.connectTLS();
          } catch (_) {}
          resolve(client);
        }, delayMs);
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
              const clientPromise = spawnLocalClient('h2', 300);
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
              const clientPromise = spawnLocalClient('quic', 300);
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
          send('fuzzer-progress', { scenario: scenario.name, total: totalTlsWithLoops, current: results.length + 1 });
          const clientPromise = spawnLocalClient('tls', 500);
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
