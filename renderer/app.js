// WireStrike — Protocol Security Testing Suite — Renderer
(function () {
  'use strict';

  // Inlined from lib/app-protocol-scenarios.js — renderer runs with
  // nodeIntegration:false, so require() is not available here.
  function getDistributedAppServerHelper(clientScenarioName) {
    if (!clientScenarioName) return null;
    if (clientScenarioName.startsWith('smtp-implicit-tls-')) return 'smtp-implicit-tls-well-behaved-server';
    if (clientScenarioName.startsWith('smtp-starttls-')) return 'smtp-starttls-well-behaved-server';
    if (clientScenarioName.startsWith('ftp-implicit-tls-')) return 'ftp-implicit-tls-well-behaved-server';
    if (clientScenarioName.startsWith('ftp-starttls-')) return 'ftp-starttls-well-behaved-server';
    if (clientScenarioName.startsWith('ldap-implicit-tls-')) return 'ldap-implicit-tls-well-behaved-server';
    if (clientScenarioName.startsWith('ldap-starttls-')) return 'ldap-starttls-well-behaved-server';
    return null;
  }

  function getDistributedAppClientHelper(serverScenarioName) {
    if (!serverScenarioName) return null;
    if (serverScenarioName === 'smtp-implicit-tls-well-behaved-server') return 'smtp-implicit-tls-well-behaved';
    if (serverScenarioName === 'smtp-starttls-well-behaved-server') return 'smtp-starttls-well-behaved';
    if (serverScenarioName === 'ftp-implicit-tls-well-behaved-server') return 'ftp-implicit-tls-well-behaved';
    if (serverScenarioName === 'ftp-starttls-well-behaved-server') return 'ftp-starttls-well-behaved';
    if (serverScenarioName === 'ldap-implicit-tls-well-behaved-server') return 'ldap-implicit-tls-well-behaved';
    if (serverScenarioName === 'ldap-starttls-well-behaved-server') return 'ldap-starttls-well-behaved';
    return null;
  }

  // DOM elements
  const modeSelect = document.getElementById('modeSelect');
  const hostGroup = document.getElementById('hostGroup');
  const hostInput = document.getElementById('hostInput');
  const portInput = document.getElementById('portInput');
  const delayInput = document.getElementById('delayInput');
  const timeoutInput = document.getElementById('timeoutInput');
  const verboseCheck = document.getElementById('verboseCheck');
  const scenariosList = document.getElementById('scenariosList');
  const runBtn = document.getElementById('runBtn');
  const rerunFailedBtn = document.getElementById('rerunFailedBtn');
  const stopBtn = document.getElementById('stopBtn');
  const loopCountInput = document.getElementById('loopCountInput');
  const pcapBtn = document.getElementById('pcapBtn');
  const pcapPathEl = document.getElementById('pcapPath');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  const resultsTable = document.getElementById('resultsTable');
  const resultsBody = document.getElementById('resultsBody');
  const resultsEmpty = document.getElementById('resultsEmpty');
  const exportJsonBtn = document.getElementById('exportJsonBtn');
  const logToFileBtn = document.getElementById('logToFileBtn');
  const logPathInput = document.getElementById('logPathInput');
  const clearResultsBtn = document.getElementById('clearResultsBtn');
  const packetLog = document.getElementById('packetLog');
  const clearLogBtn = document.getElementById('clearLogBtn');
  const summaryBar = document.getElementById('summaryBar');
  const summaryText = document.getElementById('summaryText');
  const statusBadge = document.getElementById('statusBadge');
  const elapsedClock = document.getElementById('elapsedClock');
  const localModeCheck = document.getElementById('localModeCheck');
  const baselineCheck = document.getElementById('baselineCheck');
  const distributedCheck = document.getElementById('distributedCheck');
  const distributedBar = document.getElementById('distributedBar');
  const clientAgentIp = document.getElementById('clientAgentIp');
  const serverAgentIp = document.getElementById('serverAgentIp');
  const clientStatusDot = document.getElementById('clientStatusDot');
  const clientStatusText = document.getElementById('clientStatusText');
  const serverStatusDot = document.getElementById('serverStatusDot');
  const serverStatusText = document.getElementById('serverStatusText');
  const connectBtn = document.getElementById('connectBtn');
  const disconnectBtn = document.getElementById('disconnectBtn');

  // DUT elements
  const dutCheck = document.getElementById('dutCheck');
  const dutBar = document.getElementById('dutBar');
  const dutIpInput = document.getElementById('dutIpInput');
  const dutAuthType = document.getElementById('dutAuthType');
  const dutUserPassGroup = document.getElementById('dutUserPassGroup');
  const dutApiKeyGroup = document.getElementById('dutApiKeyGroup');
  const dutUserInput = document.getElementById('dutUserInput');
  const dutPassInput = document.getElementById('dutPassInput');
  const dutApiKeyInput = document.getElementById('dutApiKeyInput');
  const firewallBtn = document.getElementById('firewallBtn');

  // Protocol tab elements
  const tlsTabBtn = document.getElementById('tlsTabBtn');
  const http2TabBtn = document.getElementById('http2TabBtn');
  const quicTabBtn = document.getElementById('quicTabBtn');
  const tcpTabBtn = document.getElementById('tcpTabBtn');

  // Select menu elements
  const selectMenuBtn = document.getElementById('selectMenuBtn');
  const selectMenu = document.getElementById('selectMenu');

  // PCAP Ingestion elements
  const ingestPcapBtn = document.getElementById('ingestPcapBtn');
  const pcapAnalysisOverlay = document.getElementById('pcapAnalysisOverlay');
  const pcapScenarioName = document.getElementById('pcapScenarioName');
  const pcapScenarioDesc = document.getElementById('pcapScenarioDesc');
  const pcapTransformPlan = document.getElementById('pcapTransformPlan');
  const pcapActionsList = document.getElementById('pcapActionsList');
  const pcapRunNowBtn = document.getElementById('pcapRunNowBtn');
  const pcapSaveTestBtn = document.getElementById('pcapSaveTestBtn');
  const pcapBackToStreams = document.getElementById('pcapBackToStreams');
  const closePcapModal = document.getElementById('closePcapModal');

  // PCAP Stream Selection elements
  const pcapStreamOverlay = document.getElementById('pcapStreamOverlay');
  const pcapStreamTableBody = document.getElementById('pcapStreamTableBody');
  const pcapStreamFilter = document.getElementById('pcapStreamFilter');
  const pcapStreamFilterBtn = document.getElementById('pcapStreamFilterBtn');
  const pcapStreamFilterClearBtn = document.getElementById('pcapStreamFilterClearBtn');
  const pcapStreamFilename = document.getElementById('pcapStreamFilename');
  const pcapStreamStatus = document.getElementById('pcapStreamStatus');
  const closePcapStreamModal = document.getElementById('closePcapStreamModal');

  // State
  let running = false;
  let pcapFile = null;
  let logToFile = false;
  let logFileHeader = false;
  let results = [];
  let pendingPackets = [];
  let allScenarios = {};
  let categories = {};
  let currentPcapScenario = null;
  let defaultDisabled = new Set();
  let runStartedAt = null;
  let elapsedTimer = null;
  let allH2Scenarios = {};
  let h2Categories = {};
  let h2DefaultDisabled = new Set();
  let allQuicScenarios = {};
  let quicCategories = {};
  let quicDefaultDisabled = new Set();
  let allTcpScenarios = {};
  let tcpCategories = {};
  let rawAvailable = false;
  let activeProtocol = 'tls'; // 'tls' | 'h2' | 'quic' | 'raw-tcp'
  let unsubPacket = null;
  let unsubResult = null;
  let unsubProgress = null;
  let unsubReport = null;
  let lastReport = null;
  let localMode = false;
  let distributedMode = false;
  let clientActiveWorkers = 0;
  let serverActiveWorkers = 0;

  // ── Scenario hover tooltip ──────────────────────────────────────────
  const scenarioTooltip = document.createElement('div');
  scenarioTooltip.className = 'scenario-tooltip';
  document.body.appendChild(scenarioTooltip);
  let _ttHideTimer = null;

  function _escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function _attachScenarioTooltip(item, s) {
    // Remove native title to avoid double tooltip
    item.removeAttribute('title');

    item.addEventListener('mouseenter', (e) => {
      clearTimeout(_ttHideTimer);
      const expectedVal = s.expected || 'N/A';
      const reason = s.expectedReason || '';
      let html = `<div class="tt-name">${_escHtml(s.name)}</div>`;
      html += `<div class="tt-desc">${_escHtml(s.description)}</div>`;
      html += `<div class="tt-divider"></div>`;
      html += `<div class="tt-section"><span class="tt-label">Side:</span><span class="tt-value">${_escHtml(s.side)}</span></div>`;
      html += `<div class="tt-section"><span class="tt-label">Category:</span><span class="tt-value">${_escHtml(s.category)}</span></div>`;
      html += `<div class="tt-section"><span class="tt-label">Expected:</span><span class="tt-value pass">${_escHtml(expectedVal)}</span></div>`;
      if (reason) {
        html += `<div class="tt-section"><span class="tt-label">Pass if:</span><span class="tt-value">${_escHtml(reason)}</span></div>`;
      }
      if (s.requiresRaw) {
        html += `<div class="tt-section"><span class="tt-label">Note:</span><span class="tt-value fail">Requires raw sockets</span></div>`;
      }
      scenarioTooltip.innerHTML = html;
      scenarioTooltip.classList.add('visible');
      _positionTooltip(e);
    });

    item.addEventListener('mousemove', _positionTooltip);

    item.addEventListener('mouseleave', () => {
      _ttHideTimer = setTimeout(() => {
        scenarioTooltip.classList.remove('visible');
      }, 80);
    });
  }

  function _positionTooltip(e) {
    const tt = scenarioTooltip;
    const margin = 12;
    let x = e.clientX + margin;
    let y = e.clientY + margin;
    // Measure after making visible
    const w = tt.offsetWidth || 300;
    const h = tt.offsetHeight || 120;
    if (x + w > window.innerWidth - 8) x = e.clientX - w - margin;
    if (y + h > window.innerHeight - 8) y = e.clientY - h - margin;
    tt.style.left = x + 'px';
    tt.style.top = y + 'px';
  }
  let agentsConnected = false;
  let connectedAgents = { client: false, server: false };
  let unsubAgentDone = null;
  let unsubAgentStatus = null;
  let statusPollTimer = null;

  // Mode toggle — hide host for server mode (unless local mode is on)
  modeSelect.addEventListener('change', () => {
    if (!distributedMode) {
      hostGroup.style.display = (modeSelect.value === 'server' && !localMode) ? 'none' : 'flex';
    }
    filterScenariosBySide();
  });

  // Local target mode toggle
  localModeCheck.addEventListener('change', () => {
    localMode = localModeCheck.checked;
    if (localMode) {
      hostInput.value = 'localhost';
      hostInput.disabled = true;
      // Show host group even in server mode so user can see it's localhost
      if (!distributedMode) hostGroup.style.display = 'flex';
    } else {
      hostInput.disabled = false;
      if (!distributedMode && modeSelect.value === 'server') {
        hostGroup.style.display = 'none';
      }
    }
  });

  // Distributed mode toggle
  distributedCheck.addEventListener('change', () => {
    distributedMode = distributedCheck.checked;
    distributedBar.style.display = distributedMode ? 'flex' : 'none';
    if (!distributedMode) {
      // Hide deploy bar when leaving distributed mode
      autoDeployCheck.checked = false;
      deployBar.style.display = 'none';
    }
    if (distributedMode) {
      // In distributed mode, show all scenarios (both sides)
      modeSelect.disabled = true;
      // Keep hostGroup visible and enabled so user can specify target for client agent
      hostGroup.style.display = 'flex';
      localModeCheck.checked = false;
      localModeCheck.disabled = true;
      localMode = false;
      hostInput.disabled = false;
      renderAllScenarios();
    } else {
      modeSelect.disabled = false;
      localModeCheck.disabled = false;
      hostGroup.style.display = modeSelect.value === 'server' && !localMode ? 'none' : 'flex';
      if (agentsConnected) {
        handleDisconnect();
      }
      renderScenarios();
    }
  });

  // DUT toggle
  dutCheck.addEventListener('change', () => {
    dutBar.style.display = dutCheck.checked ? 'flex' : 'none';
  });

  // DUT Auth toggle
  dutAuthType.addEventListener('change', () => {
    dutUserPassGroup.style.display = dutAuthType.value === 'password' ? 'flex' : 'none';
    dutApiKeyGroup.style.display = dutAuthType.value === 'apikey' ? 'flex' : 'none';
  });

  // Open firewall monitor manually
  firewallBtn.addEventListener('click', () => {
    const dut = {
      ip: dutIpInput.value.trim(),
      authType: dutAuthType.value,
      user: dutUserInput.value.trim(),
      pass: dutPassInput.value,
      apiKey: dutApiKeyInput.value.trim(),
    };
    window.fuzzer.openFirewall(dut);
  });

  // --- SSH Auto-Deploy (Beta) ---
  const autoDeployCheck = document.getElementById('autoDeployCheck');
  const deployBar = document.getElementById('deployBar');
  const clientSshHost = document.getElementById('clientSshHost');
  const clientSshUser = document.getElementById('clientSshUser');
  const clientSshPass = document.getElementById('clientSshPass');
  const clientKeyBtn = document.getElementById('clientKeyBtn');
  const clientKeyLabel = document.getElementById('clientKeyLabel');
  const serverSshHost = document.getElementById('serverSshHost');
  const serverSshUser = document.getElementById('serverSshUser');
  const serverSshPass = document.getElementById('serverSshPass');
  const serverKeyBtn = document.getElementById('serverKeyBtn');
  const serverKeyLabel = document.getElementById('serverKeyLabel');
  const deployBtn = document.getElementById('deployBtn');
  const teardownBtn = document.getElementById('teardownBtn');
  const deployLog = document.getElementById('deployLog');

  let clientKeyPath = null;
  let serverKeyPath = null;
  let deployed = false;

  autoDeployCheck.addEventListener('change', () => {
    deployBar.style.display = autoDeployCheck.checked ? 'flex' : 'none';
    // Hide manual connect when auto-deploy is active
    connectBtn.style.display = autoDeployCheck.checked ? 'none' : '';
    disconnectBtn.style.display = autoDeployCheck.checked ? 'none' : '';
    clientAgentIp.disabled = autoDeployCheck.checked;
    serverAgentIp.disabled = autoDeployCheck.checked;
  });

  clientKeyBtn.addEventListener('click', async () => {
    const keyPath = await window.fuzzer.selectSshKey();
    if (keyPath) {
      clientKeyPath = keyPath;
      const name = keyPath.split('/').pop().split('\\').pop();
      clientKeyLabel.textContent = name;
      clientKeyBtn.classList.add('key-selected');
    }
  });

  serverKeyBtn.addEventListener('click', async () => {
    const keyPath = await window.fuzzer.selectSshKey();
    if (keyPath) {
      serverKeyPath = keyPath;
      const name = keyPath.split('/').pop().split('\\').pop();
      serverKeyLabel.textContent = name;
      serverKeyBtn.classList.add('key-selected');
    }
  });

  function appendDeployLog(role, phase, message, type) {
    const cls = type === 'error' ? 'deploy-error' : type === 'ok' ? 'deploy-ok' : 'deploy-phase';
    const line = document.createElement('div');
    const prefix = document.createElement('span');
    prefix.className = cls;
    prefix.textContent = `[${role}/${phase}]`;
    line.appendChild(prefix);
    line.appendChild(document.createTextNode(` ${message}`));
    deployLog.appendChild(line);
    deployLog.scrollTop = deployLog.scrollHeight;
  }

  // Listen for deploy status events from main process
  window.fuzzer.onDeployStatus((data) => {
    const type = data.phase === 'ready' ? 'ok' : data.phase === 'error' ? 'error' : null;
    appendDeployLog(data.role, data.phase, data.message, type);
  });

  deployBtn.addEventListener('click', async () => {
    const cHost = clientSshHost.value.trim();
    const sHost = serverSshHost.value.trim();
    if (!cHost && !sHost) {
      addLogEntry('error', 'Enter at least one SSH host to deploy to');
      return;
    }

    deployBtn.disabled = true;
    teardownBtn.disabled = true;
    deployLog.innerHTML = '';

    const opts = {};
    // Tell main which protocol the upcoming run will exercise so the deployer
    // can verify the right capabilities (Node 24+ for QUIC, raw-socket for
    // raw TCP, etc.). Falls back to the currently selected tab.
    opts.protocol = activeProtocol;
    if (cHost) {
      opts.client = {
        host: cHost,
        username: clientSshUser.value.trim() || 'root',
        password: clientSshPass.value || null,
        keyPath: clientKeyPath || null,
      };
    }
    if (sHost) {
      opts.server = {
        host: sHost,
        username: serverSshUser.value.trim() || 'root',
        password: serverSshPass.value || null,
        keyPath: serverKeyPath || null,
      };
    }

    try {
      const result = await window.fuzzer.distributedDeploy(opts);

      if (result.error) {
        appendDeployLog('deploy', 'error', result.error, 'error');
        deployBtn.disabled = false;
        return;
      }

      // Handle per-role errors
      if (result.clientError) appendDeployLog('client', 'error', result.clientError, 'error');
      if (result.serverError) appendDeployLog('server', 'error', result.serverError, 'error');
      if (result.clientConnectError) appendDeployLog('client', 'error', `Connect failed: ${result.clientConnectError}`, 'error');
      if (result.serverConnectError) appendDeployLog('server', 'error', `Connect failed: ${result.serverConnectError}`, 'error');

      // Format the deployer's capability summary as a one-line status. Lets
      // the operator see, at a glance, which protocols are actually ready on
      // the deployed box — control plane up + tls/h2/quic/raw-tcp readiness.
      const fmtCaps = (c) => {
        if (!c) return '';
        const flags = ['tls', 'http2', 'quic', 'rawTcp']
          .map(k => `${k}=${c[k] ? 'ok' : '-'}`).join(' ');
        return ` [node ${c.nodeVersion || '?'}, ${flags}]`;
      };

      // Update agent status dots and IP fields
      if (result.client && !result.clientConnectError) {
        clientAgentIp.value = result.client.host;
        setAgentStatus('client', 'ready');
        connectedAgents.client = true;
        appendDeployLog('client', 'done', `Agent connected at ${result.client.host}:${result.client.controlPort}${fmtCaps(result.client.capabilities)}`, 'ok');
      }
      if (result.server && !result.serverConnectError) {
        serverAgentIp.value = result.server.host;
        setAgentStatus('server', 'ready');
        connectedAgents.server = true;
        appendDeployLog('server', 'done', `Agent connected at ${result.server.host}:${result.server.controlPort}${fmtCaps(result.server.capabilities)}`, 'ok');
      }

      if (connectedAgents.client || connectedAgents.server) {
        agentsConnected = true;
        deployed = true;
        teardownBtn.disabled = false;
        startStatusPolling();
      } else {
        deployBtn.disabled = false;
      }
    } catch (err) {
      appendDeployLog('deploy', 'error', err.message, 'error');
      deployBtn.disabled = false;
    }
  });

  teardownBtn.addEventListener('click', async () => {
    teardownBtn.disabled = true;
    try {
      await window.fuzzer.distributedTeardown();
    } catch (_) {}
    deployed = false;
    agentsConnected = false;
    connectedAgents = { client: false, server: false };
    setAgentStatus('client', 'idle');
    setAgentStatus('server', 'idle');
    stopStatusPolling();
    deployBtn.disabled = false;
    appendDeployLog('teardown', 'done', 'Agents stopped and cleaned up', 'ok');
  });

  // Connect to remote agents
  connectBtn.addEventListener('click', handleConnect);
  disconnectBtn.addEventListener('click', handleDisconnect);

  async function handleConnect() {
    const cHost = clientAgentIp.value.trim() || '127.0.0.1';
    const sHost = serverAgentIp.value.trim() || '127.0.0.1';

    setAgentStatus('client', 'connecting');
    setAgentStatus('server', 'connecting');
    connectBtn.disabled = true;

    try {
      const result = await window.fuzzer.distributedConnect({
        clientHost: cHost,
        clientPort: '9200',
        clientToken: null,
        serverHost: sHost,
        serverPort: '9201',
        serverToken: null,
      });

      if (result.client) {
        connectedAgents.client = true;
        setAgentStatus('client', result.client.status || 'idle');
        addLogEntry('info', `Client agent connected: ${cHost}:9200 (${result.client.status})`);
      } else if (result.clientError) {
        connectedAgents.client = false;
        setAgentStatus('client', 'error');
        addLogEntry('error', `Client agent: ${result.clientError}`);
      }

      if (result.server) {
        connectedAgents.server = true;
        setAgentStatus('server', result.server.status || 'idle');
        addLogEntry('info', `Server agent connected: ${sHost}:9201 (${result.server.status})`);
      } else if (result.serverError) {
        connectedAgents.server = false;
        setAgentStatus('server', 'error');
        addLogEntry('error', `Server agent: ${result.serverError}`);
      }

      const anyConnected = result.client || result.server;
      if (anyConnected) {
        agentsConnected = true;
        disconnectBtn.disabled = false;
        clientAgentIp.disabled = true;
        serverAgentIp.disabled = true;
        startStatusPolling();

        // After connecting, if we have scenarios selected, also push the configuration
        // so the agents know the target port immediately.
        const scenarios = getSelectedScenarios();
        if (scenarios.length > 0) {
          const host = hostInput.value.trim() || 'localhost';
          const port = parseInt(portInput.value, 10) || 443;
          const delay = parseInt(delayInput.value, 10) || 100;
          const timeout = parseInt(timeoutInput.value, 10) || 5000;
          const workers = 1;

          // Simple split by side
          const clientScenarios = [];
          const serverScenarios = [];
          const checkboxes = scenariosList.querySelectorAll('input[type="checkbox"]:checked');
          for (const cb of checkboxes) {
            if (cb.dataset.side === 'client') clientScenarios.push(cb.value);
            else if (cb.dataset.side === 'server') serverScenarios.push(cb.value);
          }

          addLogEntry('info', `Pushing configuration to agents (Port: ${port})...`);
          await window.fuzzer.distributedConfigure({
            clientScenarios: clientScenarios.length > 0 ? clientScenarios : null,
            serverScenarios: serverScenarios.length > 0 ? serverScenarios : null,
            clientConfig: { host, port, delay, timeout, workers, protocol: activeProtocol, baseline: baselineCheck.checked },
            serverConfig: { hostname: host, port, delay, timeout, workers: 1, protocol: activeProtocol, baseline: baselineCheck.checked },
          });
          addLogEntry('info', `Agents configured and ready on port ${port}`);
        }
      } else {
        connectBtn.disabled = false;
      }
    } catch (err) {
      addLogEntry('error', `Connect failed: ${err.message || err}`);
      setAgentStatus('client', 'error');
      setAgentStatus('server', 'error');
      connectBtn.disabled = false;
    }
  }

  async function handleDisconnect() {
    stopStatusPolling();
    try {
      await window.fuzzer.distributedDisconnect();
    } catch (_) {}
    agentsConnected = false;
    connectedAgents = { client: false, server: false };
    setAgentStatus('client', 'idle');
    setAgentStatus('server', 'idle');
    connectBtn.disabled = false;
    disconnectBtn.disabled = true;
    clientAgentIp.disabled = false;
    serverAgentIp.disabled = false;
    addLogEntry('info', 'Disconnected from agents');
  }

  function setAgentStatus(role, status, workerCount) {
    const dot = role === 'client' ? clientStatusDot : serverStatusDot;
    const text = role === 'client' ? clientStatusText : serverStatusText;
    dot.className = `agent-status-dot agent-${status}`;
    if (workerCount !== undefined) {
      if (role === 'client') clientActiveWorkers = workerCount;
      else serverActiveWorkers = workerCount;
      text.textContent = workerCount > 0 ? `${status.toUpperCase()} (${workerCount}W)` : status.toUpperCase();
      updateButtonStates();
    } else {
      text.textContent = status.toUpperCase();
    }
  }

  window.fuzzer.onAgentStatus((event) => {
    if (event.role === 'client') clientActiveWorkers = event.activeWorkerCount || 0;
    else if (event.role === 'server') serverActiveWorkers = event.activeWorkerCount || 0;
    setAgentStatus(event.role, event.status, event.activeWorkerCount);
  });

  function startStatusPolling() {
    stopStatusPolling();
    statusPollTimer = setInterval(async () => {
      if (!agentsConnected) return;
      try {
        const cStatus = await window.fuzzer.distributedStatus('client');
        if (cStatus && !cStatus.error) setAgentStatus('client', cStatus.status, cStatus.activeWorkerCount);
        const sStatus = await window.fuzzer.distributedStatus('server');
        if (sStatus && !sStatus.error) setAgentStatus('server', sStatus.status, sStatus.activeWorkerCount);
      } catch (_) {}
    }, 2000);
  }

  function stopStatusPolling() {
    if (statusPollTimer) {
      clearInterval(statusPollTimer);
      statusPollTimer = null;
    }
  }

  // Protocol tab switching
  tlsTabBtn.addEventListener('click', () => {
    if (activeProtocol === 'tls') return;
    activeProtocol = 'tls';
    tlsTabBtn.classList.add('active');
    http2TabBtn.classList.remove('active');
    quicTabBtn.classList.remove('active');
    tcpTabBtn.classList.remove('active');

    filterScenariosBySide();
  });

  http2TabBtn.addEventListener('click', () => {
    if (activeProtocol === 'h2') return;
    activeProtocol = 'h2';
    http2TabBtn.classList.add('active');
    tlsTabBtn.classList.remove('active');
    quicTabBtn.classList.remove('active');
    tcpTabBtn.classList.remove('active');

    filterScenariosBySide();
  });

  quicTabBtn.addEventListener('click', () => {
    if (activeProtocol === 'quic') return;
    activeProtocol = 'quic';
    quicTabBtn.classList.add('active');
    tlsTabBtn.classList.remove('active');
    http2TabBtn.classList.remove('active');
    tcpTabBtn.classList.remove('active');

    filterScenariosBySide();
  });

  tcpTabBtn.addEventListener('click', () => {
    if (activeProtocol === 'raw-tcp') return;
    activeProtocol = 'raw-tcp';
    tcpTabBtn.classList.add('active');
    tlsTabBtn.classList.remove('active');
    http2TabBtn.classList.remove('active');
    quicTabBtn.classList.remove('active');

    filterScenariosBySide();
  });

  // Select dropdown menu
  selectMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    selectMenu.classList.toggle('open');
  });

  // Close menu on outside click
  document.addEventListener('click', () => {
    selectMenu.classList.remove('open');
  });

  selectMenu.addEventListener('click', (e) => {
    const item = e.target.closest('.select-menu-item');
    if (!item) return;
    const action = item.dataset.action;
    selectMenu.classList.remove('open');

    const checkboxes = scenariosList.querySelectorAll('input[type="checkbox"]:not(:disabled)');
    if (action === 'none') {
      checkboxes.forEach(cb => cb.checked = false);
    } else if (action === 'all') {
      checkboxes.forEach(cb => cb.checked = true);
    } else if (action === 'fuzz') {
      checkboxes.forEach(cb => cb.checked = cb.dataset.fuzzed === 'true');
    } else if (action === 'clean') {
      checkboxes.forEach(cb => cb.checked = cb.dataset.fuzzed === 'false');
    }
  });

  // Load scenarios
  async function loadScenarios() {
    console.log('Loading scenarios...');
    try {
      const data = await window.fuzzer.listScenarios();
      console.log('Scenarios data received:', data);
      categories = data.categories;
      allScenarios = data.scenarios;
      defaultDisabled = new Set(data.defaultDisabled || []);
      h2Categories = data.h2Categories || {};
      allH2Scenarios = data.h2Scenarios || {};
      h2DefaultDisabled = new Set(data.h2DefaultDisabled || []);
      quicCategories = data.quicCategories || {};
      allQuicScenarios = data.quicScenarios || {};
      quicDefaultDisabled = new Set(data.quicDefaultDisabled || []);
      tcpCategories = data.tcpCategories || {};
      allTcpScenarios = data.tcpScenarios || {};
      rawAvailable = data.rawAvailable || false;
      renderScenarios();
    } catch (err) {
      console.error('Failed to load scenarios:', err);
    }
  }

  function renderScenarios() {
    console.log('Rendering scenarios for protocol:', activeProtocol, 'side:', modeSelect.value);
    scenariosList.innerHTML = '';
    const side = modeSelect.value;

    if (activeProtocol === 'raw-tcp') {
      renderTcpScenarios(side);
      return;
    }

    if (activeProtocol === 'quic') {
      renderQuicScenarios(side);
      return;
    }

    if (activeProtocol === 'h2') {
      renderH2Scenarios(side);
      return;
    }

    for (const [cat, label] of Object.entries(categories)) {
      const items = (allScenarios[cat] || []).filter(s => s.side === side);
      if (items.length === 0) continue;

      const group = document.createElement('div');
      group.className = 'category-group';

      const header = document.createElement('div');
      header.className = 'category-header';
      const disabledTag = defaultDisabled.has(cat)
        ? ' <span class="opt-in-tag">server-side, opt-in</span>'
        : '';
      header.innerHTML = `
        <span class="arrow">&#9660;</span>
        <span class="cat-label">${cat}: ${label}</span>
        <span class="count">${items.length}</span>${disabledTag}
        <div class="category-controls" onclick="event.stopPropagation()">
          <button class="btn-tiny select-cat-only" title="Select ONLY this category (deselect everything else)">Only</button>
          <button class="btn-tiny select-cat-all" title="Select all in this category">All</button>
          <button class="btn-tiny select-cat-none" title="Deselect all in this category">None</button>
        </div>
      `;

      const itemsDiv = document.createElement('div');
      itemsDiv.className = 'category-items';

      header.addEventListener('click', () => {
        const arrow = header.querySelector('.arrow');
        itemsDiv.classList.toggle('collapsed');
        arrow.classList.toggle('collapsed');
      });

      // Category selection logic
      header.querySelector('.select-cat-only').onclick = () => {
        scenariosList.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
        itemsDiv.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach(cb => cb.checked = true);
      };
      header.querySelector('.select-cat-all').onclick = () => {
        itemsDiv.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach(cb => cb.checked = true);
      };
      header.querySelector('.select-cat-none').onclick = () => {
        itemsDiv.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
      };

      for (const s of items) {
        const item = document.createElement('label');
        const isUnavailable = s.requiresRaw && !rawAvailable;
        item.className = `scenario-item ${isUnavailable ? 'unavailable' : ''}`;
        _attachScenarioTooltip(item, s);

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = s.name;
        cb.dataset.side = s.side;
        cb.dataset.category = cat;
        cb.dataset.fuzzed = s.fuzzed ? 'true' : 'false';
        if (isUnavailable) {
          cb.disabled = true;
        }

        const nameSpan = document.createElement('span');
        nameSpan.className = 'name';
        nameSpan.textContent = s.name;

        const sideTag = document.createElement('span');
        sideTag.className = `side-tag ${s.side}`;
        sideTag.textContent = s.side;

        item.appendChild(cb);
        item.appendChild(nameSpan);
        item.appendChild(sideTag);

        // Add delete button for PCAP scenarios
        if (cat === 'PCAP') {
          const delBtn = document.createElement('button');
          delBtn.className = 'btn-tiny pcap-delete-btn';
          delBtn.textContent = '\u2715';
          delBtn.title = 'Delete this saved PCAP test';
          delBtn.style.cssText = 'margin-left:auto; color:var(--danger); border-color:var(--danger); font-size:10px; padding:1px 5px; cursor:pointer;';
          delBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!confirm(`Delete saved PCAP test "${s.name}"?`)) return;
            const result = await window.fuzzer.deletePcapTest(s.name);
            if (result && result.ok) {
              item.remove();
              addLogEntry('info', `Deleted PCAP test: ${s.name}`);
            } else {
              addLogEntry('error', `Failed to delete: ${result ? result.error : 'unknown'}`);
            }
          });
          item.appendChild(delBtn);
        }

        itemsDiv.appendChild(item);
      }

      group.appendChild(header);
      group.appendChild(itemsDiv);
      scenariosList.appendChild(group);
    }
  }

  // Helper: build a category group element for H2/QUIC scenarios
  function _buildProtocolCategoryGroup(protocol, cat, label, items) {
    const group = document.createElement('div');
    group.className = 'category-group';

    const header = document.createElement('div');
    header.className = 'category-header';
    header.innerHTML = `
      <span class="arrow">&#9660;</span>
      <span class="cat-label">${cat}: ${label}</span>
      <span class="count">${items.length}</span>
      <div class="category-controls" onclick="event.stopPropagation()">
        <button class="btn-tiny select-cat-only" title="Select ONLY this category (deselect everything else)">Only</button>
        <button class="btn-tiny select-cat-all" title="Select all in this category">All</button>
        <button class="btn-tiny select-cat-none" title="Deselect all in this category">None</button>
      </div>
    `;

    const itemsDiv = document.createElement('div');
    itemsDiv.className = 'category-items';

    header.addEventListener('click', () => {
      const arrow = header.querySelector('.arrow');
      itemsDiv.classList.toggle('collapsed');
      arrow.classList.toggle('collapsed');
    });

    // Category selection logic
    header.querySelector('.select-cat-only').onclick = () => {
      scenariosList.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
      itemsDiv.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach(cb => cb.checked = true);
    };
    header.querySelector('.select-cat-all').onclick = () => {
      itemsDiv.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach(cb => cb.checked = true);
    };
    header.querySelector('.select-cat-none').onclick = () => {
      itemsDiv.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
    };

    for (const s of items) {
      const item = document.createElement('label');
      const isUnavailable = s.requiresRaw && !rawAvailable;
      item.className = `scenario-item ${isUnavailable ? 'unavailable' : ''}`;
      _attachScenarioTooltip(item, s);

      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = s.name;
      cb.dataset.side = s.side;
      cb.dataset.category = cat;
      cb.dataset.fuzzed = s.fuzzed ? 'true' : 'false';
      cb.dataset.protocol = protocol;
      if (isUnavailable) {
        cb.disabled = true;
      }

      const nameSpan = document.createElement('span');
      nameSpan.className = 'name';
      nameSpan.textContent = s.name;

      const protoTag = document.createElement('span');
      protoTag.className = `side-tag ${protocol}-tag`;
      protoTag.textContent = protocol;

      const sideTag = document.createElement('span');
      sideTag.className = `side-tag ${s.side}`;
      sideTag.textContent = s.side;

      item.appendChild(cb);
      item.appendChild(nameSpan);
      item.appendChild(protoTag);
      item.appendChild(sideTag);
      itemsDiv.appendChild(item);
    }

    group.appendChild(header);
    group.appendChild(itemsDiv);
    return group;
  }

  function _buildH2CategoryGroup(cat, label, items) {
    return _buildProtocolCategoryGroup('h2', cat, label, items);
  }

  function _buildQuicCategoryGroup(cat, label, items) {
    return _buildProtocolCategoryGroup('quic', cat, label, items);
  }

  function renderH2Scenarios(side) {
    scenariosList.innerHTML = '';

    if (side === 'server') {
      // Server mode: show info panel + AJ server-to-client attack scenarios
      const info = document.createElement('div');
      info.className = 'h2-server-info';
      info.innerHTML = `
        <div class="h2-server-icon">⚡</div>
        <p class="h2-server-title">HTTP/2 Server Mode</p>
        <p class="h2-server-desc">Select <strong>AJ</strong> server-to-client attack scenarios below, or click <strong>RUN</strong> with none selected to start a passive HTTP/2 server on port <strong>${portInput.value}</strong>.</p>
        <p class="h2-server-desc">A connecting HTTP/2 client will trigger each selected scenario — the fuzzer acts as a malicious server.</p>
      `;
      scenariosList.appendChild(info);

      // Show only server-side scenarios (AJ)
      for (const [cat, label] of Object.entries(h2Categories)) {
        const items = (allH2Scenarios[cat] || []).filter(s => s.side === 'server');
        if (items.length === 0) continue;
        scenariosList.appendChild(_buildH2CategoryGroup(cat, label, items));
      }
      return;
    }

    // Client mode: show all client-side HTTP/2 scenarios
    for (const [cat, label] of Object.entries(h2Categories)) {
      const items = (allH2Scenarios[cat] || []).filter(s => s.side === 'client');
      if (items.length === 0) continue;
      scenariosList.appendChild(_buildH2CategoryGroup(cat, label, items));
    }
  }

  function renderQuicScenarios(side) {
    scenariosList.innerHTML = '';

    for (const [cat, label] of Object.entries(quicCategories)) {
      const items = (allQuicScenarios[cat] || []).filter(s => s.side === side);
      if (items.length === 0) continue;
      scenariosList.appendChild(_buildQuicCategoryGroup(cat, label, items));
    }
  }

  function renderTcpScenarios(side) {
    scenariosList.innerHTML = '';

    if (!rawAvailable) {
      const warning = document.createElement('div');
      warning.className = 'tcp-warning';
      warning.innerHTML = '<strong>Raw sockets not available.</strong> Requires CAP_NET_RAW on Linux.<br>Run: <code>sudo setcap cap_net_raw+ep $(which node)</code>';
      warning.style.cssText = 'padding: 12px; margin: 8px; background: #fef3c7; border: 1px solid #f59e0b; border-radius: 6px; color: #92400e; font-size: 12px;';
      scenariosList.appendChild(warning);
    }

    for (const [cat, label] of Object.entries(tcpCategories)) {
      const items = (allTcpScenarios[cat] || []).filter(s => s.side === side);
      if (items.length === 0) continue;
      scenariosList.appendChild(_buildProtocolCategoryGroup('raw-tcp', cat, label, items));
    }
  }

  // Render all scenarios (both client and server) for distributed mode.
  // Respects activeProtocol — shows TLS or H2 scenarios depending on the active tab.
  function renderAllScenarios() {
    scenariosList.innerHTML = '';

    if (activeProtocol === 'raw-tcp') {
      for (const [cat, label] of Object.entries(tcpCategories)) {
        const items = allTcpScenarios[cat] || [];
        if (items.length === 0) continue;
        scenariosList.appendChild(_buildProtocolCategoryGroup('raw-tcp', cat, label, items));
      }
      return;
    }

    if (activeProtocol === 'quic') {
      for (const [cat, label] of Object.entries(quicCategories)) {
        const items = allQuicScenarios[cat] || [];
        if (items.length === 0) continue;
        scenariosList.appendChild(_buildQuicCategoryGroup(cat, label, items));
      }
      return;
    }

    if (activeProtocol === 'h2') {
      // Show all H2 scenarios (client + server sides)
      for (const [cat, label] of Object.entries(h2Categories)) {
        const items = allH2Scenarios[cat] || [];
        if (items.length === 0) continue;
        scenariosList.appendChild(_buildH2CategoryGroup(cat, label, items));
      }
      return;
    }

    // Show all TLS scenarios (client + server sides)
    for (const [cat, label] of Object.entries(categories)) {
      if (cat === 'Z') continue;
      const items = allScenarios[cat] || [];
      if (items.length === 0) continue;

      const group = document.createElement('div');
      group.className = 'category-group';

      const header = document.createElement('div');
      header.className = 'category-header';
      const disabledTag = defaultDisabled.has(cat)
        ? ' <span class="opt-in-tag">opt-in</span>'
        : '';
      header.innerHTML = `
        <span class="arrow">&#9660;</span>
        <span class="cat-label">${cat}: ${label}</span>
        <span class="count">${items.length}</span>${disabledTag}
        <div class="category-controls" onclick="event.stopPropagation()">
          <button class="btn-tiny select-cat-only" title="Select ONLY this category (deselect everything else)">Only</button>
          <button class="btn-tiny select-cat-all" title="Select all in this category">All</button>
          <button class="btn-tiny select-cat-none" title="Deselect all in this category">None</button>
        </div>
      `;

      const itemsDiv = document.createElement('div');
      itemsDiv.className = 'category-items';

      header.addEventListener('click', () => {
        const arrow = header.querySelector('.arrow');
        itemsDiv.classList.toggle('collapsed');
        arrow.classList.toggle('collapsed');
      });

      // Category selection logic
      header.querySelector('.select-cat-only').onclick = () => {
        scenariosList.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
        itemsDiv.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach(cb => cb.checked = true);
      };
      header.querySelector('.select-cat-all').onclick = () => {
        itemsDiv.querySelectorAll('input[type="checkbox"]:not(:disabled)').forEach(cb => cb.checked = true);
      };
      header.querySelector('.select-cat-none').onclick = () => {
        itemsDiv.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
      };

      for (const s of items) {
        const item = document.createElement('label');
        const isUnavailable = s.requiresRaw && !rawAvailable;
        item.className = `scenario-item ${isUnavailable ? 'unavailable' : ''}`;
        _attachScenarioTooltip(item, s);

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = s.name;
        cb.dataset.side = s.side;
        cb.dataset.category = cat;
        cb.dataset.fuzzed = s.fuzzed ? 'true' : 'false';
        if (isUnavailable) {
          cb.disabled = true;
        }

        const nameSpan = document.createElement('span');
        nameSpan.className = 'name';
        nameSpan.textContent = s.name;

        const sideTag = document.createElement('span');
        sideTag.className = `side-tag ${s.side}`;
        sideTag.textContent = s.side;

        item.appendChild(cb);
        item.appendChild(nameSpan);
        item.appendChild(sideTag);
        itemsDiv.appendChild(item);
      }

      group.appendChild(header);
      group.appendChild(itemsDiv);
      scenariosList.appendChild(group);
    }
  }

  function filterScenariosBySide() {
    if (distributedMode) {
      renderAllScenarios();
    } else {
      renderScenarios();
    }
  }

  function getSelectedScenarios() {
    const checkboxes = scenariosList.querySelectorAll('input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(cb => cb.value);
  }


  // PCAP toggle
  pcapBtn.addEventListener('click', async () => {
    if (pcapFile) {
      pcapFile = null;
      pcapBtn.textContent = 'PCAP: OFF';
      pcapBtn.classList.remove('active');
      pcapPathEl.textContent = '';
    } else {
      const path = await window.fuzzer.savePcapDialog();
      if (path) {
        pcapFile = path;
        pcapBtn.textContent = 'PCAP: ON';
        pcapBtn.classList.add('active');
        pcapPathEl.textContent = path.split(/[\\/]/).pop();
      }
    }
  });

  // --- PCAP Ingestion Logic ---
  let ingestedPcapPath = null;

  // Deserialize a hex-encoded Buffer from IPC back to a real Buffer-like object
  function deserializeAction(a) {
    const out = { ...a };
    if (out.data && out.data._hex) out.data = { type: 'Buffer', data: Array.from(hexToBytes(out.data._hex)), length: out.data.length };
    if (out.clientHello && out.clientHello._hex) out.clientHello = { type: 'Buffer', data: Array.from(hexToBytes(out.clientHello._hex)), length: out.clientHello.length };
    if (out.clientRandom && out.clientRandom._hex) out.clientRandom = { type: 'Buffer', data: Array.from(hexToBytes(out.clientRandom._hex)), length: out.clientRandom.length };
    return out;
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
  }

  // --- Wireshark-style filter matching ---
  let pcapStreamsList = []; // cached streams from last PCAP load

  function matchesFilter(stream, filterText) {
    if (!filterText || !filterText.trim()) return true;
    const text = filterText.trim();

    // Split on top-level || (OR groups), then each group on && (AND)
    const orGroups = text.split(/\s*\|\|\s*/);
    return orGroups.some(group => {
      const andTerms = group.split(/\s*&&\s*/);
      return andTerms.every(term => matchesSingleTerm(stream, term.trim()));
    });
  }

  function matchesSingleTerm(stream, term) {
    // Parse: field == value  or  field != value
    const m = term.match(/^([\w.]+)\s*(==|!=)\s*"?([^"]*)"?$/);
    if (!m) return true; // unrecognized filter → show all
    const [, field, op, value] = m;
    let result = false;

    // Extract ports and IPs from client/server strings like "1.2.3.4:443"
    const clientParts = (stream.client || '').split(':');
    const serverParts = (stream.server || '').split(':');
    const clientIp = clientParts.slice(0, -1).join(':');
    const clientPort = clientParts[clientParts.length - 1];
    const serverIp = serverParts.slice(0, -1).join(':');
    const serverPort = serverParts[serverParts.length - 1];

    switch (field) {
      case 'tcp.port':
      case 'udp.port':
        result = clientPort === value || serverPort === value;
        break;
      case 'tcp.srcport':
      case 'udp.srcport':
        result = clientPort === value;
        break;
      case 'tcp.dstport':
      case 'udp.dstport':
        result = serverPort === value;
        break;
      case 'ip.addr':
        result = clientIp === value || serverIp === value;
        break;
      case 'ip.src':
        result = clientIp === value;
        break;
      case 'ip.dst':
        result = serverIp === value;
        break;
      case 'tls.handshake.extensions_server_name':
        result = (stream.sni || '').toLowerCase().includes(value.toLowerCase());
        break;
      default:
        result = true; // unknown field → pass through
    }
    return op === '==' ? result : !result;
  }

  function renderStreamTable(streams, filterText) {
    pcapStreamTableBody.innerHTML = '';
    const filtered = streams.filter(s => matchesFilter(s, filterText));
    const MAX_DISPLAY = 200;
    const display = filtered.slice(0, MAX_DISPLAY);

    for (const s of display) {
      const tr = document.createElement('tr');
      tr.style.cssText = 'cursor:pointer; transition: background 0.15s;';
      tr.addEventListener('mouseenter', () => { tr.style.background = 'rgba(59,130,246,0.12)'; });
      tr.addEventListener('mouseleave', () => { tr.style.background = ''; });
      tr.addEventListener('click', () => {
        pcapStreamOverlay.style.display = 'none';
        performPcapAnalysis(ingestedPcapPath, s.index);
      });

      const cellStyle = 'padding:8px 6px; border-bottom:1px solid var(--border); color:var(--text-primary);';
      tr.innerHTML = `
        <td style="${cellStyle}">${s.index}</td>
        <td style="${cellStyle}"><span style="color:${s.transportProto === 'TCP' ? 'var(--primary)' : 'var(--secondary)'};">${_escHtml(s.proto || s.transportProto)}</span></td>
        <td style="${cellStyle}">${_escHtml(s.client || '')}</td>
        <td style="${cellStyle} text-align:center; color:var(--text-muted);">→</td>
        <td style="${cellStyle}">${_escHtml(s.server || '')}</td>
        <td style="${cellStyle} color:var(--text-secondary);">${_escHtml(s.sni || s.summary || '')}</td>
        <td style="${cellStyle} color:var(--text-secondary);">${_escHtml(s.cipher || '')}</td>
        <td style="${cellStyle} text-align:right;">${s.pktCount || 0}</td>
      `;
      pcapStreamTableBody.appendChild(tr);
    }

    const truncMsg = filtered.length > MAX_DISPLAY ? ` (showing first ${MAX_DISPLAY})` : '';
    pcapStreamStatus.textContent = filterText
      ? `${filtered.length} of ${streams.length} streams match filter${truncMsg}`
      : `${streams.length} stream${streams.length !== 1 ? 's' : ''} found${truncMsg} — use filter to narrow down`;
  }

  // --- Handshake analysis HTML rendering ---
  function buildAnalysisHtml(handshakeAnalysis, scenario, clientActions) {
    if (!handshakeAnalysis || handshakeAnalysis.length === 0) {
      // Fallback for scenarios without analysis
      const explanation = scenario.explanation || '';
      const hasTls12Hs = clientActions.some(a => a.type === 'tls12Handshake');
      if (hasTls12Hs) {
        return `<div style="color:var(--text-secondary);">TLS 1.2 ECDHE — ClientHello replayed verbatim (JA3 preserved), fresh key exchange at runtime.</div>`;
      }
      return `<div style="color:var(--text-secondary);">${_escHtml(explanation || 'Raw packet replay')}</div>`;
    }

    const parts = [];
    for (const e of handshakeAnalysis) {
      const isAlert = e.msg === 'Alert';
      const arrow = e.dir === 'c2s' ? '&rarr;' : '&larr;';
      const arrowColor = isAlert ? '#ef4444' : (e.dir === 'c2s' ? '#6366f1' : '#22c55e');
      const dirLabel = e.dir === 'c2s' ? 'Client' : 'Server';

      if (e.msg === 'ClientHello') {
        const groupsStr = e.groups.length > 0 ? e.groups.join(', ') : 'none';
        const sigAlgsMax = 4;
        const sigAlgsStr = e.sigAlgs.length > sigAlgsMax
          ? e.sigAlgs.slice(0, sigAlgsMax).join(', ') + `, ...+${e.sigAlgs.length - sigAlgsMax} more`
          : (e.sigAlgs.length > 0 ? e.sigAlgs.join(', ') : 'none');
        const ksGroups = e.keyShareGroups.length > 0
          ? e.keyShareGroups.map(g => `${g.name} (${g.keySize}B)`).join(', ')
          : '';
        const versionsStr = e.supportedVersions.length > 0 ? e.supportedVersions.join(', ') : '';

        let html = `<div style="margin-bottom:8px;">`;
        html += `<div><span style="color:${arrowColor};font-weight:600;">${arrow} ClientHello</span>`;
        html += `  <span style="color:var(--text-muted);">${_escHtml(e.version)} (0x${(0x0303).toString(16)})</span>`;
        if (e.sni) html += `  |  <span style="color:var(--primary);">SNI: ${_escHtml(e.sni)}</span>`;
        if (e.alpn.length > 0) html += `  |  ALPN: ${_escHtml(e.alpn.join(', '))}`;
        html += `</div>`;
        html += `<div style="margin-left:20px;color:var(--text-secondary);font-size:11px;">`;
        html += `<div>${e.cipherCount} cipher suites: ${_escHtml(e.cipherNames.join(', '))}</div>`;
        html += `<div>Groups: ${_escHtml(groupsStr)}</div>`;
        html += `<div>Signature Algorithms: ${_escHtml(sigAlgsStr)}</div>`;
        if (versionsStr) html += `<div>Supported Versions: ${_escHtml(versionsStr)}</div>`;
        if (ksGroups) html += `<div>Key Share: ${_escHtml(ksGroups)}</div>`;
        html += `<div>${e.extensionCount} extensions total</div>`;
        html += `</div></div>`;
        parts.push(html);

      } else if (e.msg === 'ServerHello') {
        let html = `<div style="margin-bottom:8px;">`;
        html += `<span style="color:${arrowColor};font-weight:600;">${arrow} ServerHello</span>`;
        html += `  <span style="color:var(--text-muted);">${_escHtml(e.version)}</span>`;
        html += `  |  Selected: <span style="color:var(--primary);">${_escHtml(e.selectedCipher)}</span>`;
        html += ` <span style="color:var(--text-muted);">(${e.selectedCipherHex})</span>`;
        html += `</div>`;
        parts.push(html);

      } else if (e.msg === 'Certificate') {
        let html = `<div style="margin-bottom:8px;">`;
        html += `<span style="color:${arrowColor};font-weight:600;">${arrow} Certificate</span>`;
        html += `  ${e.certCount} certificate${e.certCount !== 1 ? 's' : ''}`;
        html += `<div style="margin-left:20px;color:var(--text-secondary);font-size:11px;">`;
        for (const c of e.certs) {
          let keyInfo = '';
          if (c.keyType && c.keyType !== 'unknown') {
            keyInfo = ` | <span style="color:var(--primary);">${_escHtml(c.keyType)}`;
            if (c.keySize) keyInfo += `-${c.keySize}`;
            if (c.keyCurve) keyInfo += ` (${_escHtml(c.keyCurve)})`;
            keyInfo += `</span>`;
          }
          html += `<div>[${c.index}] CN=${_escHtml(c.cn)} (${c.size.toLocaleString()} bytes)${keyInfo}</div>`;
        }
        html += `</div></div>`;
        parts.push(html);

      } else if (e.msg === 'ServerKeyExchange') {
        let html = `<div style="margin-bottom:8px;">`;
        html += `<span style="color:${arrowColor};font-weight:600;">${arrow} ServerKeyExchange</span>`;
        html += `  Curve: <span style="color:var(--primary);">${_escHtml(e.curveName)}</span>`;
        html += ` (${e.publicKeySize}-byte public key)`;
        html += `</div>`;
        parts.push(html);

      } else if (e.msg === 'CertificateRequest') {
        parts.push(`<div style="margin-bottom:8px;"><span style="color:${arrowColor};font-weight:600;">${arrow} CertificateRequest</span>  <span style="color:var(--text-muted);">Server requests client certificate</span></div>`);

      } else if (e.msg === 'ServerHelloDone') {
        parts.push(`<div style="margin-bottom:8px;"><span style="color:${arrowColor};font-weight:600;">${arrow} ServerHelloDone</span></div>`);

      } else if (e.msg === 'Alert') {
        const levelColor = e.level === 'fatal' ? '#ef4444' : '#d97706';
        const levelLabel = e.level.toUpperCase();
        const sender = e.dir === 'c2s' ? 'Client' : 'Server';
        let html = `<div style="margin-bottom:8px;background:rgba(248,81,73,0.08);border-left:3px solid ${levelColor};padding:6px 10px;border-radius:0 4px 4px 0;">`;
        html += `<span style="color:${levelColor};font-weight:600;">&#9888; ${sender} Alert</span>`;
        html += `  <span style="color:${levelColor};">${levelLabel}: ${_escHtml(e.descName)}</span>`;
        html += ` <span style="color:var(--text-muted);">(${e.descCode})</span>`;
        if (e.causeHint) {
          html += `<div style="margin-top:3px;margin-left:20px;color:var(--text-secondary);font-size:11px;">Likely cause: ${_escHtml(e.causeHint)}</div>`;
        }
        html += `</div>`;
        parts.push(html);
      }
    }

    // Replay strategy summary
    const hasTls12Hs = clientActions.some(a => a.type === 'tls12Handshake');
    const hasTls13 = clientActions.some(a => a.label && a.label.includes('TLS 1.3'));
    if (hasTls12Hs) {
      parts.push(`<div style="margin-top:6px;padding:6px 10px;background:rgba(99,102,241,0.06);border-left:3px solid #6366f1;border-radius:0 4px 4px 0;font-size:11px;color:var(--text-secondary);">Replay: ClientHello verbatim (JA3 preserved) + fresh ECDHE key exchange at runtime</div>`);
    } else if (hasTls13) {
      parts.push(`<div style="margin-top:6px;padding:6px 10px;background:rgba(99,102,241,0.06);border-left:3px solid #6366f1;border-radius:0 4px 4px 0;font-size:11px;color:var(--text-secondary);">Replay: TLS 1.3 ClientHello with fresh key_share (fingerprint preserved)</div>`);
    }

    return parts.join('');
  }

  async function performPcapAnalysis(path, streamIdx) {
    addLogEntry('info', `Analyzing PCAP stream ${streamIdx}: ${path}...`);
    const result = await window.fuzzer.analyzePcap(path, streamIdx);
    if (!result.ok) {
      addLogEntry('error', `PCAP Analysis failed: ${result.error}`);
      alert(`PCAP Analysis failed: ${result.error}`);
      return;
    }

    // The scenario comes serialized from IPC (no functions, Buffers as hex).
    // Reconstruct actions as functions for the run pipeline.
    const s = result.scenario;
    const clientActions = (s._clientActions || []).map(deserializeAction);
    const serverActions = (s._serverActions || []).map(deserializeAction);

    currentPcapScenario = {
      ...s,
      actions: () => clientActions,
      clientActions: () => clientActions,
      serverActions: () => serverActions,
    };

    pcapScenarioName.value = currentPcapScenario.name;
    pcapScenarioDesc.value = currentPcapScenario.description;
    pcapSaveTestBtn.textContent = '\u{1F4BE} SAVE TEST';
    pcapSaveTestBtn.disabled = false;

    // Build handshake analysis
    pcapTransformPlan.innerHTML = buildAnalysisHtml(s.handshakeAnalysis || [], s, clientActions);

    // Visualize actions
    pcapActionsList.innerHTML = clientActions.map(a => {
      const label = a.label ? `<span style="color:var(--primary); margin-left:10px;">(${a.label})</span>` : '';
      if (a.type === 'send') {
        const bytes = a.data ? (a.data.length || 0) : 0;
        return `<div style="margin-bottom:4px;">&rarr; <strong>SEND</strong> ${bytes} bytes ${label}</div>`;
      } else if (a.type === 'recv') {
        return `<div style="margin-bottom:4px;">&larr; <strong>RECV</strong> (timeout: ${a.timeout}ms) ${label}</div>`;
      } else if (a.type === 'tls12Handshake') {
        return `<div style="margin-bottom:4px;">&#128273; <strong>TLS 1.2 ECDHE Handshake</strong> (live key exchange) ${label}</div>`;
      }
      return `<div style="margin-bottom:4px;">&#9889; <strong>${a.type.toUpperCase()}</strong> ${label}</div>`;
    }).join('');

    pcapAnalysisOverlay.style.display = 'flex';
  }

  // --- PCAP Ingest: Stream Selection Flow ---
  ingestPcapBtn.addEventListener('click', async () => {
    const path = await window.fuzzer.openPcapDialog();
    if (!path) return;
    ingestedPcapPath = path;
    pcapStreamFilename.textContent = path.split(/[\\/]/).pop();
    pcapStreamFilter.value = '';
    pcapStreamStatus.textContent = 'Loading streams...';
    pcapStreamTableBody.innerHTML = '';
    pcapStreamOverlay.style.display = 'flex';

    const result = await window.fuzzer.listPcapStreams(path);
    if (!result.ok) {
      pcapStreamStatus.textContent = `Error: ${result.error}`;
      addLogEntry('error', `PCAP stream listing failed: ${result.error}`);
      return;
    }

    pcapStreamsList = result.streams;
    renderStreamTable(pcapStreamsList, '');

    // If only one stream, auto-select it
    if (pcapStreamsList.length === 1) {
      pcapStreamOverlay.style.display = 'none';
      performPcapAnalysis(path, 0);
    }
  });

  // Filter handlers
  pcapStreamFilterBtn.addEventListener('click', () => {
    renderStreamTable(pcapStreamsList, pcapStreamFilter.value);
  });
  pcapStreamFilter.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') renderStreamTable(pcapStreamsList, pcapStreamFilter.value);
  });
  pcapStreamFilterClearBtn.addEventListener('click', () => {
    pcapStreamFilter.value = '';
    renderStreamTable(pcapStreamsList, '');
  });

  // Close / Back handlers
  closePcapStreamModal.addEventListener('click', () => {
    pcapStreamOverlay.style.display = 'none';
  });

  closePcapModal.addEventListener('click', () => {
    pcapAnalysisOverlay.style.display = 'none';
    currentPcapScenario = null;
  });

  pcapBackToStreams.addEventListener('click', () => {
    pcapAnalysisOverlay.style.display = 'none';
    currentPcapScenario = null;
    pcapStreamOverlay.style.display = 'flex';
  });

  // Save PCAP test to suite (independent of run)
  pcapSaveTestBtn.addEventListener('click', async () => {
    if (!currentPcapScenario) return;
    currentPcapScenario.name = pcapScenarioName.value.trim();
    currentPcapScenario.description = pcapScenarioDesc.value.trim();

    const clientActions = currentPcapScenario.actions();
    const serverActions = currentPcapScenario.serverActions ? currentPcapScenario.serverActions() : [];
    const saveData = {
      name: currentPcapScenario.name,
      category: currentPcapScenario.category,
      description: currentPcapScenario.description,
      side: currentPcapScenario.side,
      protocol: currentPcapScenario.protocol,
      explanation: currentPcapScenario.explanation,
      expected: currentPcapScenario.expected,
      expectedReason: currentPcapScenario.expectedReason,
      pcapParams: currentPcapScenario.pcapParams,
      actions: clientActions,
      serverActions: serverActions,
    };
    const saveResult = await window.fuzzer.savePcapTest(saveData);
    if (saveResult && saveResult.ok) {
      addLogEntry('info', `Test saved: ${saveResult.name} — now available under TLS > PCAP Ingested Tests`);
      pcapSaveTestBtn.textContent = '\u2713 Saved';
      pcapSaveTestBtn.disabled = true;
      // Refresh scenario list so the new test appears immediately
      await loadScenarios();
    } else {
      addLogEntry('error', `Failed to save test: ${saveResult ? saveResult.error : 'unknown error'}`);
    }
  });

  // Run PCAP test (does not save)
  pcapRunNowBtn.addEventListener('click', async () => {
    if (!currentPcapScenario) return;
    currentPcapScenario.name = pcapScenarioName.value.trim();
    currentPcapScenario.description = pcapScenarioDesc.value.trim();

    // Build a plain IPC-safe scenario — functions can't cross Electron's structured clone.
    const clientActions = currentPcapScenario.actions();
    const serverActions = currentPcapScenario.serverActions ? currentPcapScenario.serverActions() : [];
    const runScenario = {
      name: currentPcapScenario.name,
      category: currentPcapScenario.category,
      description: currentPcapScenario.description,
      side: currentPcapScenario.side,
      protocol: currentPcapScenario.protocol,
      explanation: currentPcapScenario.explanation,
      expected: currentPcapScenario.expected,
      expectedReason: currentPcapScenario.expectedReason,
      pcapParams: currentPcapScenario.pcapParams,
      _clientActions: clientActions,
      _serverActions: serverActions,
    };

    pcapAnalysisOverlay.style.display = 'none';
    // PCAP tests need a local well-behaved server to replay against
    if (!localMode) {
      localMode = true;
      localModeCheck.checked = true;
      localModeCheck.dispatchEvent(new Event('change'));
    }
    startFuzzing(runScenario);
  });

  async function startFuzzing(customScenario = null) {
    if (running) return;

    const mode = modeSelect.value;
    const host = hostInput.value.trim();
    const port = parseInt(portInput.value, 10);
    const delay = parseInt(delayInput.value, 10) || 100;
    const timeout = parseInt(timeoutInput.value, 10) || 5000;
    const verbose = verboseCheck.checked;
    const isPassiveServer = (activeProtocol === 'h2' || activeProtocol === 'quic') && mode === 'server' && getSelectedScenarios().length === 0;

    if (!port || port < 1 || port > 65535) {
      addLogEntry('error', 'Invalid port number');
      return;
    }

    if (!customScenario && !isPassiveServer) {
      if (mode === 'client' && !host && !localMode) {
        addLogEntry('error', 'Please enter a hostname');
        return;
      }
      if ((activeProtocol !== 'h2' && activeProtocol !== 'quic') || mode !== 'server') {
        const scenarioNames = getSelectedScenarios();
        if (scenarioNames.length === 0) {
          addLogEntry('error', 'No scenarios selected');
          return;
        }
      }
    }

    const workers = 1;

    const scenarioNames = customScenario ? [] : getSelectedScenarios();
    const loopCount = Math.max(1, Math.min(1000, parseInt(loopCountInput.value, 10) || 1));
    const totalScenarios = (customScenario ? 1 : (scenarioNames.length || (isPassiveServer ? 1 : 0))) * loopCount;

    setRunning(true);
    results = [];
    logFileHeader = false;
    resultsBody.innerHTML = '';
    resultsEmpty.style.display = 'none';
    resultsTable.style.display = 'table';
    summaryBar.style.display = 'none';
    progressContainer.style.display = isPassiveServer ? 'none' : 'flex';
    progressBar.style.width = '0%';
    progressText.textContent = `0 / ${totalScenarios}`;

    const dut = dutCheck.checked ? {
      ip: dutIpInput.value.trim(),
      authType: dutAuthType.value,
      user: dutUserInput.value.trim(),
      pass: dutPassInput.value,
      apiKey: dutApiKeyInput.value.trim(),
    } : null;

    const isDutValid = dut && dut.ip && (
      (dut.authType === 'password' && dut.user && dut.pass) ||
      (dut.authType === 'apikey' && dut.apiKey)
    );
    document.body.classList.toggle('dut-active', Boolean(isDutValid));

    if (dut && dut.ip) {
      window.fuzzer.openFirewall(dut);
    }

    unsubPacket = window.fuzzer.onPacket(handlePacketEvent);
    unsubResult = window.fuzzer.onResult(handleResult);
    unsubProgress = window.fuzzer.onProgress(handleProgress);
    unsubReport = window.fuzzer.onReport((report) => { lastReport = report; });

    try {
      const response = await window.fuzzer.run({
        mode, host: localMode ? 'localhost' : host, port, scenarioNames, 
        scenario: customScenario, delay, timeout,
        pcapFile: pcapFile || null,
        mergePcap: !!pcapFile,
        verbose,
        protocol: activeProtocol,
        dut,
        loopCount,
        localMode,
        baseline: baselineCheck.checked,
        workers,
      });

      if (response.error) {
        addLogEntry('error', `Error: ${response.error}`);
      }
    } catch (err) {
      addLogEntry('error', `Fatal: ${err.message || err}`);
    } finally {
      setRunning(false);
      if (unsubPacket) { unsubPacket(); unsubPacket = null; }
      if (unsubResult) { unsubResult(); unsubResult = null; }
      if (unsubProgress) { unsubProgress(); unsubProgress = null; }
      if (unsubReport) { unsubReport(); unsubReport = null; }
      progressContainer.style.display = 'none';
      showSummary();
    }
  }

  // Run
  runBtn.addEventListener('click', async () => {
    if (running) return;
    if (distributedMode) {
      runDistributed();
    } else {
      startFuzzing();
    }
  });

  // Rerun failed tests
  rerunFailedBtn.addEventListener('click', () => {
    if (running) return;

    const failedScenarios = results.filter(r => 
      r.verdict === 'UNEXPECTED' || 
      r.status === 'ERROR' || 
      r.hostDown
    ).map(r => r.scenario);

    if (failedScenarios.length === 0) return;

    // Uncheck all
    setAllCheckboxes(false);

    // Check failed ones
    const checkboxes = scenariosList.querySelectorAll('input[type="checkbox"]:not(:disabled)');
    checkboxes.forEach(cb => {
      if (failedScenarios.includes(cb.value)) {
        cb.checked = true;
      }
    });

    // Trigger run
    runBtn.click();
  });

  // Distributed run
  async function runDistributed() {
    if (!agentsConnected) {
      addLogEntry('error', 'Connect to agents first');
      return;
    }

    // Split selected scenarios by side
    const checkboxes = scenariosList.querySelectorAll('input[type="checkbox"]:checked');
    const clientScenarios = [];
    const serverScenarios = [];
    const pcapScenarios = [];
    for (const cb of checkboxes) {
      if (cb.dataset.category === 'PCAP') {
        pcapScenarios.push(cb.value);
      } else if (cb.dataset.side === 'client') {
        clientScenarios.push(cb.value);
      } else if (cb.dataset.side === 'server') {
        serverScenarios.push(cb.value);
      }
    }

    if (clientScenarios.length === 0 && serverScenarios.length === 0 && pcapScenarios.length === 0) {
      addLogEntry('error', 'No scenarios selected');
      return;
    }

    // Validate that required agents are connected
    const needClient = clientScenarios.length > 0 || serverScenarios.length > 0 || pcapScenarios.length > 0;
    const needServer = serverScenarios.length > 0 || clientScenarios.length > 0 || pcapScenarios.length > 0;
    if (needClient && !connectedAgents.client) {
      addLogEntry('error', 'Client agent is not connected — reconnect before running');
      return;
    }
    if (needServer && !connectedAgents.server) {
      addLogEntry('error', 'Server agent is not connected — reconnect before running');
      return;
    }

    const host = hostInput.value.trim() || 'localhost';
    const port = parseInt(portInput.value, 10) || 443;
    const delay = parseInt(delayInput.value, 10) || 100;
    const timeout = parseInt(timeoutInput.value, 10) || 5000;

    // In distributed mode, we coordinate the two agents to ensure every test
    // has a compliant partner. We run in two phases if both sides are selected.
    const clientScenariosFinal = [];
    const serverScenariosFinal = [];

    let wbServer = 'well-behaved-server';
    let wbClient = 'fv-tls-well-behaved-small-ch';
    if (activeProtocol === 'h2') {
      wbServer = 'well-behaved-h2-server';
      wbClient = 'well-behaved-h2-client';
    } else if (activeProtocol === 'quic') {
      wbServer = 'srv-quic-well-behaved-echo';
      wbClient = 'well-behaved-quic-client';
    }

    const helperClientForServerScenario = (scenarioName) => {
      if (activeProtocol !== 'tls') return wbClient;
      const appHelper = getDistributedAppClientHelper(scenarioName);
      if (appHelper) return appHelper;
      return String(scenarioName || '').includes('pqc')
        ? 'fv-tls-well-behaved-pqc-ch'
        : 'fv-tls-well-behaved-small-ch';
    };

    const helperServerForClientScenario = (scenarioName) => {
      if (activeProtocol !== 'tls') return wbServer;
      return getDistributedAppServerHelper(scenarioName) || wbServer;
    };

    if (clientScenarios.length > 0 && serverScenarios.length === 0) {
      // Phase: Client Fuzzing only
      clientScenariosFinal.push(...clientScenarios);
      for (const scenarioName of clientScenarios) {
        serverScenariosFinal.push(helperServerForClientScenario(scenarioName));
      }
    } else if (serverScenarios.length > 0 && clientScenarios.length === 0) {
      // Phase: Server Fuzzing only
      serverScenariosFinal.push(...serverScenarios);
      for (const scenarioName of serverScenarios) {
        clientScenariosFinal.push(helperClientForServerScenario(scenarioName));
      }
    } else if (clientScenarios.length > 0 && serverScenarios.length > 0) {
      // Combined Phase: Client Fuzzing followed by Server Fuzzing
      // 1. Client Fuzzing Batch
      clientScenariosFinal.push(...clientScenarios);
      for (const scenarioName of clientScenarios) {
        serverScenariosFinal.push(helperServerForClientScenario(scenarioName));
      }
      // 2. Server Fuzzing Batch
      serverScenariosFinal.push(...serverScenarios);
      for (const scenarioName of serverScenarios) {
        clientScenariosFinal.push(helperClientForServerScenario(scenarioName));
      }
    }

    const dut = dutCheck.checked ? {
      ip: dutIpInput.value.trim(),
      authType: dutAuthType.value,
      user: dutUserInput.value.trim(),
      pass: dutPassInput.value,
      apiKey: dutApiKeyInput.value.trim(),
    } : null;

    const isDutValid = dut && dut.ip && (
      (dut.authType === 'password' && dut.user && dut.pass) ||
      (dut.authType === 'apikey' && dut.apiKey)
    );
    document.body.classList.toggle('dut-active', Boolean(isDutValid));

    setRunning(true);
    results = [];
    logFileHeader = false;
    resultsBody.innerHTML = '';
    resultsEmpty.style.display = 'none';
    resultsTable.style.display = 'table';
    summaryBar.style.display = 'none';
    progressContainer.style.display = 'flex';
    progressBar.style.width = '0%';
    const totalScenarios = clientScenarios.length + serverScenarios.length + pcapScenarios.length;
    progressText.textContent = `0 / ${totalScenarios}`;

    // Open firewall monitor popup in DUT mode
    if (dut && dut.ip) {
      window.fuzzer.openFirewall(dut);
    }

    const workers = 1;

    // Configure agents
    addLogEntry('info', `Configuring agents: ${clientScenarios.length} client, ${serverScenarios.length} server${pcapScenarios.length ? `, ${pcapScenarios.length} PCAP` : ''} scenarios`);

    try {
      const configResult = await window.fuzzer.distributedConfigure({
        clientScenarios: clientScenariosFinal.length > 0 ? clientScenariosFinal : null,
        serverScenarios: serverScenariosFinal.length > 0 ? serverScenariosFinal : null,
        pcapScenarios: pcapScenarios.length > 0 ? pcapScenarios : null,
        clientConfig: { host, port, delay, timeout, workers, protocol: activeProtocol, dut, pcapFile: pcapFile || null, mergePcap: !!pcapFile, baseline: baselineCheck.checked },
        serverConfig: { bindAddress: '0.0.0.0', hostname: host, port, delay, timeout, workers: 1, protocol: activeProtocol, dut, pcapFile: pcapFile || null, mergePcap: !!pcapFile, baseline: baselineCheck.checked },
      });

      if (configResult.error) {
        addLogEntry('error', `Configure failed: ${configResult.error}`);
        setRunning(false);
        progressContainer.style.display = 'none';
        return;
      }

      if (connectedAgents.client) {
        setAgentStatus('client', 'ready');
        addLogEntry('info', 'Client agent configured — ready');
      }
      if (connectedAgents.server) {
        setAgentStatus('server', 'ready');
        addLogEntry('info', 'Server agent configured — ready');
      }
    } catch (err) {
      addLogEntry('error', `Configure failed: ${err.message || err}`);
      setRunning(false);
      progressContainer.style.display = 'none';
      return;
    }

    // Subscribe to events
    const hasClientWork = clientScenariosFinal.length > 0 || pcapScenarios.length > 0;
    const hasServerWork = serverScenariosFinal.length > 0 || pcapScenarios.length > 0;
    let agentsDone = { client: !hasClientWork, server: !hasServerWork };

    unsubPacket = window.fuzzer.onPacket((evt) => {
      const roleTag = evt.agentRole ? `[${evt.agentRole}] ` : '';
      handlePacketEvent(evt, roleTag);
    });

    unsubResult = window.fuzzer.onResult((result) => {
      handleResult(result);
    });

    unsubProgress = window.fuzzer.onProgress((prog) => {
      handleProgress(prog);
    });

    unsubReport = window.fuzzer.onReport((report) => {
      lastReport = report;
    });

    unsubAgentDone = window.fuzzer.onAgentDone((data) => {
      agentsDone[data.role] = true;
      setAgentStatus(data.role, 'done');
      addLogEntry('info', `${data.role} agent finished`);

      if (agentsDone.client && agentsDone.server) {
        finishDistributedRun();
      }
    });

    unsubAgentStatus = window.fuzzer.onAgentStatus((data) => {
      setAgentStatus(data.role, data.status);
    });

    // Trigger stepped execution — one scenario pair at a time
    try {
      const totalPairs = clientScenariosFinal.length + pcapScenarios.length;
      addLogEntry('info', `Starting stepped distributed execution (${totalPairs} pairs)...`);
      const runResult = await window.fuzzer.distributedRunStepped({ totalPairs });
      if (runResult.error) {
        addLogEntry('error', `Run failed: ${runResult.error}`);
      }
    } catch (err) {
      addLogEntry('error', `Run failed: ${err.message || err}`);
    }

    // Stepped execution blocks until all pairs complete + /finish is sent,
    // so both agents should already be done. Finish immediately.
    finishDistributedRun();
  }

  function finishDistributedRun() {
    setRunning(false);
    if (unsubPacket) { unsubPacket(); unsubPacket = null; }
    if (unsubResult) { unsubResult(); unsubResult = null; }
    if (unsubProgress) { unsubProgress(); unsubProgress = null; }
    if (unsubReport) { unsubReport(); unsubReport = null; }
    if (unsubAgentDone) { unsubAgentDone(); unsubAgentDone = null; }
    if (unsubAgentStatus) { unsubAgentStatus(); unsubAgentStatus = null; }
    progressContainer.style.display = 'none';
    showSummary();
  }

  // Stop
  stopBtn.addEventListener('click', async () => {
    if (!running) return;
    if (distributedMode) {
      await window.fuzzer.distributedStop();
      addLogEntry('info', 'Stop requested for all agents...');
      finishDistributedRun();
    } else {
      await window.fuzzer.stop();
      addLogEntry('info', 'Stop requested...');
    }
  });

  // Handle incoming packet events from the fuzzer
  function handlePacketEvent(evt, rolePrefix) {
    if (distributedMode && evt.agentRole) {
      modeSelect.value = evt.agentRole;
    }
    const p = rolePrefix || '';
    switch (evt.type) {
      case 'scenario':
        pendingPackets = [];
        addLogEntry('scenario-name', `${p}--- ${evt.name}: ${evt.description} ---`);
        break;
      case 'sent':
        pendingPackets.push({ ts: new Date().toISOString(), type: 'sent', label: evt.label, size: evt.size, hex: evt.hex });
        addLogEntry('sent', `${p}\u2192 ${evt.label || 'Sent'} (${evt.size} bytes)`);
        if (evt.hex) addHexDump(evt.hex);
        break;
      case 'received':
        pendingPackets.push({ ts: new Date().toISOString(), type: 'received', label: evt.label, size: evt.size, hex: evt.hex });
        addLogEntry('received', `${p}\u2190 ${evt.label || 'Received'} (${evt.size} bytes)`);
        if (evt.hex) addHexDump(evt.hex);
        break;
      case 'tcp':
        pendingPackets.push({ ts: new Date().toISOString(), type: 'tcp', direction: evt.direction, flag: evt.event });
        addLogEntry('tcp', `${p}[TCP] ${evt.direction === 'sent' ? '\u2192' : '\u2190'} ${evt.event}`);
        break;
      case 'fuzz':
        addLogEntry('fuzz', `${p}[FUZZ] ${evt.message}`);
        break;
      case 'info':
        addLogEntry('info', `${p}${evt.message}`);
        break;
      case 'error':
        addLogEntry('error', `${p}${evt.message}`);
        break;
      case 'result': {
        const cls = evt.status === 'PASSED' ? 'pass' : 'fail';
        const downStr = evt.hostDown ? ' [HOST DOWN]' : '';
        addLogEntry(`result-line ${cls}`, `${p}Result: ${evt.scenario} \u2014 ${evt.status} \u2014 ${evt.response}${downStr}`);
        break;
      }
      case 'host-down':
        addLogEntry('host-down', `${p}!! HOST DOWN — ${evt.host}:${evt.port} unreachable after "${evt.scenario}" — possible crash/DoS !!`);
        break;
      case 'health-probe': {
        const ping = evt.probe.tcp || evt.probe.udp;
        const pingStr = ping && ping.alive ? `Ping OK (${ping.latency}ms)` : `Ping FAIL (${ping ? ping.error : 'no probe'})`;
        addLogEntry('health-probe', `${p}Health: ${pingStr}`);
        break;
      }
      default:
        addLogEntry('info', `${p}${JSON.stringify(evt)}`);
    }
  }

  // Look up scenario metadata from loaded data (TLS, HTTP/2, QUIC)
  function findScenarioMeta(name) {
    for (const items of Object.values(allScenarios)) {
      const found = items.find(s => s.name === name);
      if (found) return found;
    }
    for (const items of Object.values(allH2Scenarios)) {
      const found = items.find(s => s.name === name);
      if (found) return found;
    }
    for (const items of Object.values(allQuicScenarios)) {
      const found = items.find(s => s.name === name);
      if (found) return found;
    }
    return null;
  }

  // Compute verdict: does the actual result match expected secure behavior?
  function computeVerdict(status, expected) {
    if (!expected || status === 'ERROR' || status === 'ABORTED') return { verdict: 'N/A', cls: 'na' };
    // TIMEOUT counts as "dropped" for verdict purposes (server didn't respond = implicit reject)
    const effective = status === 'TIMEOUT' ? 'DROPPED' : status;
    if (effective === expected) return { verdict: 'AS EXPECTED', cls: 'expected' };
    return { verdict: 'UNEXPECTED', cls: 'unexpected' };
  }

  function renderHealthCell(probe, hostDown) {
    if (!probe) {
      // No probe ran (PASSED status) — show a dash
      return '<span class="probe-skip" title="No probe needed — scenario passed">—</span>';
    }
    const ping = probe.tcp || probe.udp || {};
    const cls = ping.alive ? 'probe-ok' : 'probe-fail';
    const label = ping.alive ? `OK ${ping.latency}ms` : `FAIL`;
    const title = ping.alive ? `Ping OK in ${ping.latency}ms` : `Ping failed: ${ping.error}`;
    return `<span class="probe-badge ${cls}" title="${_escHtml(title)}">Ping ${label}</span>`;
  }

  window.showFirewallLog = function(rawLog) {
    const modal = document.getElementById('fwModalOverlay');
    const content = document.getElementById('fwModalContent');
    if (modal && content) {
      // Try to format the raw log as JSON if it's an object, otherwise display the string
      let displayStr = rawLog;
      if (typeof rawLog === 'object') {
          displayStr = JSON.stringify(rawLog, null, 2);
      }
      content.textContent = displayStr || 'No raw log data available.';
      modal.style.display = 'flex';
    }
  };

  function renderFirewallCell(fwResult) {
    if (!fwResult) return '<span class="finding-badge finding-INFO">—</span>';
    const actionColor = fwResult.action === 'allow' ? 'probe-ok' : 'probe-fail';
    
    // We encode the fwResult as a base64 string to safely pass it in the onclick attribute
    const encodedLog = btoa(unescape(encodeURIComponent(JSON.stringify(fwResult.raw || fwResult))));
    
    return `<span class="probe-badge ${actionColor} clickable" style="cursor:pointer;" title="App: ${fwResult.appId} | Reason: ${fwResult.endReason} | Click for details" onclick="showFirewallLog(JSON.parse(decodeURIComponent(escape(atob('${encodedLog}')))))">${fwResult.action.toUpperCase()}</span>`;
  }

  function renderFindingCell(finding) {
    if (!finding) return '<span class="finding-badge finding-INFO">—</span>';
    const title = finding.reason ? _escHtml(finding.reason) : '';
    // Only show severity badge on FAIL/WARN — it's noise on PASS/INFO
    const showSev = finding.severity && (finding.grade === 'FAIL' || finding.grade === 'WARN');
    const sevHtml = showSev
      ? `<span class="severity-badge sev-${finding.severity}">${finding.severity}</span>`
      : '';
    return `<span class="finding-badge finding-${finding.grade}" title="${title}">${finding.grade}</span>${sevHtml}`;
  }

  function handleResult(result) {
    if (distributedMode && result.agentRole) {
      modeSelect.value = result.agentRole;
    }
    // Hide internal helper-counterpart results, but keep user-selected
    // diagnostic baselines (e.g. `quic-well-behaved-single-get`). The earlier
    // `includes('well-behaved')` check was too broad — it also swallowed the
    // QZ baselines, which is why the result count comes up 8 short on a full
    // QUIC distributed run. The patterns below match every helper the
    // renderer generates as a counterpart (well-behaved-*, srv-quic-…,
    // fv-tls-…, and the SMTP/FTP/LDAP STARTTLS pairs) but leave fuzz/baseline
    // scenarios alone.
    if (result.scenario && (
      result.scenario.startsWith('well-behaved-') ||
      result.scenario.startsWith('srv-quic-well-behaved-') ||
      result.scenario.startsWith('fv-tls-well-behaved-') ||
      /-well-behaved(-server)?$/.test(result.scenario)
    )) {
      return;
    }
    const meta = findScenarioMeta(result.scenario);
    const expected = meta ? meta.expected : null;
    const expectedReason = meta ? meta.expectedReason : '';
    
    // If the backend didn't provide a verdict (older version or error), compute one here
    let verdict = result.verdict;
    let verdictCls = 'na';
    if (!verdict || verdict === 'N/A') {
      const computed = computeVerdict(result.status, expected);
      verdict = computed.verdict;
      verdictCls = computed.cls;
    } else {
      verdictCls = verdict === 'AS EXPECTED' ? 'expected' : 'unexpected';
    }

    result.expected = expected;
    result.expectedReason = expectedReason;
    result.packets = pendingPackets;
    pendingPackets = [];
    // Don't overwrite result.verdict if it came from IPC
    if (!result.verdict || result.verdict === 'N/A') result.verdict = verdict;
    results.push(result);

    // Stream result to log file if logging is enabled
    if (logToFile) {
      const filePath = logPathInput.value.trim();
      if (filePath) {
        let content = '';
        if (!logFileHeader) {
          content += `--- WireStrike Run Log: ${new Date().toISOString()} ---\n`;
          content += `--- Verbose Mode: ${verboseCheck.checked ? 'ON' : 'OFF'} ---\n\n`;
          logFileHeader = true;
        }
        content += formatResultLogEntry(result);
        window.fuzzer.saveLogToFile(filePath, content).catch(() => {});
      }
    }

    const idx = results.length;
    const scenario = result.scenario || '?';
    const status = result.status || '?';
    const response = result.response || '';
    const baseline = result.baselineResponse || 'N/A';
    const cat = meta ? meta.category : '?';
    const isH2 = typeof cat === 'string' && cat.length === 2 && cat[0] === 'A';
    const isQuic = typeof cat === 'string' && cat.length >= 2 && cat[0] === 'Q';
    const noBaseline = isH2 || isQuic;
    const hostDown = result.hostDown || false;

    const tr = document.createElement('tr');
    const verdictTitle = expectedReason ? `Expected: ${expected} — ${expectedReason}` : '';
    const downBadge = hostDown ? '<span class="host-down-badge" title="Target became unreachable — possible crash/DoS">DOWN</span>' : '';
    const healthHtml = renderHealthCell(result.probe, hostDown);
    const findingHtml = renderFindingCell(result.finding);
    const firewallHtml = renderFirewallCell(result.firewallResult);
    // In distributed mode, results from client and server agents arrive interleaved.
    // Show a role badge so the user can tell them apart (otherwise it looks like
    // tests are "looping" when the server agent runs SRV scenarios in parallel
    // with the client agent's longer scenario list).
    const roleBadge = (distributedMode && result.agentRole)
      ? `<span class="role-badge role-${result.agentRole}" title="Result from ${result.agentRole} agent">${result.agentRole}</span> `
      : '';
    tr.innerHTML = `
      <td class="num">${idx}</td>
      <td>${roleBadge}${_escHtml(scenario)}</td>
      <td>${_escHtml(cat)}</td>
      <td><span class="status-badge status-${status}">${status}</span>${downBadge}</td>
      <td style="font-size: 11px; color: var(--text-secondary);${noBaseline ? ' opacity: 0.35;' : ''}">${noBaseline ? (isH2 ? 'N/A (HTTP/2)' : 'N/A (QUIC)') : _escHtml(baseline)}</td>
      <td>${healthHtml}</td>
      <td class="fw-col">${firewallHtml}</td>
      <td>${findingHtml}</td>
      <td><span class="verdict-badge verdict-${verdictCls}" title="${_escHtml(verdictTitle)}">${verdict}</span></td>
      <td>${_escHtml(response)}</td>
    `;
    resultsBody.appendChild(tr);
    tr.scrollIntoView({ block: 'nearest' });
    exportJsonBtn.disabled = false;
  }

  function handleProgress(prog) {
    if (distributedMode && prog.agentRole) {
      modeSelect.value = prog.agentRole;
    }
    const pct = Math.round((prog.current / prog.total) * 100);
    progressBar.style.width = pct + '%';
    progressText.textContent = `${prog.current} / ${prog.total}: ${prog.scenario}`;
  }

  // Packet log helpers
  function addLogEntry(cls, text) {
    const logEmpty = packetLog.querySelector('.log-empty');
    if (logEmpty) logEmpty.remove();

    const div = document.createElement('div');
    div.className = `log-entry ${cls}`;

    const time = document.createElement('span');
    time.className = 'time';
    time.textContent = new Date().toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 3 });

    div.appendChild(time);
    div.appendChild(document.createTextNode(text));
    packetLog.appendChild(div);
    packetLog.scrollTop = packetLog.scrollHeight;

    // Cap log entries at 500
    while (packetLog.children.length > 500) {
      packetLog.removeChild(packetLog.firstChild);
    }
  }

  function addHexDump(hex) {
    const pre = document.createElement('pre');
    pre.className = 'hex-dump';
    pre.textContent = hex;
    packetLog.appendChild(pre);
    packetLog.scrollTop = packetLog.scrollHeight;
  }

  // Summary
  function showSummary() {
    if (results.length === 0) return;
    summaryBar.style.display = 'flex';

    const total = results.length;
    const passed = results.filter(r => r.status === 'PASSED').length;
    const dropped = results.filter(r => r.status === 'DROPPED').length;
    const timeouts = results.filter(r => r.status === 'TIMEOUT').length;
    const errors = results.filter(r => r.status === 'ERROR').length;
    const aborted = results.filter(r => r.status === 'ABORTED').length;
    const hostDownCount = results.filter(r => r.hostDown).length;
    const probed = results.filter(r => r.probe).length;
    const pingOk = results.filter(r => r.probe && r.probe.tcp && r.probe.tcp.alive).length;
    const asExpected = results.filter(r => r.verdict === 'AS EXPECTED').length;
    const unexpected = results.filter(r => r.verdict === 'UNEXPECTED').length;

    // Grade banner
    let gradeBannerHtml = '';
    if (lastReport) {
      const r = lastReport;
      gradeBannerHtml = `
        <span class="grade-badge grade-${r.grade}">${r.grade}</span>
        <span class="grade-label">${_escHtml(r.label)}</span>
        <span class="grade-stats">
          <span class="g-pass">PASS: ${r.stats.pass}</span>
          <span class="g-fail">FAIL: ${r.stats.fail}</span>
          <span class="g-warn">WARN: ${r.stats.warn}</span>
          <span class="g-info">INFO: ${r.stats.info}</span>
        </span>
        <span style="margin-left:12px">|</span>
      `;
    }

    summaryText.innerHTML = `
      ${gradeBannerHtml}
      <span class="total">Total: ${total}</span>
      <span class="passed">Passed: ${passed}</span>
      <span class="dropped">Dropped: ${dropped}</span>
      <span class="timeout">Timeout: ${timeouts}</span>
      <span class="errors">Errors: ${errors}</span>
      ${aborted > 0 ? `<span>Aborted: ${aborted}</span>` : ''}
      ${hostDownCount > 0 ? `<span class="host-down-count">Host Down: ${hostDownCount}</span>` : ''}
      ${probed > 0 ? `<span style="margin-left:12px">|</span><span class="probe-summary">Ping ${pingOk}/${probed}</span>` : ''}
      <span style="margin-left:12px">|</span>
      <span class="as-expected">As Expected: ${asExpected}</span>
      <span class="unexpected-count">Unexpected: ${unexpected}</span>
    `;

    const hasDown = hostDownCount > 0;
    const gradeStr = lastReport ? ` [Grade: ${lastReport.grade}]` : '';
    statusBadge.textContent = hasDown ? 'DONE (HOST DOWN)' : errors > 0 ? 'DONE (ERRORS)' : `DONE${gradeStr}`;
    statusBadge.className = hasDown ? 'header-status error' : 'header-status done';

    const failedScenarios = results.filter(r => 
      r.verdict === 'UNEXPECTED' || 
      r.status === 'ERROR' || 
      r.hostDown
    ).map(r => r.scenario);
    
    const uniqueFailed = [...new Set(failedScenarios)];
    if (uniqueFailed.length > 0) {
      rerunFailedBtn.disabled = false;
      rerunFailedBtn.title = `Rerun ${uniqueFailed.length} failed test(s)`;
    } else {
      rerunFailedBtn.disabled = true;
      rerunFailedBtn.title = 'No failed tests to rerun';
    }
  }

  function updateButtonStates() {
    const isBusy = running || clientActiveWorkers > 0 || serverActiveWorkers > 0;
    runBtn.disabled = isBusy;
    if (isBusy) rerunFailedBtn.disabled = true;

    if (distributedMode) {
      // Allow Connect again even if already connected, to update the target port/config
      connectBtn.disabled = running;
      disconnectBtn.disabled = running || !agentsConnected;
    }
  }

  function formatElapsed(ms) {
    const totalSeconds = Math.max(0, Math.floor(ms / 1000));
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    const mm = String(minutes).padStart(2, '0');
    const ss = String(seconds).padStart(2, '0');
    if (hours > 0) return `${hours}:${mm}:${ss}`;
    return `${mm}:${ss}`;
  }

  function updateElapsedClock() {
    if (!elapsedClock) return;
    const elapsedMs = runStartedAt ? Date.now() - runStartedAt : 0;
    elapsedClock.textContent = `Elapsed ${formatElapsed(elapsedMs)}`;
  }

  function startElapsedClock() {
    stopElapsedClock();
    runStartedAt = Date.now();
    updateElapsedClock();
    elapsedClock?.classList.add('running');
    elapsedTimer = setInterval(updateElapsedClock, 1000);
  }

  function stopElapsedClock({ reset = false } = {}) {
    if (elapsedTimer) {
      clearInterval(elapsedTimer);
      elapsedTimer = null;
    }
    if (reset) runStartedAt = null;
    updateElapsedClock();
    elapsedClock?.classList.remove('running');
  }

  // UI state management
  function setRunning(state) {
    running = state;
    updateButtonStates();
    stopBtn.disabled = !state;
    modeSelect.disabled = state || distributedMode;
    hostInput.disabled = state;
    portInput.disabled = state;
    distributedCheck.disabled = state;

    if (state) {
      startElapsedClock();
      statusBadge.textContent = distributedMode ? 'DISTRIBUTED RUN' : 'RUNNING';
      statusBadge.className = 'header-status running';
    } else {
      stopElapsedClock();
    }
  }

  // Export JSON
  exportJsonBtn.addEventListener('click', () => {
    if (results.length === 0) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fuzzer-results-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Format a single result entry for the log file
  function formatResultLogEntry(r) {
    const meta = findScenarioMeta(r.scenario);
    const isVerbose = verboseCheck.checked;
    let entry = `==========================================================\n`;
    entry += `Scenario: ${r.scenario}\n`;
    entry += `Category: ${meta ? meta.category : 'Unknown'}\n`;
    entry += `Description: ${meta ? meta.description : 'N/A'}\n`;
    entry += `Status: ${r.status}\n`;
    entry += `Verdict: ${r.verdict}\n`;
    entry += `Target Response: ${r.response}\n`;

    const exportCat = meta ? meta.category : '';
    const exportNoBaseline = typeof exportCat === 'string' && exportCat.length >= 2 && (exportCat[0] === 'A' || exportCat[0] === 'Q');
    if (r.baselineCommand && !exportNoBaseline) {
      entry += `\n[OpenSSL Baseline Check]\n`;
      entry += `Command: ${r.baselineCommand}\n`;
      entry += `Response: ${r.baselineResponse}\n`;
      const match = r.response === r.baselineResponse ? 'YES' : 'NO';
      entry += `Matches Baseline: ${match}\n`;
    }

    if (isVerbose && r.packets && r.packets.length > 0) {
      entry += `\n[Packet Trace]\n`;
      for (const p of r.packets) {
        const dir = (p.type === 'sent' || (p.type === 'tcp' && p.direction === 'sent')) ? '\u2192' : '\u2190';
        entry += `${p.ts} ${dir} ${p.label || p.flag || p.type} (${p.size || 0} bytes)\n`;
        if (p.hex) {
          const hex = p.hex;
          for (let i = 0; i < hex.length; i += 32) {
            const chunk = hex.substr(i, 32);
            let line = `    ${(i/2).toString(16).padStart(8, '0')}  `;
            for (let j = 0; j < chunk.length; j += 2) {
              line += chunk.substr(j, 2) + ' ';
              if (j === 14) line += ' ';
            }
            entry += line + '\n';
          }
        }
      }
    }
    entry += `\n`;
    return entry;
  }

  logToFileBtn.addEventListener('click', () => {
    if (logToFile) {
      // Toggle OFF
      logToFile = false;
      logFileHeader = false;
      logToFileBtn.textContent = 'Log: OFF';
      logToFileBtn.classList.remove('active');
      logPathInput.disabled = false;
      return;
    }
    const filePath = logPathInput.value.trim();
    if (!filePath) {
      alert('Please enter a file path first.');
      return;
    }
    // Toggle ON
    logToFile = true;
    logFileHeader = false;
    logToFileBtn.textContent = 'Log: ON';
    logToFileBtn.classList.add('active');
    logPathInput.disabled = true;
  });

  // Clear buttons
  clearResultsBtn.addEventListener('click', () => {
    results = [];
    pendingPackets = [];
    lastReport = null;
    resultsBody.innerHTML = '';
    resultsEmpty.style.display = 'block';
    resultsTable.style.display = 'table';
    exportJsonBtn.disabled = true;
    rerunFailedBtn.disabled = true;
    rerunFailedBtn.title = 'Rerun failed tests';
    summaryBar.style.display = 'none';
    statusBadge.textContent = 'IDLE';
    statusBadge.className = 'header-status';
    stopElapsedClock({ reset: true });
  });

  clearLogBtn.addEventListener('click', () => {
    packetLog.innerHTML = '<div class="log-empty">Waiting for packets...</div>';
  });

  // Utility
  function _escHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Init
  loadScenarios();
})();
