// TLS/TCP Protocol Fuzzer — Renderer
(function () {
  'use strict';

  // DOM elements
  const modeSelect = document.getElementById('modeSelect');
  const hostGroup = document.getElementById('hostGroup');
  const hostInput = document.getElementById('hostInput');
  const portInput = document.getElementById('portInput');
  const delayInput = document.getElementById('delayInput');
  const timeoutInput = document.getElementById('timeoutInput');
  const workersInput = document.getElementById('workersInput');
  workersInput.value = window.fuzzer.cpuCount || 4;
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

  // State
  let running = false;
  let pcapFile = null;
  let logToFile = false;
  let logFileHeader = false;
  let results = [];
  let pendingPackets = [];
  let allScenarios = {};
  let categories = {};
  let defaultDisabled = new Set();
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
          const workers = parseInt(workersInput.value, 10) || 1;

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

  function updateWorkerConstraints() {
    const protocol = activeProtocol;
    if (protocol === 'tls' || protocol === 'h2' || protocol === 'quic') {
      workersInput.disabled = true;
      workersInput.title = `${protocol.toUpperCase()} is currently limited to 1 worker (concurrency support coming later).`;
      workersInput.value = 1;
    } else {
      workersInput.disabled = false;
      workersInput.title = "";
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
    updateWorkerConstraints();
    filterScenariosBySide();
  });

  http2TabBtn.addEventListener('click', () => {
    if (activeProtocol === 'h2') return;
    activeProtocol = 'h2';
    http2TabBtn.classList.add('active');
    tlsTabBtn.classList.remove('active');
    quicTabBtn.classList.remove('active');
    tcpTabBtn.classList.remove('active');
    updateWorkerConstraints();
    filterScenariosBySide();
  });

  quicTabBtn.addEventListener('click', () => {
    if (activeProtocol === 'quic') return;
    activeProtocol = 'quic';
    quicTabBtn.classList.add('active');
    tlsTabBtn.classList.remove('active');
    http2TabBtn.classList.remove('active');
    tcpTabBtn.classList.remove('active');
    updateWorkerConstraints();
    filterScenariosBySide();
  });

  tcpTabBtn.addEventListener('click', () => {
    if (activeProtocol === 'raw-tcp') return;
    activeProtocol = 'raw-tcp';
    tcpTabBtn.classList.add('active');
    tlsTabBtn.classList.remove('active');
    http2TabBtn.classList.remove('active');
    quicTabBtn.classList.remove('active');
    updateWorkerConstraints();
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
      warning.style.cssText = 'padding: 12px; margin: 8px; background: #3a2a00; border: 1px solid #665500; border-radius: 6px; color: #ffcc00; font-size: 12px;';
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

  // Run
  runBtn.addEventListener('click', async () => {
    if (running) return;

    if (distributedMode) {
      return runDistributed();
    }

    const mode = modeSelect.value;
    const host = hostInput.value.trim();
    const port = parseInt(portInput.value, 10);
    const delay = parseInt(delayInput.value, 10) || 100;
    const timeout = parseInt(timeoutInput.value, 10) || 5000;
    const verbose = verboseCheck.checked;
    
    let workers = parseInt(workersInput.value, 10) || 1;
    const maxWorkers = window.fuzzer.cpuCount || 10;
    if (workers > maxWorkers) {
      alert(`Requested threads (${workers}) exceed the available CPU cores (${maxWorkers}).`);
      workersInput.value = maxWorkers;
      return;
    }
    if (workers < 1) {
      workers = 1;
      workersInput.value = 1;
    }

    const dut = dutCheck.checked ? {
      ip: dutIpInput.value.trim(),
      authType: dutAuthType.value,
      user: dutUserInput.value.trim(),
      pass: dutPassInput.value,
      apiKey: dutApiKeyInput.value.trim(),
    } : null;

    if (!port || port < 1 || port > 65535) {
      addLogEntry('error', 'Invalid port number');
      return;
    }

    // HTTP/2 or QUIC passive server mode: no scenarios needed (just starts the server)
    const isPassiveServer = (activeProtocol === 'h2' || activeProtocol === 'quic') && mode === 'server' && getSelectedScenarios().length === 0;

    if (!isPassiveServer) {
      if (mode === 'client' && !host && !localMode) {
        addLogEntry('error', 'Please enter a hostname');
        return;
      }
      if ((activeProtocol !== 'h2' && activeProtocol !== 'quic') || mode !== 'server') {
        // For non-server-mode or TLS, require at least one scenario
        const scenarioNames = getSelectedScenarios();
        if (scenarioNames.length === 0) {
          addLogEntry('error', 'No scenarios selected');
          return;
        }
      }
    }

    const scenarioNames = getSelectedScenarios();
    const loopCount = Math.max(1, Math.min(1000, parseInt(loopCountInput.value, 10) || 1));
    const totalScenarios = (scenarioNames.length || (isPassiveServer ? 1 : 0)) * loopCount;

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

    // Open firewall monitor popup in DUT mode
    if (dut && dut.ip) {
      window.fuzzer.openFirewall(dut);
    }

    // Subscribe to events
    unsubPacket = window.fuzzer.onPacket((evt) => {
      handlePacketEvent(evt);
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

    try {
      const response = await window.fuzzer.run({
        mode, host: localMode ? 'localhost' : host, port, scenarioNames, delay, timeout,
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
    for (const cb of checkboxes) {
      if (cb.dataset.side === 'client') clientScenarios.push(cb.value);
      else if (cb.dataset.side === 'server') serverScenarios.push(cb.value);
    }

    if (clientScenarios.length === 0 && serverScenarios.length === 0) {
      addLogEntry('error', 'No scenarios selected');
      return;
    }

    // Validate that required agents are connected
    const needClient = clientScenarios.length > 0 || serverScenarios.length > 0;
    const needServer = serverScenarios.length > 0 || clientScenarios.length > 0;
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
    let wbClient = 'well-behaved-client';
    if (activeProtocol === 'h2') {
      wbServer = 'well-behaved-h2-server';
      wbClient = 'well-behaved-h2-client';
    } else if (activeProtocol === 'quic') {
      wbServer = 'srv-quic-well-behaved-echo';
      wbClient = 'well-behaved-quic-client';
    }

    if (clientScenarios.length > 0 && serverScenarios.length === 0) {
      // Phase: Client Fuzzing only
      clientScenariosFinal.push(...clientScenarios);
      for (let i = 0; i < clientScenarios.length; i++) {
        serverScenariosFinal.push(wbServer);
      }
    } else if (serverScenarios.length > 0 && clientScenarios.length === 0) {
      // Phase: Server Fuzzing only
      serverScenariosFinal.push(...serverScenarios);
      for (let i = 0; i < serverScenarios.length; i++) {
        clientScenariosFinal.push(wbClient);
      }
    } else if (clientScenarios.length > 0 && serverScenarios.length > 0) {
      // Combined Phase: Client Fuzzing followed by Server Fuzzing
      // 1. Client Fuzzing Batch
      clientScenariosFinal.push(...clientScenarios);
      for (let i = 0; i < clientScenarios.length; i++) {
        serverScenariosFinal.push(wbServer);
      }
      // 2. Server Fuzzing Batch
      serverScenariosFinal.push(...serverScenarios);
      for (let i = 0; i < serverScenarios.length; i++) {
        clientScenariosFinal.push(wbClient);
      }
    }

    const dut = dutCheck.checked ? {
      ip: dutIpInput.value.trim(),
      authType: dutAuthType.value,
      user: dutUserInput.value.trim(),
      pass: dutPassInput.value,
      apiKey: dutApiKeyInput.value.trim(),
    } : null;

    setRunning(true);
    results = [];
    logFileHeader = false;
    resultsBody.innerHTML = '';
    resultsEmpty.style.display = 'none';
    resultsTable.style.display = 'table';
    summaryBar.style.display = 'none';
    progressContainer.style.display = 'flex';
    progressBar.style.width = '0%';
    const totalScenarios = clientScenarios.length + serverScenarios.length;
    progressText.textContent = `0 / ${totalScenarios}`;

    // Open firewall monitor popup in DUT mode
    if (dut && dut.ip) {
      window.fuzzer.openFirewall(dut);
    }

    const workers = parseInt(workersInput.value, 10) || 1;

    // Configure agents
    addLogEntry('info', `Configuring agents: ${clientScenarios.length} client, ${serverScenarios.length} server scenarios`);

    try {
      const configResult = await window.fuzzer.distributedConfigure({
        clientScenarios: clientScenariosFinal.length > 0 ? clientScenariosFinal : null,
        serverScenarios: serverScenariosFinal.length > 0 ? serverScenariosFinal : null,
        clientConfig: { host, port, delay, timeout, workers, protocol: activeProtocol, dut, pcapFile: pcapFile || null, mergePcap: !!pcapFile, baseline: baselineCheck.checked },
        serverConfig: { hostname: host, port, delay, timeout, workers: 1, protocol: activeProtocol, dut, pcapFile: pcapFile || null, mergePcap: !!pcapFile, baseline: baselineCheck.checked },
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
    let agentsDone = { client: !clientScenariosFinal.length, server: !serverScenariosFinal.length };

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
      const totalPairs = clientScenariosFinal.length; // Both lists are same length by construction
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
    // Hide well-behaved counterpart results — they are internal helpers, not actual tests
    if (result.scenario && result.scenario.includes('well-behaved')) {
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
          content += `--- Protocol Fuzzer Run Log: ${new Date().toISOString()} ---\n`;
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
    tr.innerHTML = `
      <td class="num">${idx}</td>
      <td>${_escHtml(scenario)}</td>
      <td>${_escHtml(cat)}</td>
      <td><span class="status-badge status-${status}">${status}</span>${downBadge}</td>
      <td style="font-size: 11px; color: var(--text-secondary);${noBaseline ? ' opacity: 0.35;' : ''}">${noBaseline ? (isH2 ? 'N/A (HTTP/2)' : 'N/A (QUIC)') : _escHtml(baseline)}</td>
      <td>${healthHtml}</td>
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
      statusBadge.textContent = distributedMode ? 'DISTRIBUTED RUN' : 'RUNNING';
      statusBadge.className = 'header-status running';
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
