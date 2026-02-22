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
  const verboseCheck = document.getElementById('verboseCheck');
  const scenariosList = document.getElementById('scenariosList');
  const selectAllBtn = document.getElementById('selectAllBtn');
  const selectNoneBtn = document.getElementById('selectNoneBtn');
  const runBtn = document.getElementById('runBtn');
  const stopBtn = document.getElementById('stopBtn');
  const pcapBtn = document.getElementById('pcapBtn');
  const pcapPathEl = document.getElementById('pcapPath');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  const resultsTable = document.getElementById('resultsTable');
  const resultsBody = document.getElementById('resultsBody');
  const resultsEmpty = document.getElementById('resultsEmpty');
  const exportJsonBtn = document.getElementById('exportJsonBtn');
  const clearResultsBtn = document.getElementById('clearResultsBtn');
  const packetLog = document.getElementById('packetLog');
  const clearLogBtn = document.getElementById('clearLogBtn');
  const summaryBar = document.getElementById('summaryBar');
  const summaryText = document.getElementById('summaryText');
  const statusBadge = document.getElementById('statusBadge');
  const distributedCheck = document.getElementById('distributedCheck');
  const distributedBar = document.getElementById('distributedBar');
  const clientAgentHost = document.getElementById('clientAgentHost');
  const clientAgentPort = document.getElementById('clientAgentPort');
  const serverAgentHost = document.getElementById('serverAgentHost');
  const serverAgentPort = document.getElementById('serverAgentPort');
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

  // Protocol tab elements
  const tlsTabBtn = document.getElementById('tlsTabBtn');
  const http2TabBtn = document.getElementById('http2TabBtn');
  const quicTabBtn = document.getElementById('quicTabBtn');

  // State
  let running = false;
  let pcapFile = null;
  let results = [];
  let allScenarios = {};
  let categories = {};
  let defaultDisabled = new Set();
  let allH2Scenarios = {};
  let h2Categories = {};
  let h2DefaultDisabled = new Set();
  let allQuicScenarios = {};
  let quicCategories = {};
  let quicDefaultDisabled = new Set();
  let activeProtocol = 'tls'; // 'tls' | 'h2' | 'quic'
  let unsubPacket = null;
  let unsubResult = null;
  let unsubProgress = null;
  let unsubReport = null;
  let lastReport = null;
  let distributedMode = false;
  let agentsConnected = false;
  let unsubAgentDone = null;
  let unsubAgentStatus = null;
  let statusPollTimer = null;

  // Mode toggle — hide host for server mode
  modeSelect.addEventListener('change', () => {
    if (!distributedMode) {
      hostGroup.style.display = modeSelect.value === 'server' ? 'none' : 'flex';
    }
    filterScenariosBySide();
  });

  // Distributed mode toggle
  distributedCheck.addEventListener('change', () => {
    distributedMode = distributedCheck.checked;
    distributedBar.style.display = distributedMode ? 'flex' : 'none';
    if (distributedMode) {
      // In distributed mode, show all scenarios (both sides)
      modeSelect.disabled = true;
      hostGroup.style.display = 'none';
      renderAllScenarios();
    } else {
      modeSelect.disabled = false;
      hostGroup.style.display = modeSelect.value === 'server' ? 'none' : 'flex';
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

  // Connect to remote agents
  connectBtn.addEventListener('click', handleConnect);
  disconnectBtn.addEventListener('click', handleDisconnect);

  async function handleConnect() {
    const cHost = clientAgentHost.value.trim();
    const cPort = clientAgentPort.value.trim();
    const sHost = serverAgentHost.value.trim();
    const sPort = serverAgentPort.value.trim();

    if (!cHost && !sHost) {
      addLogEntry('error', 'Enter at least one agent address');
      return;
    }

    setAgentStatus('client', 'connecting');
    setAgentStatus('server', 'connecting');
    connectBtn.disabled = true;

    try {
      const result = await window.fuzzer.distributedConnect({
        clientHost: cHost || null,
        clientPort: cPort || null,
        serverHost: sHost || null,
        serverPort: sPort || null,
      });

      if (result.client) {
        setAgentStatus('client', result.client.status || 'idle');
        addLogEntry('info', `Client agent connected: ${cHost}:${cPort} (${result.client.status})`);
      } else if (result.clientError) {
        setAgentStatus('client', 'error');
        addLogEntry('error', `Client agent: ${result.clientError}`);
      } else if (!cHost) {
        setAgentStatus('client', 'idle');
      }

      if (result.server) {
        setAgentStatus('server', result.server.status || 'idle');
        addLogEntry('info', `Server agent connected: ${sHost}:${sPort} (${result.server.status})`);
      } else if (result.serverError) {
        setAgentStatus('server', 'error');
        addLogEntry('error', `Server agent: ${result.serverError}`);
      } else if (!sHost) {
        setAgentStatus('server', 'idle');
      }

      const anyConnected = result.client || result.server;
      if (anyConnected) {
        agentsConnected = true;
        disconnectBtn.disabled = false;
        clientAgentHost.disabled = true;
        clientAgentPort.disabled = true;
        serverAgentHost.disabled = true;
        serverAgentPort.disabled = true;
        startStatusPolling();
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
    setAgentStatus('client', 'idle');
    setAgentStatus('server', 'idle');
    connectBtn.disabled = false;
    disconnectBtn.disabled = true;
    clientAgentHost.disabled = false;
    clientAgentPort.disabled = false;
    serverAgentHost.disabled = false;
    serverAgentPort.disabled = false;
    addLogEntry('info', 'Disconnected from agents');
  }

  function setAgentStatus(role, status) {
    const dot = role === 'client' ? clientStatusDot : serverStatusDot;
    const text = role === 'client' ? clientStatusText : serverStatusText;
    dot.className = `agent-status-dot agent-${status}`;
    text.textContent = status.toUpperCase();
  }

  function startStatusPolling() {
    stopStatusPolling();
    statusPollTimer = setInterval(async () => {
      if (!agentsConnected) return;
      try {
        const cStatus = await window.fuzzer.distributedStatus('client');
        if (cStatus && !cStatus.error) setAgentStatus('client', cStatus.status);
        const sStatus = await window.fuzzer.distributedStatus('server');
        if (sStatus && !sStatus.error) setAgentStatus('server', sStatus.status);
      } catch (_) {}
    }, 3000);
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
    filterScenariosBySide();
  });

  http2TabBtn.addEventListener('click', () => {
    if (activeProtocol === 'h2') return;
    activeProtocol = 'h2';
    http2TabBtn.classList.add('active');
    tlsTabBtn.classList.remove('active');
    quicTabBtn.classList.remove('active');
    filterScenariosBySide();
  });

  quicTabBtn.addEventListener('click', () => {
    if (activeProtocol === 'quic') return;
    activeProtocol = 'quic';
    quicTabBtn.classList.add('active');
    tlsTabBtn.classList.remove('active');
    http2TabBtn.classList.remove('active');
    filterScenariosBySide();
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
      renderScenarios();
    } catch (err) {
      console.error('Failed to load scenarios:', err);
    }
  }

  function renderScenarios() {
    console.log('Rendering scenarios for protocol:', activeProtocol, 'side:', modeSelect.value);
    scenariosList.innerHTML = '';
    const side = modeSelect.value;

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
      header.innerHTML = `<span class="arrow">&#9660;</span> ${cat}: ${label} <span class="count">${items.length}</span>${disabledTag}`;

      const itemsDiv = document.createElement('div');
      itemsDiv.className = 'category-items';

      header.addEventListener('click', () => {
        const arrow = header.querySelector('.arrow');
        itemsDiv.classList.toggle('collapsed');
        arrow.classList.toggle('collapsed');
      });

      for (const s of items) {
        const item = document.createElement('label');
        item.className = 'scenario-item';
        item.title = s.description;

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = s.name;
        cb.dataset.side = s.side;
        cb.dataset.category = cat;

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
    header.innerHTML = `<span class="arrow">&#9660;</span> ${cat}: ${label} <span class="count">${items.length}</span>`;

    const itemsDiv = document.createElement('div');
    itemsDiv.className = 'category-items';

    header.addEventListener('click', () => {
      const arrow = header.querySelector('.arrow');
      itemsDiv.classList.toggle('collapsed');
      arrow.classList.toggle('collapsed');
    });

    for (const s of items) {
      const item = document.createElement('label');
      item.className = 'scenario-item';
      item.title = s.description;

      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = s.name;
      cb.dataset.side = s.side;
      cb.dataset.category = cat;
      cb.dataset.protocol = protocol;

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

  // Render all scenarios (both client and server) for distributed mode.
  // Respects activeProtocol — shows TLS or H2 scenarios depending on the active tab.
  function renderAllScenarios() {
    scenariosList.innerHTML = '';

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
      const items = allScenarios[cat] || [];
      if (items.length === 0) continue;

      const group = document.createElement('div');
      group.className = 'category-group';

      const header = document.createElement('div');
      header.className = 'category-header';
      const disabledTag = defaultDisabled.has(cat)
        ? ' <span class="opt-in-tag">opt-in</span>'
        : '';
      header.innerHTML = `<span class="arrow">&#9660;</span> ${cat}: ${label} <span class="count">${items.length}</span>${disabledTag}`;

      const itemsDiv = document.createElement('div');
      itemsDiv.className = 'category-items';

      header.addEventListener('click', () => {
        const arrow = header.querySelector('.arrow');
        itemsDiv.classList.toggle('collapsed');
        arrow.classList.toggle('collapsed');
      });

      for (const s of items) {
        const item = document.createElement('label');
        item.className = 'scenario-item';
        item.title = s.description;

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = s.name;
        cb.dataset.side = s.side;
        cb.dataset.category = cat;

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

  function setAllCheckboxes(checked) {
    const checkboxes = scenariosList.querySelectorAll('input[type="checkbox"]');
    let disabled = defaultDisabled;
    if (activeProtocol === 'h2') disabled = h2DefaultDisabled;
    if (activeProtocol === 'quic') disabled = quicDefaultDisabled;

    checkboxes.forEach(cb => {
      if (checked && disabled.has(cb.dataset.category)) return;
      cb.checked = checked;
    });
  }

  selectAllBtn.addEventListener('click', () => setAllCheckboxes(true));
  selectNoneBtn.addEventListener('click', () => setAllCheckboxes(false));

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
      if (mode === 'client' && !host) {
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
    const totalScenarios = scenarioNames.length || (isPassiveServer ? 1 : 0);

    setRunning(true);
    results = [];
    resultsBody.innerHTML = '';
    resultsEmpty.style.display = 'none';
    resultsTable.style.display = 'table';
    summaryBar.style.display = 'none';
    progressContainer.style.display = isPassiveServer ? 'none' : 'flex';
    progressBar.style.width = '0%';
    progressText.textContent = `0 / ${totalScenarios}`;

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
        mode, host, port, scenarioNames, delay, timeout,
        pcapFile: pcapFile || null,
        verbose,
        protocol: activeProtocol,
        dut,
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

    const host = hostInput.value.trim() || 'localhost';
    const port = parseInt(portInput.value, 10) || 443;
    const delay = parseInt(delayInput.value, 10) || 100;
    const timeout = parseInt(timeoutInput.value, 10) || 5000;

    const dut = dutCheck.checked ? {
      ip: dutIpInput.value.trim(),
      authType: dutAuthType.value,
      user: dutUserInput.value.trim(),
      pass: dutPassInput.value,
      apiKey: dutApiKeyInput.value.trim(),
    } : null;

    setRunning(true);
    results = [];
    resultsBody.innerHTML = '';
    resultsEmpty.style.display = 'none';
    resultsTable.style.display = 'table';
    summaryBar.style.display = 'none';
    progressContainer.style.display = 'flex';
    progressBar.style.width = '0%';
    const totalScenarios = clientScenarios.length + serverScenarios.length;
    progressText.textContent = `0 / ${totalScenarios}`;

    // Configure agents
    addLogEntry('info', `Configuring agents: ${clientScenarios.length} client, ${serverScenarios.length} server scenarios`);

    try {
      const configResult = await window.fuzzer.distributedConfigure({
        clientScenarios: clientScenarios.length > 0 ? clientScenarios : null,
        serverScenarios: serverScenarios.length > 0 ? serverScenarios : null,
        clientConfig: { host, port, delay, timeout, protocol: activeProtocol, dut },
        serverConfig: { hostname: host, port: parseInt(portInput.value, 10) || 4433, delay, timeout, protocol: activeProtocol, dut },
      });

      if (configResult.error) {
        addLogEntry('error', `Configure failed: ${configResult.error}`);
        setRunning(false);
        progressContainer.style.display = 'none';
        return;
      }

      addLogEntry('info', 'Agents configured — both ready');
      setAgentStatus('client', 'ready');
      setAgentStatus('server', 'ready');
    } catch (err) {
      addLogEntry('error', `Configure failed: ${err.message || err}`);
      setRunning(false);
      progressContainer.style.display = 'none';
      return;
    }

    // Subscribe to events
    let agentsDone = { client: !clientScenarios.length, server: !serverScenarios.length };

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

    // Trigger execution
    try {
      addLogEntry('info', 'Starting distributed execution...');
      const runResult = await window.fuzzer.distributedRun();
      if (runResult.error) {
        addLogEntry('error', `Run failed: ${runResult.error}`);
        finishDistributedRun();
      }
    } catch (err) {
      addLogEntry('error', `Run failed: ${err.message || err}`);
      finishDistributedRun();
    }
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
    const p = rolePrefix || '';
    switch (evt.type) {
      case 'scenario':
        addLogEntry('scenario-name', `${p}--- ${evt.name}: ${evt.description} ---`);
        break;
      case 'sent':
        addLogEntry('sent', `${p}\u2192 ${evt.label || 'Sent'} (${evt.size} bytes)`);
        if (evt.hex) addHexDump(evt.hex);
        break;
      case 'received':
        addLogEntry('received', `${p}\u2190 ${evt.description || 'Received'} (${evt.size} bytes)`);
        if (evt.hex) addHexDump(evt.hex);
        break;
      case 'tcp':
        addLogEntry('tcp', `${p}[TCP] ${evt.direction === 'sent' ? '\u2192' : '\u2190'} ${evt.flag}`);
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
        const tcp = evt.probe.tcp;
        const ht = evt.probe.https;
        const tcpStr = tcp.alive ? `TCP OK (${tcp.latency}ms)` : `TCP FAIL (${tcp.error})`;
        const htStr = ht.alive ? `HTTPS OK (${ht.statusCode} ${ht.tlsVersion} ${ht.cipher} ${ht.latency}ms)` : `HTTPS FAIL (${ht.error})`;
        addLogEntry('health-probe', `${p}Health: ${tcpStr}  |  ${htStr}`);
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
    const tcp = probe.tcp || {};
    const ht = probe.https || {};
    const tcpCls = tcp.alive ? 'probe-ok' : 'probe-fail';
    const htCls = ht.alive ? 'probe-ok' : 'probe-fail';
    const tcpLabel = tcp.alive ? `OK ${tcp.latency}ms` : `FAIL`;
    const htLabel = ht.alive ? `${ht.statusCode} ${ht.latency}ms` : `FAIL`;
    const tcpTitle = tcp.alive ? `TCP connected in ${tcp.latency}ms` : `TCP failed: ${tcp.error}`;
    const htTitle = ht.alive
      ? `HTTPS ${ht.statusCode} | ${ht.tlsVersion} | ${ht.cipher} | ${ht.latency}ms`
      : `HTTPS failed: ${ht.error}`;
    return `<span class="probe-badge ${tcpCls}" title="${escapeHtml(tcpTitle)}">TCP ${tcpLabel}</span>` +
           `<span class="probe-badge ${htCls}" title="${escapeHtml(htTitle)}">HTTPS ${htLabel}</span>`;
  }

  function renderFindingCell(finding) {
    if (!finding) return '<span class="finding-badge finding-INFO">—</span>';
    const title = finding.reason ? escapeHtml(finding.reason) : '';
    const sevHtml = finding.severity
      ? `<span class="severity-badge sev-${finding.severity}">${finding.severity}</span>`
      : '';
    return `<span class="finding-badge finding-${finding.grade}" title="${title}">${finding.grade}</span>${sevHtml}`;
  }

  function handleResult(result) {
    const meta = findScenarioMeta(result.scenario);
    const expected = meta ? meta.expected : null;
    const expectedReason = meta ? meta.expectedReason : '';
    const { verdict, cls: verdictCls } = computeVerdict(result.status, expected);

    result.expected = expected;
    result.expectedReason = expectedReason;
    result.verdict = verdict;
    results.push(result);

    const idx = results.length;
    const scenario = result.scenario || '?';
    const status = result.status || '?';
    const response = result.response || '';
    const cat = meta ? meta.category : '?';
    const hostDown = result.hostDown || false;

    const tr = document.createElement('tr');
    const verdictTitle = expectedReason ? `Expected: ${expected} — ${expectedReason}` : '';
    const downBadge = hostDown ? '<span class="host-down-badge" title="Target became unreachable — possible crash/DoS">DOWN</span>' : '';
    const healthHtml = renderHealthCell(result.probe, hostDown);
    const findingHtml = renderFindingCell(result.finding);
    tr.innerHTML = `
      <td class="num">${idx}</td>
      <td>${escapeHtml(scenario)}</td>
      <td>${escapeHtml(cat)}</td>
      <td><span class="status-badge status-${status}">${status}</span>${downBadge}</td>
      <td>${healthHtml}</td>
      <td>${findingHtml}</td>
      <td><span class="verdict-badge verdict-${verdictCls}" title="${escapeHtml(verdictTitle)}">${verdict}</span></td>
      <td>${escapeHtml(response)}</td>
    `;
    resultsBody.appendChild(tr);
    tr.scrollIntoView({ block: 'nearest' });
    exportJsonBtn.disabled = false;
  }

  function handleProgress(prog) {
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
    const tcpOk = results.filter(r => r.probe && r.probe.tcp && r.probe.tcp.alive).length;
    const httpsOk = results.filter(r => r.probe && r.probe.https && r.probe.https.alive).length;
    const asExpected = results.filter(r => r.verdict === 'AS EXPECTED').length;
    const unexpected = results.filter(r => r.verdict === 'UNEXPECTED').length;

    // Grade banner
    let gradeBannerHtml = '';
    if (lastReport) {
      const r = lastReport;
      gradeBannerHtml = `
        <span class="grade-badge grade-${r.grade}">${r.grade}</span>
        <span class="grade-label">${escapeHtml(r.label)}</span>
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
      ${probed > 0 ? `<span style="margin-left:12px">|</span><span class="probe-summary">TCP ${tcpOk}/${probed}</span><span class="probe-summary">HTTPS ${httpsOk}/${probed}</span>` : ''}
      <span style="margin-left:12px">|</span>
      <span class="as-expected">As Expected: ${asExpected}</span>
      <span class="unexpected-count">Unexpected: ${unexpected}</span>
    `;

    const hasDown = hostDownCount > 0;
    const gradeStr = lastReport ? ` [Grade: ${lastReport.grade}]` : '';
    statusBadge.textContent = hasDown ? 'DONE (HOST DOWN)' : errors > 0 ? 'DONE (ERRORS)' : `DONE${gradeStr}`;
    statusBadge.className = hasDown ? 'header-status error' : 'header-status done';
  }

  // UI state management
  function setRunning(state) {
    running = state;
    runBtn.disabled = state;
    stopBtn.disabled = !state;
    modeSelect.disabled = state || distributedMode;
    hostInput.disabled = state;
    portInput.disabled = state;
    distributedCheck.disabled = state;

    if (distributedMode) {
      connectBtn.disabled = state || agentsConnected;
      disconnectBtn.disabled = state || !agentsConnected;
    }

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

  // Clear buttons
  clearResultsBtn.addEventListener('click', () => {
    results = [];
    lastReport = null;
    resultsBody.innerHTML = '';
    resultsEmpty.style.display = 'block';
    resultsTable.style.display = 'table';
    exportJsonBtn.disabled = true;
    summaryBar.style.display = 'none';
    statusBadge.textContent = 'IDLE';
    statusBadge.className = 'header-status';
  });

  clearLogBtn.addEventListener('click', () => {
    packetLog.innerHTML = '<div class="log-empty">Waiting for packets...</div>';
  });

  // Utility
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Init
  loadScenarios();
})();
