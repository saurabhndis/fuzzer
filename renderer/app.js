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

  // State
  let running = false;
  let pcapFile = null;
  let results = [];
  let allScenarios = {};
  let categories = {};
  let unsubPacket = null;
  let unsubResult = null;
  let unsubProgress = null;
  let unsubReport = null;
  let lastReport = null;

  // Mode toggle — hide host for server mode
  modeSelect.addEventListener('change', () => {
    hostGroup.style.display = modeSelect.value === 'server' ? 'none' : 'flex';
    filterScenariosBySide();
  });

  // Load scenarios
  async function loadScenarios() {
    const data = await window.fuzzer.listScenarios();
    categories = data.categories;
    allScenarios = data.scenarios;
    renderScenarios();
  }

  function renderScenarios() {
    scenariosList.innerHTML = '';
    const side = modeSelect.value;

    for (const [cat, label] of Object.entries(categories)) {
      const items = (allScenarios[cat] || []).filter(s => s.side === side);
      if (items.length === 0) continue;

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
    renderScenarios();
  }

  function getSelectedScenarios() {
    const checkboxes = scenariosList.querySelectorAll('input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(cb => cb.value);
  }

  function setAllCheckboxes(checked) {
    const checkboxes = scenariosList.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(cb => { cb.checked = checked; });
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

    const scenarioNames = getSelectedScenarios();
    if (scenarioNames.length === 0) {
      addLogEntry('error', 'No scenarios selected');
      return;
    }

    const mode = modeSelect.value;
    const host = hostInput.value.trim();
    const port = parseInt(portInput.value, 10);
    const delay = parseInt(delayInput.value, 10) || 100;
    const timeout = parseInt(timeoutInput.value, 10) || 5000;
    const verbose = verboseCheck.checked;

    if (mode === 'client' && !host) {
      addLogEntry('error', 'Please enter a hostname');
      return;
    }
    if (!port || port < 1 || port > 65535) {
      addLogEntry('error', 'Invalid port number');
      return;
    }

    setRunning(true);
    results = [];
    resultsBody.innerHTML = '';
    resultsEmpty.style.display = 'none';
    resultsTable.style.display = 'table';
    summaryBar.style.display = 'none';
    progressContainer.style.display = 'flex';
    progressBar.style.width = '0%';
    progressText.textContent = `0 / ${scenarioNames.length}`;

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

  // Stop
  stopBtn.addEventListener('click', async () => {
    if (!running) return;
    await window.fuzzer.stop();
    addLogEntry('info', 'Stop requested...');
  });

  // Handle incoming packet events from the fuzzer
  function handlePacketEvent(evt) {
    switch (evt.type) {
      case 'scenario':
        addLogEntry('scenario-name', `--- ${evt.name}: ${evt.description} ---`);
        break;
      case 'sent':
        addLogEntry('sent', `\u2192 ${evt.label || 'Sent'} (${evt.size} bytes)`);
        if (evt.hex) addHexDump(evt.hex);
        break;
      case 'received':
        addLogEntry('received', `\u2190 ${evt.description || 'Received'} (${evt.size} bytes)`);
        if (evt.hex) addHexDump(evt.hex);
        break;
      case 'tcp':
        addLogEntry('tcp', `[TCP] ${evt.direction === 'sent' ? '\u2192' : '\u2190'} ${evt.flag}`);
        break;
      case 'fuzz':
        addLogEntry('fuzz', `[FUZZ] ${evt.message}`);
        break;
      case 'info':
        addLogEntry('info', evt.message);
        break;
      case 'error':
        addLogEntry('error', evt.message);
        break;
      case 'result': {
        const cls = evt.status === 'PASSED' ? 'pass' : 'fail';
        const downStr = evt.hostDown ? ' [HOST DOWN]' : '';
        addLogEntry(`result-line ${cls}`, `Result: ${evt.scenario} \u2014 ${evt.status} \u2014 ${evt.response}${downStr}`);
        break;
      }
      case 'host-down':
        addLogEntry('host-down', `!! HOST DOWN — ${evt.host}:${evt.port} unreachable after "${evt.scenario}" — possible crash/DoS !!`);
        break;
      case 'health-probe': {
        const tcp = evt.probe.tcp;
        const ht = evt.probe.https;
        const tcpStr = tcp.alive ? `TCP OK (${tcp.latency}ms)` : `TCP FAIL (${tcp.error})`;
        const htStr = ht.alive ? `HTTPS OK (${ht.statusCode} ${ht.tlsVersion} ${ht.cipher} ${ht.latency}ms)` : `HTTPS FAIL (${ht.error})`;
        addLogEntry('health-probe', `Health: ${tcpStr}  |  ${htStr}`);
        break;
      }
      default:
        addLogEntry('info', JSON.stringify(evt));
    }
  }

  // Look up scenario metadata from loaded data
  function findScenarioMeta(name) {
    for (const items of Object.values(allScenarios)) {
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
    modeSelect.disabled = state;
    hostInput.disabled = state;
    portInput.disabled = state;

    if (state) {
      statusBadge.textContent = 'RUNNING';
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
