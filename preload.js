const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('fuzzer', {
  listScenarios: () => ipcRenderer.invoke('list-scenarios'),
  run: (opts) => ipcRenderer.invoke('run-fuzzer', opts),
  stop: () => ipcRenderer.invoke('stop-fuzzer'),
  savePcapDialog: () => ipcRenderer.invoke('save-pcap-dialog'),
  onPacket: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('fuzzer-packet', listener);
    return () => ipcRenderer.removeListener('fuzzer-packet', listener);
  },
  onResult: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('fuzzer-result', listener);
    return () => ipcRenderer.removeListener('fuzzer-result', listener);
  },
  onProgress: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('fuzzer-progress', listener);
    return () => ipcRenderer.removeListener('fuzzer-progress', listener);
  },
  onReport: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('fuzzer-report', listener);
    return () => ipcRenderer.removeListener('fuzzer-report', listener);
  },

  // Distributed mode
  distributedConnect: (opts) => ipcRenderer.invoke('distributed-connect', opts),
  distributedConfigure: (opts) => ipcRenderer.invoke('distributed-configure', opts),
  distributedRun: () => ipcRenderer.invoke('distributed-run'),
  distributedStop: () => ipcRenderer.invoke('distributed-stop'),
  distributedStatus: (role) => ipcRenderer.invoke('distributed-status', role),
  distributedDisconnect: () => ipcRenderer.invoke('distributed-disconnect'),
  distributedResults: (role) => ipcRenderer.invoke('distributed-results', role),
  onAgentDone: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('distributed-agent-done', listener);
    return () => ipcRenderer.removeListener('distributed-agent-done', listener);
  },
  onAgentStatus: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('distributed-agent-status', listener);
    return () => ipcRenderer.removeListener('distributed-agent-status', listener);
  },

  // Firewall monitor
  openFirewall: (dutConfig) => ipcRenderer.invoke('open-firewall', dutConfig),
  closeFirewall: () => ipcRenderer.invoke('close-firewall'),
});

// PAN-OS Firewall API (used by the firewall popup window)
contextBridge.exposeInMainWorld('panos', {
  ping: (args) => ipcRenderer.invoke('panos:ping', args),
  getApiKey: (args) => ipcRenderer.invoke('panos:getApiKey', args),
  runCommand: (args) => ipcRenderer.invoke('panos:runCommand', args),
  runConfig: (args) => ipcRenderer.invoke('panos:runConfig', args),
  systemInfo: (args) => ipcRenderer.invoke('panos:systemInfo', args),
  onDutConfig: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('dut-config', listener);
    return () => ipcRenderer.removeListener('dut-config', listener);
  },
});
