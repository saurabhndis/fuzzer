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
});
