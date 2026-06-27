'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('oyster', {
  rpc: (method, params) => ipcRenderer.invoke('rpc', method, params),
  chooseFolder: () => ipcRenderer.invoke('choose-folder'),
  confirm: (opts) => ipcRenderer.invoke('confirm', opts),
  openFDA: () => ipcRenderer.invoke('open-fda'),
  setTheme: (mode) => ipcRenderer.invoke('set-theme', mode),
  reveal: (p) => ipcRenderer.invoke('reveal', p),
  setBusy: (b) => ipcRenderer.send('set-busy', b),
  onEvent: (cb) => ipcRenderer.on('engine-event', (_e, msg) => cb(msg)),
});
