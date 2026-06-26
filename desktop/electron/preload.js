'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('oyster', {
  rpc: (method, params) => ipcRenderer.invoke('rpc', method, params),
  chooseFolder: () => ipcRenderer.invoke('choose-folder'),
  confirm: (opts) => ipcRenderer.invoke('confirm', opts),
  onEvent: (cb) => ipcRenderer.on('engine-event', (_e, msg) => cb(msg)),
});
