'use strict';
// Oyster — Electron main process.
// Spawns the Python engine sidecar (stdio JSON-RPC), makes the frosted-glass
// window, and relays RPC + streamed progress events to the renderer.

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

let win = null;
let engine = null;
let nextId = 1;
const pending = new Map(); // id -> {resolve, reject}

function repoRoot() {
  // desktop/electron/main.js -> repo root
  return path.join(__dirname, '..', '..');
}

function engineCommand() {
  if (app.isPackaged) {
    // PyInstaller onedir bundle: engine/oyster-engine/oyster-engine(.exe)
    const exe = process.platform === 'win32' ? 'oyster-engine.exe' : 'oyster-engine';
    return { cmd: path.join(process.resourcesPath, 'engine', 'oyster-engine', exe), args: [], opts: {} };
  }
  // dev: run the sidecar with the project venv interpreter
  const py = process.platform === 'win32'
    ? path.join(repoRoot(), '.venv', 'Scripts', 'python.exe')
    : path.join(repoRoot(), '.venv', 'bin', 'python');
  return { cmd: py, args: ['-m', 'sidecar.server'], opts: { cwd: repoRoot() } };
}

function startEngine() {
  const { cmd, args, opts } = engineCommand();
  engine = spawn(cmd, args, { ...opts, stdio: ['pipe', 'pipe', 'pipe'] });
  engine.on('error', (e) => console.error('engine spawn error', e));
  engine.stderr.on('data', (d) => console.error('[engine]', d.toString()));

  const rl = readline.createInterface({ input: engine.stdout });
  rl.on('line', (line) => {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (msg.event) {                       // streamed event (progress)
      if (win) win.webContents.send('engine-event', msg);
      return;
    }
    const p = pending.get(msg.id);         // response to a request
    if (!p) return;
    pending.delete(msg.id);
    msg.ok ? p.resolve(msg.result) : p.reject(new Error(msg.error));
  });

  engine.on('exit', (code) => {
    for (const p of pending.values()) p.reject(new Error('engine exited ' + code));
    pending.clear();
  });
}

function rpc(method, params) {
  return new Promise((resolve, reject) => {
    if (!engine || engine.killed) return reject(new Error('engine not running'));
    const id = nextId++;
    pending.set(id, { resolve, reject });
    engine.stdin.write(JSON.stringify({ id, method, params: params || {} }) + '\n');
  });
}

function createWindow() {
  const mac = process.platform === 'darwin';
  const win32 = process.platform === 'win32';
  win = new BrowserWindow({
    width: 1280, height: 840, minWidth: 1060, minHeight: 700,
    titleBarStyle: mac ? 'hiddenInset' : 'default',
    // true see-through glass: the window itself is translucent and blurs
    // whatever is BEHIND it (desktop, other windows) via the OS compositor.
    // (vibrancy + a transparent backgroundColor is the reliable combo; setting
    //  `transparent:true` as well can disable vibrancy on some versions.)
    vibrancy: mac ? 'under-window' : undefined,          // macOS NSVisualEffectView
    visualEffectState: 'active',
    backgroundMaterial: win32 ? 'acrylic' : undefined,   // Windows 11 acrylic
    backgroundColor: '#00000000',                        // no opaque paint
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.on('closed', () => { win = null; });
}

ipcMain.handle('rpc', (_e, method, params) => rpc(method, params));
ipcMain.handle('choose-folder', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
  return r.canceled ? null : r.filePaths[0];
});
ipcMain.handle('confirm', async (_e, opts) => {
  const r = await dialog.showMessageBox(win, {
    type: opts.type || 'question',
    buttons: opts.buttons || ['Cancel', 'OK'],
    defaultId: 1, cancelId: 0,
    message: opts.message || '', detail: opts.detail || '',
  });
  return r.response;
});

app.whenReady().then(() => {
  startEngine();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => {
  if (engine && !engine.killed) engine.kill();
  if (process.platform !== 'darwin') app.quit();
});
app.on('quit', () => { if (engine && !engine.killed) engine.kill(); });
