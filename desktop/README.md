# Oyster desktop app (Electron + Python engine)

A real cross-platform desktop app implementing the `Oyster.dc` frosted-glass
design. The UI is web (Chromium `backdrop-filter` → true glass); the antivirus
engine is the project's existing Python `core/`, bundled as a sidecar the app
drives over stdio. **No sockets are opened** — the privacy guarantee is intact.

```
┌──────────────────────────────┐     stdio JSON-RPC      ┌────────────────────┐
│ Electron (renderer = design) │  ◀───────────────────▶ │ Python engine       │
│  • real backdrop-filter glass│   {id,method,params}   │  sidecar/server.py  │
│  • Hanken Grotesk / JetBrains│   ◀ progress events    │  wraps core/, agent/│
└──────────────────────────────┘                        └────────────────────┘
```

- `electron/main.js` — spawns the engine, makes the window, relays IPC
- `electron/preload.js` — safe `window.oyster` bridge (contextIsolation)
- `renderer/` — the design: `index.html`, `styles.css`, `app.js`, bundled `fonts/`
- `../sidecar/server.py` — the engine sidecar (line-delimited JSON-RPC over stdio)

## Run in dev
```bash
# 1) the engine runs via the project venv (deps already installed)
# 2) launch electron
cd desktop
npm install
npm start
```
> In a VS Code integrated terminal, unset `ELECTRON_RUN_AS_NODE` first:
> `env -u ELECTRON_RUN_AS_NODE npm start` (VS Code sets it, which breaks `electron .`).

In dev, `main.js` runs the sidecar with `../.venv/bin/python -m sidecar.server`.

## Build installers
The engine is bundled as a PyInstaller binary; build it first, then the app:
```bash
# from repo root — produces dist/oyster-engine (mac/linux) or dist\oyster-engine.exe (win)
.venv/bin/python -m PyInstaller --noconfirm --clean packaging/engine.spec

cd desktop && npm install
npm run dist:mac    # → desktop/dist/Oyster-*.dmg
npm run dist:win    # → desktop/dist/Oyster Setup *.exe   (must run on Windows)
```

**Cross-compiling is not possible** — build the macOS app on a Mac and the
Windows app on Windows. `.github/workflows/desktop-build.yml` does both on CI
(macOS + Windows runners) and uploads the `.dmg` / `.exe` as artifacts.

## Still required at runtime (unchanged)
- **ClamAV** for signature/YARA detection (`brew install clamav && freshclam`, or
  `winget install ClamAV.ClamAV`). The app finds it on a stripped PATH.
- **Ollama** (optional) for the AI summary; heuristic fallback otherwise.
- **macOS Full Disk Access** for whole-computer / private-folder scans — the
  in-app gate checks it and links to Settings.

Distribution needs code signing (Apple Developer ID / Windows cert) — unsigned
builds trip Gatekeeper/SmartScreen on first launch.
