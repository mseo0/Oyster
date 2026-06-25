# Packaging Oyster as native executables

This turns Oyster into standalone binaries with [PyInstaller](https://pyinstaller.org):

| Artifact | macOS | Windows |
|----------|-------|---------|
| CLI      | `dist/oyster`      | `dist\oyster.exe`     |
| Desktop UI | `dist/Oyster.app` | `dist\oyster-gui.exe` |

> **PyInstaller cannot cross-compile.** Build the macOS artifacts on a Mac and
> the Windows `.exe` on Windows. There is no Mac→Windows shortcut.

## Build

Use the **same Python** you run Oyster with.

**macOS**
```bash
.venv/bin/python packaging/build.py              # CLI + UI
.venv/bin/python packaging/build.py --installer  # also build dist/Oyster.pkg
```

**Windows**
```bat
.venv\Scripts\python.exe packaging\build.py
```

`build.py` installs PyInstaller into the environment if it's missing, then runs
`packaging/oyster.spec`. You can also call PyInstaller directly:
```bash
pyinstaller --noconfirm --clean packaging/oyster.spec
```

## Prerequisites per target

- **UI build needs Tkinter.** This repo's Python (3.14 via Homebrew) ships
  without it, so the `.app`/`oyster-gui.exe` build needs Tk first:
  - macOS: `brew install python-tk@3.14`
  - Windows: the python.org installer already includes Tk.
  The CLI build needs no Tk.
- **libmagic** (for `python-magic`) is bundled automatically *only if it's found
  on the build host* (`brew install libmagic` on macOS). Without it the scanner
  silently falls back to extension-based file typing — not fatal.

## What is NOT bundled (by design)

Oyster shells out to two external programs; they are **not** inside the binary
and never will be — bundling a ~300 MB virus DB and multi-GB LLM weights into an
app would defeat the point:

- **ClamAV** — the detection engine. Users install it separately
  (`brew install clamav && freshclam`, or `winget install ClamAV.ClamAV`).
  Without it the scan still runs (hashing, processes, vuln audit) but does no
  signature/YARA matching.
- **Ollama** — the local LLM. Without it Oyster prints the offline heuristic
  report instead of AI explanations.

A "full" installer that also ships these engines is possible but out of scope
here; the README's roadmap tracks that under code signing / polished installer.

## Making real installers

`build.py --installer` does the first step; distribution still needs signing:

- **macOS** → `productbuild` wraps `Oyster.app` into `dist/Oyster.pkg` (unsigned).
  To run on other people's Macs without Gatekeeper warnings you must codesign
  and notarize with an Apple Developer ID:
  ```bash
  codesign --deep --options runtime --sign "Developer ID Application: …" dist/Oyster.app
  xcrun notarytool submit dist/Oyster.pkg --apple-id … --wait
  ```
- **Windows** → feed `dist\` to [Inno Setup](https://jrsoftware.org/isinfo.php)
  or WiX to produce a setup `.exe`/`.msi`, then sign with `signtool.exe` and a
  code-signing certificate.

## How the spec handles Oyster's quirks

- Bundles `rules/` at the bundle root so `Path(__file__).parent.parent/"rules"`
  resolves at runtime and the EICAR/YARA rule loads.
- CLI is named `oyster`, UI exe `oyster-gui` — deliberately differing by **more
  than case**, because macOS/Windows filesystems are case-insensitive and
  `Oyster` would silently overwrite `oyster`.
- Best-effort bundling of `libmagic` + its `magic.mgc` database when present.
