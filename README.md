# Oyster

**Scan your files, processes, and software for threats — explained in plain English, entirely on your machine.**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Electron](https://img.shields.io/badge/Electron-2B2E3A?logo=electron&logoColor=white)
![ClamAV](https://img.shields.io/badge/Engine-ClamAV%20%2B%20YARA-FF6600)
![Ollama](https://img.shields.io/badge/AI-Local%20Ollama-000000?logo=ollama&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows-lightgrey)
![Interface](https://img.shields.io/badge/Interface-Desktop%20%2B%20CLI-black)

A local antivirus that never phones home. It scans your files, sweeps what's running, checks your installed software against known vulnerabilities, then hands the results to a local LLM that explains what it found in plain English. No cloud, no account, no uploads — and it runs on an ordinary 8GB laptop, not just a workstation with a GPU.

## Quick Start

Grab the installer from the [**Releases**](../../releases) page, then:

- **macOS:** open the `.dmg`, drag **Oyster** into **Applications**, then right-click → **Open** once to get past the unverified-app warning.
- **Windows:** run `Oyster-Setup-x.y.z.exe` (per-user, no admin). If SmartScreen pops up, **More info → Run anyway**.

On first launch Oyster offers to set up its scanning definitions (ClamAV signatures + an optional small AI model). That's the only time it touches the internet, and it tells you exactly what it contacts.

## Why Oyster?

**The usual way to sanity-check a machine:**
1. Run an antivirus that uploads file hashes (or whole files) to someone's cloud
2. Squint at Activity Monitor / Task Manager and guess which processes are sketchy
3. Manually cross-reference installed software against CVE databases
4. Check `lsof`/`netstat` by hand to see what's listening on the network
5. Get a cryptic verdict like `Trojan.Win32.Agent.xyz` with no idea what to do
6. Hope the "delete" button didn't just nuke something important

**With Oyster:**
```
Files · Processes · Vulnerabilities · Cleanup · Applications · Quarantine · AI Summary
```
One desktop app scans all of it locally, scores the suspicious stuff, explains each finding in everyday language, and never deletes anything irreversibly — "delete" means "move to a restorable quarantine."

### Why not another local antivirus with a UI?

There are plenty of ClamAV front-ends (ClamTk, ClamXAV) and consumer suites (Malwarebytes, the built-in Defender/XProtect). Oyster is built for a different job: a **thorough, explainable, genuinely-offline checkup of the whole machine** — not just a file scanner with a window around it.

| | ClamAV GUIs (ClamTk/ClamXAV) | Cloud suites (Malwarebytes, etc.) | **Oyster** |
|---|---|---|---|
| **Truly offline** | Mostly, but reputation lookups vary | No — uploads hashes/files for cloud scoring | **Yes — the scanner imports no networking library; it *can't* open a socket** |
| **What it inspects** | Files only | Files + some behaviour | **Files, processes, CVEs, open ports, OS posture, app leftovers** |
| **Explains findings** | Raw signature names | Marketing-grade severity labels | **Plain-English, written by a local LLM — plus a second opinion on the uncertain ones** |
| **False-positive handling** | You're on your own | Vendor allowlists | **Corroborates heuristic hits with code-signing + provenance, then downgrades likely FPs** |
| **"Delete" is reversible** | Usually a real delete | Quarantine, vendor-managed | **Always — a restorable vault you control, with its own management tab** |
| **Runs on an 8GB laptop** | Yes | Heavy background agent | **Yes — skip-funnel + the model loads only *after* the disk scan** |
| **Cost / openness** | Free / open | Subscription / closed | **Free, MIT, fully auditable** |

The short version: other tools answer *"is this one file in ClamAV's database?"* Oyster answers *"is this machine okay, and what should I actually do about each thing you found?"* — and proves it stayed offline by how the code is shaped, not by a privacy policy.

## What It Does

- **Files:** on-demand scan with **ClamAV + YARA + known-bad hashes**, reversible quarantine, and a "downloaded only" filter so it ignores files you made yourself. Heuristic hits are corroborated with code-signing + provenance so signed system/app files stop getting flagged as malware. Uncertain hits get a one-click **local-AI second opinion**.
- **Processes:** running programs scored by suspicious behaviour — masquerading, temp-dir binaries, unsigned-and-networked.
- **Vulnerabilities:** your installed packages matched against an **offline OSV/CVE snapshot**, your **open/listening network ports** (what's reachable from the network, and whether it's a risky service or a program running from a temp folder), plus OS posture (Firewall, SIP, FileVault, Gatekeeper).
- **Cleanup:** finds junk, duplicates, large & stale files; the AI flags *personally important* files (tax, legal, identity, credentials) and keeps them out of every delete suggestion, and warns before touching anything that looks like it belongs to a program. A **chat box** takes plain-English commands (`remove all files with ENGE in the name`). Everything is reversible.
- **Applications:** uninstall apps and sweep the leftover files they leave behind, all into the reversible vault.
- **Quarantine:** a dedicated view of the reversible vault — **restore** any item to where it came from, **open the folder**, or **empty the vault** to reclaim disk for good. Nothing leaves the vault unless you say so.
- **AI Summary:** a plain-English read-out written locally by Ollama after a scan — it prioritizes and explains, but never decides what's malware on its own.

All of the local-AI features run against a model on `127.0.0.1` only, and Oyster disables the model's hidden "thinking" step so answers come back in seconds rather than tens of seconds.

## Reliability

- **Real detection engines do the verdicts** — ClamAV signatures, YARA rules, hash lookups. The model only reads, prioritizes, and explains those findings; it never invents a detection.
- **Built for a modest machine.** A skip-funnel throws most files away early, so by the time anything reaches the AI you're down from millions of files to a few dozen findings. The model loads into memory *only* during that final step, after the disk scan — an 8GB laptop never holds a full scan and a language model at once.
- **Nothing destructive happens on its own.** "Delete" moves to a reversible quarantine vault, and Oyster always asks before touching anything important.
- **Fast by skipping work, not corners.** An **incremental hash cache** lets re-scans skip unchanged files, a **verdict cache** remembers files ClamAV already cleared (auto-invalidated when the virus DB or rules change), batched scanning loads ClamAV's signature database once per batch instead of once per file, and files that will never be content-scanned aren't needlessly read end-to-end. The full scan also runs every check — files, processes, vulnerabilities, ports, posture, cleanup — back to back.

```
ALL files ──skip rules──> candidates ──hash + known-bad──> unknown
   └──────────────────────────────────────────────────────────┘
                          │ ClamAV (signatures + YARA + unpack), interesting only
                          ▼
                       FINDINGS (tens)  ──> local LLM triage + report
```

### Is This Safe?

Oyster is fully open source, and the "stays offline" claim is how the code is *shaped*, not a promise in a policy:

- The scanner doesn't import a single networking library. It literally can't open a socket, so it can't leak your files, IP, or location — even by accident.
- Exactly one component talks over a socket: the AI layer, nailed to `127.0.0.1:11434` (your local Ollama) in [agent/netguard.py](agent/netguard.py). Point it anywhere that isn't loopback and it refuses with an `EgressBlocked` error.
- No telemetry, no analytics, no silent "check for updates" pings. The only time Oyster reaches the internet is when *you* run the updater, and even then it prints every host it contacts.

## Table of Contents

- [Install](#install)
- [First-Run Setup](#first-run-setup)
- [Usage](#usage)
- [Definitions Updater](#definitions-updater)
- [Detection Sources](#detection-sources)
- [Flags](#flags)
- [Dependencies](#dependencies)
- [Development](#development)
- [License](#license)
- [Disclaimer](#disclaimer)

## Install

Download a prebuilt installer from [**Releases**](../../releases):

| Platform | File | Install |
|----------|------|---------|
| macOS | `Oyster-x.y.z-arm64.dmg` | Open the `.dmg`, drag **Oyster** into **Applications**. |
| Windows | `Oyster-Setup-x.y.z.exe` | Run the installer (per-user, no admin needed). |

**First launch — getting past the "unverified app" warning.** Oyster is signed ad-hoc (no paid Apple/Microsoft certificate), so the OS shows a one-time warning. It's safe to allow:

- **macOS:** right-click the app → **Open** → **Open** (or System Settings → Privacy & Security → **Open Anyway**). Once only.
- **Windows:** if SmartScreen appears, click **More info → Run anyway**.

Building from source instead:

```bash
git clone <this repo>
cd Oyster
pip install -r requirements.txt        # the Python engine's deps
./scripts/install-mac.sh               # build + install /Applications/Oyster.app (macOS)
# Windows installer builds via .github/workflows/desktop-build.yml
```

## First-Run Setup

The detection engine isn't a pip package — install it on its own, then let Oyster fetch definitions:

```bash
# macOS
brew install clamav && freshclam

# Windows
winget install ClamAV.ClamAV        # then run freshclam
```

The local AI model is optional. Without it, Oyster still works and falls back to plain heuristic reports; with it, you get the readable explanations:

```bash
ollama pull qwen3:8b                 # sized to your RAM; picked automatically
```

On first launch the app offers to download the ClamAV signature database and (optionally) the model for you — the only time it goes online.

## Usage

### Desktop App

The recommended interface is the cross-platform **Electron app** (real frosted glass) that drives the Python engine as a stdio sidecar. Launch it from Applications/Start Menu, or build it locally:

```bash
./scripts/install-mac.sh             # macOS: build + install
```

> Because the app is signed ad-hoc, macOS Gatekeeper blocks the first launch. **Right-click → Open** once; after that it launches normally.

### CLI

No UI needed:

```bash
python -m cli.scan --apply ~/Downloads     # scan a folder, act on findings
python -m cli.scan --processes-only        # just running processes
python -m cli.scan --vuln-only             # software + OS posture
python -m cli.scan --everything            # deep scan the whole computer
```

### Catch a Test Detection

Want to see it catch something without going near real malware? Drop an [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) in the folder you scan — `rules/example.yar` is set up to flag it.

## Definitions Updater

Fresh definitions are the *only* thing that goes online, and only because you asked. The updater prints exactly what it's contacting:

```bash
python -m updater.update --clamav          # refresh ClamAV signatures
python -m updater.update --osv PyPI npm    # pull down the offline CVE snapshot
python -m updater.update --all             # both at once
```

## Detection Sources

| Source | Role | Notes |
|--------|------|-------|
| ClamAV | Signature scanning + archive unpacking | Installed separately (`brew`/`winget`); the engine drives `clamscan` |
| YARA | Pattern rules | Bundled under [`rules/`](rules/); `example.yar` flags EICAR |
| Known-bad hashes | Instant hash verdicts | Local set, no network lookup |
| OSV / CVE | Vulnerability matching | Offline snapshot via [updater/update.py](updater/update.py) |
| Open ports | Network-exposure check | Listening TCP sockets + their process, scored in [core/portscan.py](core/portscan.py) |
| OS posture | Firewall, SIP, FileVault, Gatekeeper | Read-only system checks in [core/posture.py](core/posture.py) |
| Local LLM | Plain-English explanation + second opinion | Loopback-only Ollama; reads findings, never invents detections |

## Flags

| Flag | Description |
|------|-------------|
| `<paths>` | One or more paths to scan |
| `--apply` | Interactively act on findings (quarantine, etc.) |
| `--processes-only` | Sweep running processes only |
| `--vuln-only` | Audit installed software + OS posture only |
| `--no-vuln` | Skip the vulnerability audit |
| `--deep` | Descend into system trees too |
| `--everything` | Deep scan the whole computer (every volume) |
| `--model <name>` | Override the auto-picked Ollama model |

## Dependencies

- [Python](https://www.python.org/) 3.11+
- [ClamAV](https://www.clamav.net/) (installed separately — not a pip package)
- [Node.js](https://nodejs.org/) 18+ and npm (to build the desktop app)

### Runtime

- [psutil](https://github.com/giampaolo/psutil) — cross-platform process inspection
- [python-magic](https://github.com/ahupp/python-magic) — content-based file typing (falls back to extensions)
- [Electron](https://www.electronjs.org/) — the desktop UI shell

### Recommended

- [Ollama](https://ollama.com/) — Optional. If running locally, Oyster uses it for plain-English explanations. Without it, Oyster falls back to heuristic reports. The scan engine never depends on it.

## Development

```bash
pip install -r requirements.txt
python -m cli.scan ~/Downloads       # run the engine headless
cd desktop && npm install && npm start   # run the Electron app in dev
```

See [desktop/README.md](desktop/README.md) for dev/build steps. The previous Tkinter UI is archived under `legacy/`.

### Project Structure

```
core/                   # the scanning engine — no networking libraries
├── walker.py           # filesystem walk + skip rules
├── config.py           # tuning, protected paths, model tiering
├── scanner.py          # the scan funnel
├── hashcache.py        # incremental hash cache (skip unchanged files)
├── engine.py           # ClamAV: signatures, YARA, archive unpacking
├── processes.py        # suspicious-process scoring
├── portscan.py         # open/listening-port network-exposure inspector
├── risk.py             # heuristic-hit triage (signing + provenance) → ranked risk
├── quarantine.py       # reversible "delete" vault
├── findings.py         # findings store + action log
├── vulnaudit.py        # installed software vs. offline CVE data
├── osvdb.py            # local OSV/CVE database
├── inventory.py        # installed-package inventory
├── posture.py          # OS posture checks (Firewall/SIP/FileVault)
├── organize.py         # Cleanup: junk / duplicates / clutter
├── appcleanup.py       # app uninstall + leftover sweep
├── maintenance.py      # bounds Oyster's own ~/.oyster storage growth
├── provenance.py       # downloaded-vs-user-created detection
└── preflight.py        # permission / dependency checks
agent/                  # local AI layer — the only socket, loopback-only
├── netguard.py         # enforces 127.0.0.1:11434, blocks all other egress
├── ollama_client.py    # Ollama HTTP client
└── triage.py           # findings → prioritized, explained report
updater/update.py       # the one and only component allowed online
sidecar/server.py       # wraps core/ as stdio JSON-RPC for the desktop app
cli/scan.py             # python -m cli.scan
desktop/                # Electron app (real frosted glass) driving the engine
rules/                  # YARA rules (example.yar flags EICAR)
```

## License

[MIT](LICENSE) © 2026 Matthew Seo. Provided as-is, with no warranty — see the license for details.

By using Oyster, you acknowledge:

- **Oyster is an on-demand scanner, not a real-time shield.** It doesn't sit in your kernel or replace Defender/XProtect — it's something you run when you want a thorough look, not something humming in the background all day.
- **The AI does not decide what is malware.** Real engines produce the verdicts; the model reads, prioritizes, and explains them.
- **You are responsible for actions you confirm.** Oyster makes "delete" reversible and always asks before touching important files, but the final call is yours.

## Disclaimer

This software is provided "as is," without warranty of any kind. Oyster is a security *aid*, not a guarantee — no scanner catches everything.

- **Not a substitute for safe habits.** Keep your OS and software updated, and don't run things you don't trust.
- **Definitions can lag.** ClamAV signatures and the CVE snapshot are only as current as your last update; run the updater regularly.
- **Quarantine is reversible by design.** Files are moved, not destroyed — which also means quarantined items still occupy disk until you empty the vault.
- **Heuristic process/vulnerability scoring is best-effort.** Treat flags as "worth a look," not as proof of compromise.
