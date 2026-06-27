# Oyster

Oyster is an antivirus that never phones home. It scans your files, looks through
what's running (the way you'd squint at Activity Monitor or Task Manager), checks
your installed software for known vulnerabilities, and then hands the results to a
local LLM that explains what it found in plain English. All of it stays on your
machine — no cloud, no account, no uploads.

It runs on macOS and Windows, and it's built to be usable on an ordinary 8GB
laptop, not just a workstation with a fancy GPU.

A note on what the AI actually does: it doesn't decide what's malware. Real
engines do that — ClamAV signatures, YARA rules, hash lookups. The model's job is
to read those findings, prioritize them, explain them, and suggest what to do. And
it never does anything destructive on its own. "Delete" really means "move to a
reversible quarantine," and Oyster always asks before touching anything important.

## What you get

- **A real desktop app** (Electron, true frosted-glass UI) on macOS and Windows,
  driving the Python scanning engine as a local sidecar — no sockets, no egress.
- **Files** — on-demand scan with ClamAV + YARA + known-bad hashes, reversible
  quarantine, and a "downloaded only" filter so it ignores files you made yourself.
- **Processes** — running programs scored by suspicious behaviour (masquerading,
  temp-dir binaries, unsigned + network).
- **Vulnerabilities** — your installed packages matched against an offline OSV/CVE
  snapshot, plus OS posture (Firewall, SIP, FileVault, Gatekeeper).
- **Cleanup** — find junk, duplicates, large & stale files; the AI flags
  *personally important* files (tax, legal, identity, credentials) and keeps them
  out of every delete suggestion, and warns before removing anything that looks
  like it belongs to a program. A **chat box** takes plain-English commands
  ("remove all files with ENGE in the name"). Everything is reversible.
- **AI Summary** — a plain-English read-out written locally by Ollama, after a scan.

## Why you can trust that it stays offline

This isn't a promise in a privacy policy — it's how the code is shaped:

- The scanner doesn't import a single networking library. It literally can't open
  a socket, so there's no way for it to leak your files, your IP, or your
  location, even by accident.
- Exactly one part of the app talks over a socket: the AI layer, and it's nailed
  to `127.0.0.1:11434` (your local Ollama) in
  [agent/netguard.py](agent/netguard.py). Point it anywhere that isn't loopback
  and it refuses with an `EgressBlocked` error.
- No telemetry, no analytics, no silent "check for updates" pings. The only time
  Oyster reaches the internet is when *you* run the updater, and even then it
  prints every host it contacts.

If your worry is "can someone figure out where I am?" — on a desktop, that only
happens if something makes an outbound connection. Oyster's scanner never does, so
there's no IP for anyone to geolocate in the first place.

## How a scan works

The trick to staying fast on a modest machine is to do almost no expensive work.
Everything flows through a funnel that throws most files away early:

```
ALL files ──skip rules──> candidates ──hash + known-bad──> unknown
   └──────────────────────────────────────────────────────────┘
                          │ ClamAV (signatures + YARA + unpack), interesting only
                          ▼
                       FINDINGS (tens)  ──> local LLM triage + report
```

By the time anything reaches the AI, you're down from millions of files to a few
dozen findings. The model runs once over that short list — never file by file —
and it only loads into memory during that final step, after the disk scan is done.
So an 8GB machine is never asked to hold a full scan and a language model at the
same time.

Here's where each piece lives if you want to poke around:

| Piece | Where | What it does |
|-------|-------|--------------|
| Walk + filter | [core/walker.py](core/walker.py), [core/config.py](core/config.py) | skips the noise so the slow stages barely run |
| Hash cache | [core/hashcache.py](core/hashcache.py) | remembers files so re-scans skip unchanged ones |
| Engine | [core/engine.py](core/engine.py) | ClamAV: signatures, YARA, and unpacking archives |
| Processes | [core/processes.py](core/processes.py) | flags shady running programs |
| Quarantine | [core/quarantine.py](core/quarantine.py) | the reversible vault that replaces deleting |
| Findings + log | [core/findings.py](core/findings.py) | the record the AI report is written from |
| Vuln audit | [core/vulnaudit.py](core/vulnaudit.py), [core/osvdb.py](core/osvdb.py), [core/inventory.py](core/inventory.py), [core/posture.py](core/posture.py) | matches your software against offline CVE data, checks OS settings |
| AI | [agent/](agent/) | local Ollama, with a no-AI fallback when it's off |
| Updater | [updater/update.py](updater/update.py) | the one and only piece allowed online |
| CLI | [cli/scan.py](cli/scan.py) | `python -m cli.scan` |
| Engine sidecar | [sidecar/server.py](sidecar/server.py) | wraps core/ as stdio JSON-RPC for the app |
| Desktop app | [desktop/](desktop/) | Electron UI (real frosted glass) driving the Python engine |
| Cleanup/organize | [core/organize.py](core/organize.py) | finds junk/dupes/clutter, recommends tidy-up |

## Download & install

Grab the latest installer from the [**Releases**](../../releases) page:

| Platform | File | Install |
|----------|------|---------|
| macOS | `Oyster-x.y.z-arm64.dmg` | Open the `.dmg`, drag **Oyster** into **Applications**. |
| Windows | `Oyster-Setup-x.y.z.exe` | Run the installer (per-user, no admin needed). |

**First launch — getting past the "unverified app" warning.** Oyster is signed
ad-hoc (it doesn't have a paid Apple/Microsoft signing certificate), so the OS
shows a one-time warning. It's safe to allow:

- **macOS:** right-click the app → **Open** → **Open** (or System Settings →
  Privacy & Security → **Open Anyway**). Only needed once.
- **Windows:** if SmartScreen pops up, click **More info → Run anyway**.

On first launch Oyster offers to **set up its scanning definitions** (downloads
the ClamAV signature database and, optionally, a small local AI model). That's
the only time it goes online, and it tells you exactly what it contacts.

> Building it yourself / contributing? See the developer setup below and
> [desktop/README.md](desktop/README.md).

## Getting set up

```bash
pip install -r requirements.txt   # the Python engine's deps

# The detection engine isn't a pip package — install it on its own:
#   macOS:    brew install clamav && freshclam
#   Windows:  winget install ClamAV.ClamAV   (then run freshclam)

# The local model is optional. Without it, Oyster still works and falls back to
# plain heuristic reports. With it, you get the readable explanations:
ollama pull qwen3:8b         # sized to your RAM; picked automatically
```

The UI is a cross-platform **Electron desktop app** (real frosted glass) that
drives the Python engine as a stdio sidecar — see [desktop/README.md](desktop/README.md)
for dev/build steps. The previous Tkinter UI is archived under `legacy/`.

## Using it

**Desktop app** (recommended):

```bash
./scripts/install-mac.sh      # build + install /Applications/Oyster.app  (macOS)
# Windows installer builds via .github/workflows/desktop-build.yml
```

> Because the app is signed ad-hoc (no Apple Developer ID), macOS Gatekeeper
> blocks the first launch. **Right-click the app → Open** (or System Settings →
> Privacy & Security → "Open Anyway") once; after that it launches normally.

**CLI** (no UI needed):

```bash
python -m cli.scan --apply ~/Downloads     # scan a folder, act on findings
python -m cli.scan --processes-only        # just running processes
python -m cli.scan --vuln-only             # software + OS posture
python -m cli.scan --everything            # deep scan the whole computer
```

When you want fresh definitions — the *only* thing that goes online, and only
because you asked — run the updater. It tells you exactly what it's contacting:

```bash
python -m updater.update --clamav          # refresh ClamAV signatures
python -m updater.update --osv PyPI npm     # pull down the offline CVE snapshot
python -m updater.update --all              # both at once
```

Want to see it catch something without going anywhere near real malware? Drop an
[EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) in the
folder you scan — `rules/example.yar` is set up to flag it.

## Where it's at

- [x] Phase 1 — the scanner core: walking, hashing, ClamAV, processes
- [x] Phase 2 — reversible quarantine, the approval prompts, protected paths
- [x] Phase 3 — local AI triage and the end-of-scan report
- [x] Phase 4 — the desktop app, including process and vulnerability controls
- [x] Phase 5 — vulnerability auditing against an offline OSV snapshot + OS checks
- [x] Phase 6 — the isolated, opt-in definitions updater
- [ ] Next — a polished Tauri UI, code signing, and scheduled scans

## What Oyster isn't

It's not a real-time shield sitting in your kernel — that needs signed drivers and
is a different kind of project — and it's not trying to replace Defender or
XProtect. Think of it as an on-demand scanner with a smart assistant reading over
the results: something you run when you want a thorough look, not something humming
in the background all day.

## License

[MIT](LICENSE) © 2026 Matthew Seo. Provided as-is, with no warranty — see the
license for details.
