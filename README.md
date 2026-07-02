# RaidDeck

A **desktop white-hat security toolkit** — a PySide6 GUI over the
[raidkit](https://github.com/Vl4dimirz/raidkit) scanner engine. Point it at your
own app, it runs the checks and shows color-coded findings you can export as a
report.

**White-hat by design.** RaidDeck only scans hosts that are **local/private** or
on your **Authorized Targets** allowlist, and it only reads (non-destructive
recon). It cannot be pointed at an arbitrary third party — this is a
self-testing tool, not an attack tool.

## Run

```bash
python -m venv .venv
.venv\Scripts\pip install PySide6
.venv\Scripts\pip install -e ..\raidkit   # the scan engine (brings httpx + rich)
.venv\Scripts\python run.py
```

Or just double-click the built **`dist\RaidDeck.exe`** (standalone, no Python needed).

## Features

- **Scope gate** — refuses targets that aren't local/private or on your allowlist
- **Background scans** — the UI never freezes (scan runs on a worker thread)
- **Color-coded findings** table (Severity / Check / Finding / Evidence / Fix)
- **Scan history** — every scan is saved; click a past scan to reopen it
- **Export** — JSON, Markdown, or a styled HTML report
- **Target manager** — add/remove authorized hosts
- **Check selection** — toggle which checks run (headers, transport, exposure,
  discovery, CORS, open redirect, reflected XSS)

## Build the .exe

```bash
.venv\Scripts\pip install pyinstaller
.venv\Scripts\pyinstaller --name RaidDeck --windowed --onefile ^
  --paths ..\raidkit --collect-submodules raidkit run.py
```

## Build log (rung-by-rung)

- [x] Rung 1 — Qt app shell + white-hat scope gate + background scan
- [x] Rung 2 — scan history + report export (JSON / Markdown / HTML)
- [x] Rung 3 — target manager dialog + per-check selection
- [x] Rung 4 — packaged as a standalone `RaidDeck.exe` (PyInstaller)

Data (allowlist, history) is stored under `%APPDATA%\RaidDeck\`.
