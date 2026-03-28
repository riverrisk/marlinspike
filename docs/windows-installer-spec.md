# MarlinSpike Windows Workbench Installer Spec

## Summary

Package the full MarlinSpike workbench as a local Windows install that runs the existing Flask application, analyzer engine, templates, and static assets without Docker. The Windows build installs the app into the user's local app area, keeps mutable state in the user's local app data, serves the UI on loopback with Waitress, defaults to SQLite instead of PostgreSQL, and relies on the native Wireshark CLI tools already installed on the target workstation.

## Problem Statement

MarlinSpike is deployable today as a Linux Docker stack, but there is no supported path for analysts who need the full workbench on Windows laptops or jump hosts. The current repo assumes a server-style runtime in a few key places:

- `_config.py` defaults to PostgreSQL and repo-local data paths.
- `app.py` launches scans and the MITRE sidecar with hardcoded `python3`.
- `create_app()` in `app.py` uses PostgreSQL-style `ALTER TABLE ... IF NOT EXISTS` and `DROP COLUMN IF EXISTS`.
- `app.py` forces `SESSION_COOKIE_SECURE=True`, which breaks local HTTP session cookies outside an HTTPS reverse proxy.
- `Dockerfile` and `docker-compose.yml` are the only first-class deployment assets in the repo.

The goal is a proper Windows installer for the whole workbench, not a marketing demo or a one-off developer note.

## Goals

- Install the full MarlinSpike workbench on Windows as a local loopback web app.
- Reuse the current Flask/Jinja app and engine code without forking the product into a separate desktop codebase.
- Avoid touching `_ms_engine.py` so the Voracity dual-sync requirement is not triggered for packaging work.
- Replace the implicit PostgreSQL dependency with a desktop-friendly default for installer mode.
- Give operators a simple Start / Stop / Open workflow from the Start Menu.
- Produce packaging assets that can be built on a Windows machine into an actual GUI installer.

## Non-Goals

- Native single-file EXE packaging.
- Replacing Wireshark CLI tools with a custom packet parsing stack.
- Shipping live capture as a guaranteed day-one Windows feature.
- Converting the app into an Electron or native desktop UI.
- Reworking the engine for cross-platform interface enumeration in this packaging phase.

## Current-State Findings

- `app.py` is the Flask entrypoint and currently advertises a PostgreSQL-backed app runtime.
- `_config.py` centralizes data-path, database, and host defaults; this is the cleanest place to switch installer mode behavior.
- `_models.py` uses generic SQLAlchemy models and is compatible with SQLite for a clean install.
- `app.py` starts scans with `["python3", "-u", config.MARLINSPIKE_PY]` and starts the MITRE sidecar with another `python3` subprocess call, which breaks a bundled interpreter model.
- `create_app()` in `app.py` already performs its own idempotent schema fixes, so dialect-aware migration logic can live there without introducing Alembic.
- `_ms_engine.py` depends on `tshark`, `capinfos`, and `editcap` for core analysis. Those are mandatory external prerequisites for Windows packaging.
- `requirements.txt` does not currently include a production WSGI server, so the local installer needs an added runtime dependency.

## Proposed Solution

Ship MarlinSpike on Windows as a bundled Python application plus launcher scripts and an Inno Setup installer:

- App payload lives under `%LOCALAPPDATA%\Programs\MarlinSpike`.
- Mutable state lives under `%LOCALAPPDATA%\MarlinSpike`.
- `serve.py` becomes the Windows/local production entrypoint and serves the app with Waitress.
- Desktop mode defaults to SQLite, loopback bind, and non-secure cookies for local HTTP.
- PowerShell launchers start, stop, and open the workbench.
- Inno Setup packages the staged bundle into `MarlinSpike-Setup.exe`.
- Wireshark CLI tools remain an external prerequisite, detected at runtime from the standard install path, with an official `wireshark.org` bootstrap flow instead of vendoring third-party installer bits.

This keeps the existing product intact while creating a real installer boundary around it.

## Architecture And Component Changes

### Runtime Configuration

`_config.py` now supports installer-friendly runtime defaults:

- `DESKTOP_MODE` determines loopback-oriented behavior.
- `APP_HOME` and `MARLINSPIKE_HOME` separate writable runtime state from the code directory.
- `DATABASE_URL` defaults to SQLite in desktop mode or on Windows when no explicit database URL is provided.
- `PYTHON_EXE` replaces hardcoded interpreter assumptions.
- `SESSION_COOKIE_SECURE` is configurable and no longer assumed true for every deployment.
- `WIRESHARK_BIN_DIR` supports explicit Wireshark path injection when needed.

### Flask Application

`app.py` now:

- uses `config.PYTHON_EXE` for analyzer and MITRE subprocesses
- applies cookie security from config instead of a hardcoded HTTPS-only value
- performs schema repair using SQLAlchemy inspection instead of PostgreSQL-only `IF NOT EXISTS` and `DROP COLUMN IF EXISTS`

This keeps server deployments working while allowing SQLite-backed desktop installs to boot cleanly.

### Local Server Entrypoint

`serve.py` is a new production-style launcher that:

- prepends the Wireshark install directory to `PATH` when found
- creates the Flask app through `create_app()`
- serves it with Waitress when available
- falls back to the Flask dev server only if Waitress is missing

### Windows Runtime Scripts

The `windows/runtime/` scripts provide a local workstation lifecycle:

- `start-marlinspike.ps1` launches the workbench in the background
- `open-marlinspike.ps1` starts the app if needed and opens the browser
- `install-wireshark.ps1` opens the official Wireshark download page and install guide
- `stop-marlinspike.ps1` kills the launcher process tree
- `status-marlinspike.ps1` reports current local status
- `common.ps1` centralizes local app data paths, PID file, log directory, and Wireshark detection logic

### Installer Packaging

The Windows packaging layer consists of:

- `windows/build-windows-bundle.ps1` to stage the app payload and bundled virtual environment
- `windows/installer/MarlinSpike.iss` to compile the GUI installer with Inno Setup
- `windows/README.md` to document the build flow and operator expectations

## Data Model, API, And Integration Impacts

- Database backend changes in installer mode from PostgreSQL to SQLite by default.
- Existing SQLAlchemy models remain unchanged.
- Existing HTTP routes remain unchanged.
- Existing report JSON artifacts remain unchanged.
- No API contract changes are introduced for browser clients or downstream report consumers.

Compatibility note:

- Existing Linux/Docker installs continue to use PostgreSQL because `docker-compose.yml` already sets `DATABASE_URL`.
- The desktop installer is intended for clean local installs first, not for migrating an existing PostgreSQL deployment into SQLite automatically.

## UX And Workflow Changes

Windows operators use the workbench like a local application:

1. Install MarlinSpike with `MarlinSpike-Setup.exe`.
2. Launch `Open MarlinSpike` from the Start Menu.
3. Sign in with the bootstrap admin account.
4. Upload PCAPs and use the workbench normally in the browser.

First-run behavior:

- The runtime creates `%LOCALAPPDATA%\MarlinSpike\admin-password.txt` on first launch.
- That file stores the bootstrap password so the background launch path does not hide the generated credentials from the operator.
- If Wireshark is missing, the installer offers an official post-install download prompt and the Start Menu includes an `Install Wireshark (Official)` shortcut.

## Security, Reliability, And Performance Considerations

- The desktop install binds to `127.0.0.1` only by default.
- Session cookies are intentionally non-secure in desktop mode because the local workbench is served over HTTP on loopback.
- Mutable app data is separated from the program install directory to avoid write failures under the install path.
- PID files and logs live in the user's local app data, which keeps launcher state outside the read-only install path and avoids unnecessary admin prompts.
- Wireshark CLI tooling is not bundled in this phase; the installer and runtime direct the user to the official `wireshark.org` download flow when those tools are missing.
- Live capture remains disabled by default in desktop mode because the current interface-enumeration code is Linux/macOS-oriented and the installer’s main responder value comes from uploaded PCAP analysis.

## Delivery Plan

### Phase 1: Runtime Portability

- Add config-driven interpreter, cookie, database, and app-home defaults.
- Make schema migration logic dialect-aware.
- Add a WSGI launcher entrypoint.

### Phase 2: Windows Bundle

- Stage app files, assets, engine code, and bundled Python environment on a Windows build machine.
- Add PowerShell lifecycle scripts for start, stop, status, and browser open.

### Phase 3: Installer

- Package the staged bundle with Inno Setup.
- Create Start Menu shortcuts and uninstall stop hooks.
- Add Wireshark prerequisite detection, post-install prompt, and official download shortcut.

### Phase 4: Validation

- Smoke-test first-run bootstrap and login.
- Run a PCAP upload and analyzer execution on Windows with Wireshark installed.
- Confirm logs, PID cleanup, and restart behavior.

## Testing And Validation

Required checks for the installer path:

- `python -m py_compile app.py _config.py _models.py _auth.py serve.py`
- clean SQLite boot through `create_app()` in desktop mode
- first-run admin bootstrap file creation under `%LOCALAPPDATA%`
- local login flow on `http://127.0.0.1:5001/`
- scan execution against a known preset or uploaded PCAP with Wireshark CLI tools present
- launcher lifecycle checks:
  - start when stopped
  - open when already running
  - stop process tree cleanup
  - restart after stop

Recommended follow-up validation:

- Windows 11 smoke test with Wireshark installed under both `Program Files` and `Program Files (x86)`
- large PCAP regression test to measure local desktop memory pressure
- signed installer packaging before public release

## Risks And Mitigations

- Missing Wireshark CLI tools:
  - Mitigation: detect common install paths, prompt to open the official Wireshark download page after install, add a dedicated Start Menu shortcut, and warn again during runtime launch.
- Hidden bootstrap credentials on first launch:
  - Mitigation: create a deterministic first-run password file in the user's local app data.
- SQLite-specific migration differences:
  - Mitigation: inspect actual columns first and avoid PostgreSQL-only DDL.
- Background launcher orphaning child processes:
  - Mitigation: store the launcher PID and stop the full process tree.
- Desktop users expecting live capture parity:
  - Mitigation: keep live capture disabled by default and position PCAP upload as the supported Windows workflow initially.

## Open Questions

- Should the Windows build move from bundled source plus venv to a frozen Python distribution later for startup speed and code obfuscation?
- Is Windows live capture a release requirement, or is uploaded PCAP analysis sufficient for the first supported installer release?
- Do we want a signed MSI eventually, or is Inno Setup EXE packaging acceptable for the first production installer?
