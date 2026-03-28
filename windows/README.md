# MarlinSpike Windows Installer

This folder packages the full MarlinSpike workbench as a local Windows install:

- Flask app served by `serve.py`
- bundled Python runtime
- local SQLite database under `%LOCALAPPDATA%\MarlinSpike`
- Start / Stop / Open launcher scripts
- Inno Setup project for a GUI installer

## Packaging model

The installer is not a single-file EXE. It installs a full local workbench:

- app files into `%LOCALAPPDATA%\Programs\MarlinSpike`
- writable data, logs, pid files, and the SQLite database into `%LOCALAPPDATA%\MarlinSpike`
- Start Menu shortcuts that launch the workbench on `http://127.0.0.1:5001/`

## Prerequisites

- Windows 10 or Windows 11, x64
- PowerShell 5.1+
- Python 3.12 available on the build machine
- Inno Setup 6.x if you want to compile `MarlinSpike-Setup.exe`
- Wireshark CLI tools installed on the target system

MarlinSpike analysis depends on `tshark.exe`, `capinfos.exe`, and `editcap.exe`. The launcher looks for them in the standard `Wireshark` install directories and warns if they are missing.
The installer does not vendor Wireshark. Instead it offers an official `wireshark.org` download flow after install and adds an `Install Wireshark (Official)` Start Menu shortcut for later setup.

## Build on Windows

Run this on a Windows build machine from the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\build-windows-bundle.ps1
```

That creates:

- `windows/build/bundle/` — app payload staged for installation
- `windows/build/venv/` — Python virtual environment used by the bundle

## Build the installer

If Inno Setup is installed:

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\build-windows-bundle.ps1 -BuildInstaller
```

That also compiles:

- `windows/build/installer/MarlinSpike-Setup.exe`

## Cross-build from macOS or Linux

Run this from the repo root on a machine with Docker:

```bash
./windows/build-cross-installer.sh
```

That path:

- downloads the official Windows embeddable Python package from `python.org`
- downloads Windows wheels for the Python dependencies
- assembles `windows/build/bundle/` without needing a Windows host
- uses Wine in an `amd64` Docker container to run `ISCC.exe`
- writes `windows/build/installer/MarlinSpike-Setup.exe`

## Runtime behavior

- `runtime\start-marlinspike.ps1` launches the local workbench in the background
- `runtime\open-marlinspike.ps1` starts the workbench if needed and opens the browser
- `runtime\install-wireshark.ps1` opens the official Wireshark download page and install guide
- `runtime\stop-marlinspike.ps1` stops the background process tree
- `runtime\status-marlinspike.ps1` reports whether the local server is reachable

The first local start generates an admin password file at:

- `%LOCALAPPDATA%\MarlinSpike\admin-password.txt`

That file is meant for first-run bootstrap only. Change the admin password immediately after signing in.

If Wireshark is not already installed, use the Start Menu shortcut:

- `Install Wireshark (Official)`

That flow opens:

- the official download page at `https://www.wireshark.org/download.html`
- the Windows install guide at `https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall`
