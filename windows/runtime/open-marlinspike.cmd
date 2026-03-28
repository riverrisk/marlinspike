@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..\python\pythonw.exe") do set "PYTHONW_EXE=%%~fI"
for %%I in ("%SCRIPT_DIR%desktop-launcher.py") do set "LAUNCHER_PY=%%~fI"
start "" "%PYTHONW_EXE%" "%LAUNCHER_PY%" open
endlocal
