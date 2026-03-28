@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..\python\python.exe") do set "PYTHON_EXE=%%~fI"
for %%I in ("%SCRIPT_DIR%desktop-launcher.py") do set "LAUNCHER_PY=%%~fI"
start /wait "" "%PYTHON_EXE%" "%LAUNCHER_PY%" run
endlocal
