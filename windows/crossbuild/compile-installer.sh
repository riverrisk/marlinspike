#!/bin/sh
set -eu

REPO_ROOT=${REPO_ROOT:-/src}
APP_VERSION=${APP_VERSION:-dev}
INNO_SETUP_VERSION=${INNO_SETUP_VERSION:-6.7.1}
INNO_TAG=$(printf '%s' "$INNO_SETUP_VERSION" | tr '.' '_')
INNO_URL=${INNO_URL:-"https://github.com/jrsoftware/issrc/releases/download/is-${INNO_TAG}/innosetup-${INNO_SETUP_VERSION}.exe"}
WORK_ROOT=/work
DOWNLOAD_DIR=$WORK_ROOT/downloads

mkdir -p "$DOWNLOAD_DIR" "$WINEPREFIX"

INSTALLER_EXE="$DOWNLOAD_DIR/innosetup-${INNO_SETUP_VERSION}.exe"
WINE_INNO_DIR='C:\InnoSetup'
WINE_ISCC='C:\InnoSetup\ISCC.exe'
LINUX_ISCC="$WINEPREFIX/drive_c/InnoSetup/ISCC.exe"
if [ ! -f "$INSTALLER_EXE" ]; then
    echo "[cross-installer] Downloading $INNO_URL"
    curl -fsSL "$INNO_URL" -o "$INSTALLER_EXE"
fi

ISS_FILE="$REPO_ROOT/windows/installer/MarlinSpike.iss"
if [ ! -f "$ISS_FILE" ]; then
    echo "Missing installer script: $ISS_FILE" >&2
    exit 1
fi

mkdir -p "$REPO_ROOT/windows/build/installer"

ISS_WIN=$(printf 'Z:%s' "$(printf '%s' "$ISS_FILE" | sed 's#/#\\\\#g')")

echo "[cross-installer] Initializing Wine"
xvfb-run -a wineboot -i >/dev/null 2>&1 || true

if [ ! -f "$LINUX_ISCC" ]; then
    echo "[cross-installer] Installing Inno Setup under Wine"
    xvfb-run -a wine "$INSTALLER_EXE" /SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART "/DIR=$WINE_INNO_DIR" >/dev/null 2>&1
fi

if [ ! -f "$LINUX_ISCC" ]; then
    echo "ISCC.exe not found after installing $INSTALLER_EXE" >&2
    exit 1
fi

echo "[cross-installer] Compiling installer"
xvfb-run -a wine "$WINE_ISCC" /Qp "/DMyAppVersion=$APP_VERSION" "$ISS_WIN"

echo "[cross-installer] Output ready in $REPO_ROOT/windows/build/installer"
