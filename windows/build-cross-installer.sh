#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
APP_VERSION=${APP_VERSION:-$(python3 - <<'PY'
from pathlib import Path
text = (Path("app.py")).read_text(encoding="utf-8")
marker = 'APP_VERSION = "'
start = text.find(marker)
if start == -1:
    print("dev")
else:
    start += len(marker)
    end = text.find('"', start)
    print(text[start:end])
PY
)}

cd "$REPO_ROOT"

python3 "$SCRIPT_DIR/build-cross-bundle.py" --app-version "$APP_VERSION"

docker build --platform linux/amd64 \
    -t marlinspike-inno-cross \
    -f "$SCRIPT_DIR/crossbuild/Dockerfile" \
    "$SCRIPT_DIR/crossbuild"

mkdir -p "$SCRIPT_DIR/build/installer"

docker run --rm --platform linux/amd64 \
    -e APP_VERSION="$APP_VERSION" \
    -e INNO_SETUP_VERSION="${INNO_SETUP_VERSION:-6.7.1}" \
    -v "$REPO_ROOT:/src" \
    marlinspike-inno-cross

echo "Cross-built installer available at $SCRIPT_DIR/build/installer/MarlinSpike-Setup.exe"
