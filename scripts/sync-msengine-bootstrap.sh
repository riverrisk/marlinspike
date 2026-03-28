#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

ENGINE_SRC="$ROOT_DIR/_ms_engine.py"
ENGINE_DST="$ROOT_DIR/msengine/msengine/engine.py"
OUI_SRC="$ROOT_DIR/data/oui.json"
OUI_DST="$ROOT_DIR/msengine/msengine/data/oui.json"
LICENSE_SRC="$ROOT_DIR/LICENSE"
LICENSE_DST="$ROOT_DIR/msengine/LICENSE"
VORACITY_DST="$ROOT_DIR/../voracity-modules/Recon_Discovery/VORACITY-MODULE-MARLINSPIKE.py"

mkdir -p "$(dirname "$ENGINE_DST")" "$(dirname "$OUI_DST")"

cp "$ENGINE_SRC" "$ENGINE_DST"
cp "$OUI_SRC" "$OUI_DST"
cp "$LICENSE_SRC" "$LICENSE_DST"

echo "Synced bootstrap msengine subtree:"
echo "  $ENGINE_DST"
echo "  $OUI_DST"
echo "  $LICENSE_DST"

if [[ -f "$VORACITY_DST" ]]; then
  cp "$ENGINE_SRC" "$VORACITY_DST"
  echo "Synced Voracity mirror:"
  echo "  $VORACITY_DST"
else
  echo "Voracity mirror not found, skipped:"
  echo "  $VORACITY_DST"
fi
