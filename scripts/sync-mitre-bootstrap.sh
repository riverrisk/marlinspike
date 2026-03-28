#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_ROOT="${MARLINSPIKE_MITRE_REPO:-$HOME/marlinspike-mitre}"

if [[ ! -d "$SOURCE_ROOT" ]]; then
  echo "marlinspike-mitre repo not found: $SOURCE_ROOT" >&2
  exit 1
fi

mkdir -p "$ROOT_DIR/plugins/marlinspike_mitre" "$ROOT_DIR/rules/mitre"

rsync -a --delete "$SOURCE_ROOT/plugins/marlinspike_mitre/" "$ROOT_DIR/plugins/marlinspike_mitre/"
rsync -a --delete "$SOURCE_ROOT/rules/mitre/" "$ROOT_DIR/rules/mitre/"

echo "Synced vendored marlinspike-mitre from $SOURCE_ROOT"
