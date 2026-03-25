#!/usr/bin/env bash
# Convenience wrapper for a staging deploy target.
# Usage: REMOTE=deploy@staging-host ./deploy-dev.sh [--rebuild] [--ui-only]

set -euo pipefail

REMOTE="${REMOTE:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/marlinspike}"
BACKUP_DIR="${BACKUP_DIR:-${REMOTE_DIR}-backups}"

export REMOTE REMOTE_DIR BACKUP_DIR
exec "$(cd "$(dirname "$0")" && pwd)/deploy.sh" "$@"
