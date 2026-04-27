#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="$ROOT_DIR/collector/macOS Collectors.sh"

if [[ ! -x "$COLLECTOR" ]]; then
  chmod +x "$COLLECTOR"
fi

"$COLLECTOR"
