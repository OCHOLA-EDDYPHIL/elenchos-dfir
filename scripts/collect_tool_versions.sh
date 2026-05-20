#!/usr/bin/env bash
set -euo pipefail

mkdir -p runs
out_file="runs/tool_versions.txt"

{
  date -u +"captured_at_utc=%Y-%m-%dT%H:%M:%SZ"

  if command -v python >/dev/null 2>&1; then
    python --version 2>&1
  fi
  if command -v git >/dev/null 2>&1; then
    git --version 2>&1
  fi
  if command -v gh >/dev/null 2>&1; then
    gh --version 2>&1 | head -n 1
  fi
  if command -v volatility3 >/dev/null 2>&1; then
    volatility3 --version 2>&1 || true
  elif command -v vol >/dev/null 2>&1; then
    vol --version 2>&1 || true
  fi
  if command -v log2timeline.py >/dev/null 2>&1; then
    log2timeline.py --version 2>&1 || true
  fi
  if command -v psort.py >/dev/null 2>&1; then
    psort.py --version 2>&1 || true
  fi
  if command -v fls >/dev/null 2>&1; then
    fls -V 2>&1 || true
  fi
  if command -v mmls >/dev/null 2>&1; then
    mmls -V 2>&1 || true
  fi
  if command -v yara >/dev/null 2>&1; then
    yara --version 2>&1 || true
  fi
} > "$out_file"

echo "Wrote $out_file"
