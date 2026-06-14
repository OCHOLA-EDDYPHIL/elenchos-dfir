#!/usr/bin/env bash
set -euo pipefail

if [ ! -d "cases/official/selected" ] || [ -z "$(find cases/official/selected -type f -print -quit 2>/dev/null || true)" ]; then
  echo "No demo case artifacts found under cases/official/selected."
  echo "Run ./scripts/prepare_case.sh and place selected artifacts locally before demo."
  exit 1
fi

echo "Demo placeholder commands:"
echo "  elenchos inventory cases/official/selected --manifest-out runs/case_demo_001/manifest.json"
echo "  elenchos hash cases/official/selected/<artifact>"
echo "  # parser/correlation/reporting steps will be added in later milestones"
