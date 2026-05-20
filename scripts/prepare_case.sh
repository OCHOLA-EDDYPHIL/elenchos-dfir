#!/usr/bin/env bash
set -euo pipefail

mkdir -p cases/official/raw cases/official/selected runs

echo "Created: cases/official/raw cases/official/selected runs"
echo "Reminder: evidence and case data are gitignored and must not be committed."
echo "Dataset download is intentionally manual; this script does not fetch large datasets."
