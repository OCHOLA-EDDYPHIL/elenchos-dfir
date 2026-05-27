#!/usr/bin/env bash
set -euo pipefail

CASE_ID="${CASE_ID:-CASE-AGENT-OPENCLAW-SMOKE}"
RUN_ROOT="${RUN_ROOT:-runs/$CASE_ID}"
MAX_ITERATIONS="${MAX_ITERATIONS:-7}"
PYTHON_BIN=".venv/bin/python"

case "$RUN_ROOT" in
  runs/*|outputs/*|analysis/*|reports/generated/*|*/runs/*|*/outputs/*|*/analysis/*|*/reports/generated/*)
    ;;
  *)
    echo "RUN_ROOT must be under runs/, outputs/, analysis/, or reports/generated/." >&2
    exit 2
    ;;
esac

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python executable is not available or executable: $PYTHON_BIN" >&2
  exit 2
fi

INPUT_DIR="$RUN_ROOT/synthetic-inputs"
OUTPUT_DIR="$RUN_ROOT/agent-run"
MANIFEST_PATH="$RUN_ROOT/manifest.json"
TRACE_DIR="$RUN_ROOT/openclaw-trace"

mkdir -p "$INPUT_DIR" "$OUTPUT_DIR" "$TRACE_DIR"

export CASE_ID INPUT_DIR MANIFEST_PATH

"$PYTHON_BIN" - <<'PY'
from __future__ import annotations

import csv
import hashlib
import os
from pathlib import Path

from siftguard.evidence.manifest import (
    EvidenceArtifact,
    EvidenceManifest,
    utc_now_z,
    write_manifest,
)

case_id = os.environ["CASE_ID"]
input_dir = Path(os.environ["INPUT_DIR"]).resolve()
manifest_path = Path(os.environ["MANIFEST_PATH"]).resolve()
observation_path = r"C:\ProgramData\SIFTGuard\demo-observation.exe"
observation_hash = "b" * 64


def write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerows(rows)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(path: Path, artifact_type: str, artifact_id: str) -> EvidenceArtifact:
    resolved = path.resolve()
    return EvidenceArtifact(
        artifact_id=artifact_id,
        path=str(resolved),
        relative_path=resolved.relative_to(input_dir).as_posix(),
        size_bytes=resolved.stat().st_size,
        sha256=sha256(resolved),
        artifact_type=artifact_type,
        discovered_at_utc=generated_at,
    )


generated_at = utc_now_z()
input_dir.mkdir(parents=True, exist_ok=True)

mft_csv = input_dir / "mftecmd.csv"
write_csv(
    mft_csv,
    [
        ["FullPath", "FileName", "Created0x10", "SHA256", "EntryNumber"],
        [
            observation_path,
            "demo-observation.exe",
            "2026-01-01 00:00:01",
            observation_hash,
            "1842",
        ],
    ],
)

amcache_csv = input_dir / "amcache.csv"
write_csv(
    amcache_csv,
    [
        ["FilePath", "ProgramName", "LastModifiedTimeUtc", "SHA256"],
        [
            observation_path,
            "demo-observation.exe",
            "2026-01-01 00:00:02",
            observation_hash,
        ],
    ],
)

runkeys_csv = input_dir / "runkeys.csv"
write_csv(
    runkeys_csv,
    [
        ["Hive", "KeyPath", "ValueName", "ValueData", "LastWriteTime"],
        [
            "NTUSER.DAT",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "DemoObservation",
            observation_path,
            "2026-01-01 00:00:03",
        ],
    ],
)

artifacts = [
    artifact(mft_csv, "mftecmd_csv", "EV-AGENT-SMOKE-MFT-001"),
    artifact(amcache_csv, "amcacheparser_csv", "EV-AGENT-SMOKE-AMCACHE-001"),
    artifact(runkeys_csv, "recmd_runkeys_csv", "EV-AGENT-SMOKE-REG-001"),
]
manifest = EvidenceManifest(
    case_id=case_id,
    generated_at_utc=generated_at,
    case_root=str(input_dir),
    artifact_count=len(artifacts),
    artifacts=artifacts,
)
write_manifest(manifest, manifest_path)
PY

if ! "$PYTHON_BIN" -m siftguard agent run \
  --case-id "$CASE_ID" \
  --manifest "$MANIFEST_PATH" \
  --output-dir "$OUTPUT_DIR" \
  --max-iterations "$MAX_ITERATIONS" \
  > "$TRACE_DIR/siftguard-agent-run.stdout" \
  2> "$TRACE_DIR/siftguard-agent-run.stderr"; then
  echo "siftguard agent run failed; see $TRACE_DIR/siftguard-agent-run.stdout and $TRACE_DIR/siftguard-agent-run.stderr." >&2
  exit 1
fi

for required in agent_run.json audit.jsonl findings.json report.md; do
  test -f "$OUTPUT_DIR/$required"
done

printf 'case_id=%s\n' "$CASE_ID"
printf 'manifest=%s\n' "$MANIFEST_PATH"
printf 'output_dir=%s\n' "$OUTPUT_DIR"
printf 'agent_run=%s\n' "$OUTPUT_DIR/agent_run.json"
printf 'audit=%s\n' "$OUTPUT_DIR/audit.jsonl"
printf 'findings=%s\n' "$OUTPUT_DIR/findings.json"
printf 'report=%s\n' "$OUTPUT_DIR/report.md"
printf 'openclaw_trace_dir=%s\n' "$TRACE_DIR"
