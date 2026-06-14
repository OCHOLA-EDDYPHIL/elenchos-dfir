from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from siftguard.audit.execution_ledger import utc_now
from siftguard.evidence.hashing import sha256_file
from siftguard.policy.paths import is_relative_to

INTEGRITY_MANIFEST_NAME = "run_integrity_manifest.json"
VOLATILE_RUN_FILES = {"progress.jsonl", INTEGRITY_MANIFEST_NAME}


def _relative_run_path(output_dir: Path, path: Path) -> str:
    resolved_output_dir = output_dir.resolve()
    resolved_path = path.resolve()
    if not is_relative_to(resolved_path, resolved_output_dir):
        raise ValueError(f"integrity path escapes output_dir: {path}")
    return resolved_path.relative_to(resolved_output_dir).as_posix()


def iter_integrity_files(output_dir: Path) -> list[Path]:
    resolved_output_dir = output_dir.resolve()
    paths: list[Path] = []
    for path in sorted(resolved_output_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in VOLATILE_RUN_FILES:
            continue
        paths.append(path)
    return paths


def build_integrity_manifest(
    output_dir: Path,
    *,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    resolved_output_dir = output_dir.resolve()
    files = []
    for path in iter_integrity_files(resolved_output_dir):
        stat = path.stat()
        files.append(
            {
                "path": _relative_run_path(resolved_output_dir, path),
                "size_bytes": stat.st_size,
                "sha256": sha256_file(path),
            }
        )
    return {
        "schema_version": 1,
        "generated_at_utc": generated_at_utc or utc_now(),
        "hash_algorithm": "sha256",
        "volatile_exclusions": sorted(VOLATILE_RUN_FILES),
        "file_count": len(files),
        "files": files,
    }


def write_integrity_manifest(output_dir: Path) -> Path:
    path = output_dir.resolve() / INTEGRITY_MANIFEST_NAME
    payload = build_integrity_manifest(output_dir)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_integrity_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("integrity manifest must contain a JSON object")
    return payload


def validate_integrity_manifest(output_dir: Path) -> list[dict[str, Any]]:
    manifest_path = output_dir / INTEGRITY_MANIFEST_NAME
    if not manifest_path.is_file():
        return [
            {
                "path": INTEGRITY_MANIFEST_NAME,
                "reason": "missing_integrity_manifest",
            }
        ]

    try:
        payload = read_integrity_manifest(manifest_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [
            {
                "path": INTEGRITY_MANIFEST_NAME,
                "reason": "malformed_integrity_manifest",
                "error": str(exc),
            }
        ]
    rows = payload.get("files")
    if not isinstance(rows, list):
        return [{"path": INTEGRITY_MANIFEST_NAME, "reason": "files_not_list"}]

    violations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            violations.append({"path": None, "reason": "file_entry_not_object"})
            continue
        rel_path = row.get("path")
        expected_size = row.get("size_bytes")
        expected_sha256 = row.get("sha256")
        if not isinstance(rel_path, str) or not rel_path:
            violations.append({"path": rel_path, "reason": "invalid_path"})
            continue
        seen.add(rel_path)
        path = (output_dir / rel_path).resolve()
        if not is_relative_to(path, output_dir.resolve()):
            violations.append({"path": rel_path, "reason": "path_escapes_output_dir"})
            continue
        if not path.is_file():
            violations.append({"path": rel_path, "reason": "missing_file"})
            continue
        stat = path.stat()
        if not isinstance(expected_size, int) or expected_size != stat.st_size:
            violations.append(
                {
                    "path": rel_path,
                    "reason": "size_mismatch",
                    "expected_size_bytes": expected_size,
                    "actual_size_bytes": stat.st_size,
                }
            )
        if not isinstance(expected_sha256, str) or expected_sha256 != sha256_file(path):
            violations.append({"path": rel_path, "reason": "sha256_mismatch"})

    current_paths = {
        _relative_run_path(output_dir, path) for path in iter_integrity_files(output_dir)
    }
    for rel_path in sorted(current_paths - seen):
        violations.append({"path": rel_path, "reason": "unexpected_file"})

    expected_count = payload.get("file_count")
    if isinstance(expected_count, int) and expected_count != len(rows):
        violations.append(
            {
                "path": INTEGRITY_MANIFEST_NAME,
                "reason": "file_count_mismatch",
                "expected_file_count": expected_count,
                "actual_file_count": len(rows),
            }
        )

    return violations
