from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from elenchos.case_prep.models import (
    SourceManifest,
    SourceRecord,
    source_id_for,
    source_set_id_for,
    utc_now_z,
)

YAML_REJECTION = (
    "YAML source manifests are not supported in the final sprint; use JSON or "
    "source-root discovery."
)


def reject_yaml_manifest_path(path: Path) -> None:
    if path.suffix.casefold() in {".yaml", ".yml"}:
        raise ValueError(YAML_REJECTION)


def require_json_manifest_path(path: Path) -> None:
    reject_yaml_manifest_path(path)
    if path.suffix.casefold() != ".json":
        raise ValueError("source manifests must use .json")


def default_source_manifest_path(case_id: str) -> Path:
    return Path(".local") / "cases" / case_id / "source-manifest.json"


def _source_classification(path: Path) -> tuple[str, str, str, str] | None:
    suffix = path.suffix.casefold()
    if suffix == ".e01":
        return "disk_image", "ewf_e01", "available", "primary"
    if suffix in {".raw", ".mem"}:
        return (
            "memory_image",
            "raw",
            "staged_not_analyzed",
            "out_of_scope_for_final_submission",
        )
    if suffix == ".zip":
        return "archive", "zip", "unsupported", "inventory_only"
    if suffix == ".7z":
        return "archive", "7z", "unsupported", "inventory_only"
    if suffix == ".pptx":
        return "case_background", "pptx", "available", "case_context"
    return None


def discover_source_root(
    *,
    case_id: str,
    source_root: Path,
    clock: Any = utc_now_z,
) -> SourceManifest:
    resolved_root = source_root.resolve()
    if not resolved_root.exists():
        raise FileNotFoundError(f"source_root does not exist: {source_root}")
    if not resolved_root.is_dir():
        raise NotADirectoryError(f"source_root must be a directory: {source_root}")

    sources: list[SourceRecord] = []
    for path in sorted(resolved_root.rglob("*")):
        if not path.is_file():
            continue
        classification = _source_classification(path)
        if classification is None:
            continue
        role, kind, status, analysis_scope = classification
        relative_path = path.relative_to(resolved_root).as_posix()
        sources.append(
            SourceRecord(
                source_id=source_id_for(
                    case_id=case_id,
                    source_ref=relative_path,
                    role=role,
                    kind=kind,
                ),
                role=role,
                kind=kind,
                display_name=path.name,
                source_ref=relative_path,
                sanitized_path=relative_path,
                size_bytes=path.stat().st_size,
                sha256=None,
                hash_status="not_requested",
                status=status,
                analysis_scope=analysis_scope,
                local_path=str(path.resolve()),
            )
        )

    source_set_id = source_set_id_for(case_id, sources)
    return SourceManifest(
        case_id=case_id,
        source_set_id=source_set_id,
        created_at=clock(),
        source_root=str(resolved_root),
        sources=sources,
    )


def read_source_manifest(path: Path) -> SourceManifest:
    require_json_manifest_path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed source manifest JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("source manifest JSON must contain an object")
    return SourceManifest.from_dict(payload)


def write_source_manifest(
    manifest: SourceManifest,
    path: Path,
    *,
    include_local_paths: bool,
) -> None:
    require_json_manifest_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = manifest.to_dict(include_local_paths=include_local_paths)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
