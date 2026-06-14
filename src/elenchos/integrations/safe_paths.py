from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from elenchos.policy.paths import (
    MOUNTED_EVIDENCE_ROOT,
    generated_output_display_path,
    is_generated_output_path,
    is_relative_to,
    validate_generated_output_dir,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCAL_CONFIG_ROOT = ".local"
SOURCE_MANIFEST_FILENAME_SUFFIX = ".json"


def repo_root() -> Path:
    return REPO_ROOT


def _reject_bad_path_text(value: str, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must be a non-empty path string")
    if "\x00" in value:
        raise ValueError(f"{field_name} contains a NUL byte")
    parts = Path(value).parts
    if ".." in parts:
        raise ValueError(f"path traversal detected in {field_name}: {value}")


def resolve_user_path(value: str, field_name: str) -> Path:
    _reject_bad_path_text(value, field_name)
    path = Path(value).expanduser()
    if path.is_absolute():
        return path.resolve()
    resolved = (REPO_ROOT / path).resolve()
    if not is_relative_to(resolved, REPO_ROOT):
        raise ValueError(f"path traversal detected in {field_name}: {value}")
    return resolved


def require_json_path(path: Path, field_name: str) -> None:
    if path.suffix.casefold() != SOURCE_MANIFEST_FILENAME_SUFFIX:
        raise ValueError(f"{field_name} must be a JSON path")


def display_path(path: Path | str | None) -> str | None:
    if path is None:
        return None
    resolved = Path(path).resolve()
    if is_generated_output_path(resolved):
        return generated_output_display_path(resolved)
    if is_relative_to(resolved, REPO_ROOT):
        return resolved.relative_to(REPO_ROOT).as_posix()
    return resolved.name


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed {label} JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} JSON must contain an object")
    return payload


def _root_from_string(value: object) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return Path(value).expanduser().resolve()
    except OSError:
        return None


def evidence_roots_from_source_manifest(path: Path) -> list[Path]:
    payload = _read_json_object(path, "source manifest")
    roots: list[Path] = []
    source_root = _root_from_string(payload.get("source_root"))
    if source_root is not None:
        roots.append(source_root)
    sources = payload.get("sources", [])
    if isinstance(sources, list):
        for source in sources:
            if not isinstance(source, dict):
                continue
            local_path = _root_from_string(source.get("local_path"))
            if local_path is not None:
                roots.append(local_path.parent)
    return dedupe_paths(roots)


def evidence_roots_from_case_prep(path: Path) -> list[Path]:
    payload = _read_json_object(path, "case_prep")
    roots: list[Path] = []
    source_root = _root_from_string(payload.get("source_root"))
    if source_root is not None:
        roots.append(source_root)
    sources = payload.get("sources", [])
    if isinstance(sources, list):
        for source in sources:
            if not isinstance(source, dict):
                continue
            local_path = _root_from_string(source.get("local_path"))
            if local_path is not None:
                roots.append(local_path.parent)
    roots.append(path.resolve().parent)
    return dedupe_paths(roots)


def dedupe_paths(paths: list[Path] | tuple[Path, ...]) -> list[Path]:
    seen: set[str] = set()
    output: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        key = resolved.as_posix()
        if key in seen:
            continue
        seen.add(key)
        output.append(resolved)
    return output


def validate_integration_output_dir(
    output_dir: str,
    *,
    forbidden_roots: list[Path] | tuple[Path, ...] = (),
) -> Path:
    resolved = resolve_user_path(output_dir, "output_dir")
    return validate_generated_output_dir(
        resolved,
        forbidden_roots=tuple(dedupe_paths(list(forbidden_roots))),
        evidence_root=MOUNTED_EVIDENCE_ROOT,
    )


def validate_generated_read_dir(output_dir: str) -> Path:
    resolved = resolve_user_path(output_dir, "output_dir")
    if not is_generated_output_path(resolved):
        raise ValueError(
            "output_dir must be under an ignored generated output path such as "
            "runs/, outputs/, analysis/, or reports/generated/"
        )
    if is_relative_to(resolved, MOUNTED_EVIDENCE_ROOT):
        raise ValueError(f"output_dir must not be under evidence root '{MOUNTED_EVIDENCE_ROOT}'")
    return resolved


def validate_source_manifest_out(path_text: str, *, forbidden_roots: list[Path]) -> Path:
    resolved = resolve_user_path(path_text, "source_manifest_out")
    require_json_path(resolved, "source_manifest_out")
    if is_relative_to(resolved, MOUNTED_EVIDENCE_ROOT):
        raise ValueError("source_manifest_out must not be under /mnt/evidence")
    for root in forbidden_roots:
        if is_relative_to(resolved, root):
            raise ValueError(f"source_manifest_out must not be under evidence root '{root}'")
    if is_generated_output_path(resolved):
        return resolved
    try:
        relative = resolved.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError(
            "source_manifest_out must be under .local/ or a generated output path"
        ) from exc
    if not relative.parts or relative.parts[0] != LOCAL_CONFIG_ROOT:
        raise ValueError("source_manifest_out must be under .local/ or a generated output path")
    return resolved
