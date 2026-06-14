from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elenchos.case_prep.models import CASE_PREP_SCHEMA_VERSION
from elenchos.evidence.manifest import EvidenceArtifact, EvidenceManifest, utc_now_z

AGENT_ARTIFACT_TYPE_BY_PREP_TYPE = {
    "amcache_hive": "amcache",
    "mft": "mft",
    "registry_hive": "registry_hive",
}


@dataclass(slots=True)
class AdaptedCaseManifest:
    case_id: str
    case_prep_path: Path
    evidence_manifest: EvidenceManifest
    sources: list[dict[str, Any]]
    prepared_artifacts: list[dict[str, Any]]
    skipped_prepared_artifacts: list[dict[str, Any]]
    coverage_gaps: list[dict[str, Any]]
    memory_sources: list[dict[str, Any]]
    case_background_sources: list[dict[str, Any]]
    warnings: list[str]
    source_roots: list[Path]


def load_case_prep_manifest(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.exists():
        raise ValueError(f"artifact manifest does not exist: {path}")
    if resolved.is_dir():
        raise ValueError(f"artifact manifest path is a directory: {path}")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed artifact manifest JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("artifact manifest JSON must contain an object")
    return payload


def _required_string(data: dict[str, Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"case_prep.{name} must be a non-empty string")
    return value


def _optional_string(data: dict[str, Any], name: str) -> str | None:
    value = data.get(name)
    return value if isinstance(value, str) and value else None


def _list_of_objects(data: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = data.get(name)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"case_prep.{name} must be a list of objects")
    return [dict(item) for item in value]


def _source_label(source: dict[str, Any]) -> str:
    for key in ("display_name", "source_ref", "sanitized_path", "source_id"):
        value = source.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown-source"


def _source_roots_from_payload(
    payload: dict[str, Any],
    sources: list[dict[str, Any]],
) -> list[Path]:
    roots: list[Path] = []
    source_root = payload.get("source_root")
    if isinstance(source_root, str) and source_root:
        roots.append(Path(source_root))
    for source in sources:
        local_path = source.get("local_path")
        if isinstance(local_path, str) and local_path:
            roots.append(Path(local_path).parent)
    return roots


def _validate_sources(sources: list[dict[str, Any]]) -> None:
    if not sources:
        raise ValueError("case_prep.sources must not be empty")
    for index, source in enumerate(sources):
        for key in ("source_id", "role", "kind", "display_name", "status", "analysis_scope"):
            value = source.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(f"case_prep.sources[{index}].{key} must be a non-empty string")


def _validate_coverage_gaps(gaps: list[dict[str, Any]]) -> None:
    for index, gap in enumerate(gaps):
        for key in ("gap_id", "artifact_type", "source_id", "reason", "impact"):
            value = gap.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"case_prep.coverage_gaps[{index}].{key} must be a non-empty string"
                )


def _adapted_artifact(
    *,
    case_root: Path,
    prepared_artifact: dict[str, Any],
    source_by_id: dict[str, dict[str, Any]],
) -> EvidenceArtifact:
    artifact_id = _required_string(prepared_artifact, "artifact_id")
    prepared_type = _required_string(prepared_artifact, "artifact_type")
    source_id = _required_string(prepared_artifact, "source_id")
    relative_path = _required_string(prepared_artifact, "path")
    if prepared_type not in AGENT_ARTIFACT_TYPE_BY_PREP_TYPE:
        raise ValueError(f"unsupported prepared artifact type: {prepared_type}")
    if source_id not in source_by_id:
        raise ValueError(f"prepared artifact {artifact_id} references unknown source_id")
    if Path(relative_path).is_absolute() or ".." in Path(relative_path).parts:
        raise ValueError(f"prepared artifact path is not safe: {relative_path}")

    path = (case_root / relative_path).resolve()
    size_bytes = path.stat().st_size if path.exists() and path.is_file() else 0
    source = source_by_id[source_id]
    return EvidenceArtifact(
        artifact_id=artifact_id,
        path=relative_path,
        relative_path=relative_path,
        size_bytes=size_bytes,
        sha256=prepared_artifact.get("sha256"),  # type: ignore[arg-type]
        artifact_type=AGENT_ARTIFACT_TYPE_BY_PREP_TYPE[prepared_type],
        discovered_at_utc=utc_now_z(),
        source_image_id=source_id,
        source_image_label=_source_label(source),
        registry_hive_type=_optional_string(prepared_artifact, "registry_hive_type"),
        profile_id=_optional_string(prepared_artifact, "profile_id"),
        profile_display_name=_optional_string(prepared_artifact, "profile_display_name"),
        sanitized_profile_hint=_optional_string(prepared_artifact, "sanitized_profile_hint"),
        source_candidate_ref=_optional_string(prepared_artifact, "source_candidate_ref"),
    )


def adapt_case_prep_to_evidence_manifest(
    *,
    case_prep_path: Path,
    requested_case_id: str | None,
) -> AdaptedCaseManifest:
    resolved_path = case_prep_path.resolve()
    payload = load_case_prep_manifest(resolved_path)
    case_id = _required_string(payload, "case_id")
    if requested_case_id is not None and requested_case_id != case_id:
        raise ValueError(
            f"artifact manifest case_id '{case_id}' does not match requested case_id "
            f"'{requested_case_id}'"
        )

    schema_version = payload.get("schema_version", CASE_PREP_SCHEMA_VERSION)
    if schema_version != CASE_PREP_SCHEMA_VERSION:
        raise ValueError(f"unsupported case_prep schema_version: {schema_version}")

    sources = _list_of_objects(payload, "sources")
    prepared_artifacts = _list_of_objects(payload, "prepared_artifacts")
    coverage_gaps = _list_of_objects(payload, "coverage_gaps")
    warnings_raw = payload.get("warnings", [])
    if not isinstance(warnings_raw, list) or not all(
        isinstance(item, str) for item in warnings_raw
    ):
        raise ValueError("case_prep.warnings must be a list of strings")

    _validate_sources(sources)
    _validate_coverage_gaps(coverage_gaps)

    source_by_id = {source["source_id"]: source for source in sources}
    adapted_artifacts: list[EvidenceArtifact] = []
    skipped_prepared_artifacts: list[dict[str, Any]] = []
    case_root = resolved_path.parent

    for index, artifact in enumerate(prepared_artifacts):
        artifact_id = artifact.get("artifact_id", f"prepared_artifacts[{index}]")
        status = artifact.get("status")
        parser_eligible = artifact.get("parser_eligible")
        artifact_type = artifact.get("artifact_type")
        if status == "available" and parser_eligible is True:
            if artifact_type in AGENT_ARTIFACT_TYPE_BY_PREP_TYPE:
                adapted_artifacts.append(
                    _adapted_artifact(
                        case_root=case_root,
                        prepared_artifact=artifact,
                        source_by_id=source_by_id,
                    )
                )
                continue
        skipped = dict(artifact)
        skipped["skip_reason"] = (
            "not parser eligible"
            if parser_eligible is not True
            else f"status={status} artifact_type={artifact_type}"
        )
        skipped["artifact_id"] = artifact_id
        skipped_prepared_artifacts.append(skipped)

    evidence_manifest = EvidenceManifest(
        case_id=case_id,
        generated_at_utc=utc_now_z(),
        case_root=str(case_root),
        artifact_count=len(adapted_artifacts),
        artifacts=sorted(adapted_artifacts, key=lambda item: item.relative_path),
    )
    return AdaptedCaseManifest(
        case_id=case_id,
        case_prep_path=resolved_path,
        evidence_manifest=evidence_manifest,
        sources=sources,
        prepared_artifacts=prepared_artifacts,
        skipped_prepared_artifacts=skipped_prepared_artifacts,
        coverage_gaps=coverage_gaps,
        memory_sources=[
            source for source in sources if source.get("role") == "memory_image"
        ],
        case_background_sources=[
            source for source in sources if source.get("role") == "case_background"
        ],
        warnings=list(warnings_raw),
        source_roots=_source_roots_from_payload(payload, sources),
    )
