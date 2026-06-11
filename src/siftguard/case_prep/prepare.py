from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from siftguard.audit.execution_ledger import append_event, make_event_id
from siftguard.case_prep.extractors import (
    CasePrepExtractor,
    ExtractorContext,
    SiftEwfExtractor,
)
from siftguard.case_prep.models import (
    ArtifactSidecar,
    ArtifactTarget,
    CasePrepManifest,
    CoverageGap,
    ExtractionOutcome,
    PreparedArtifact,
    SourceManifest,
    SourceRecord,
    artifact_id_for,
    gap_id_for,
    utc_now_z,
)
from siftguard.case_prep.source_discovery import (
    default_source_manifest_path,
    discover_source_root,
    read_source_manifest,
    reject_yaml_manifest_path,
    require_json_manifest_path,
    write_source_manifest,
)
from siftguard.evidence.hashing import sha256_file
from siftguard.parser.paths import validate_parser_path_identifier
from siftguard.policy.paths import (
    generated_output_display_path,
    is_relative_to,
    validate_generated_output_dir,
)
from siftguard.progress import append_progress_event, progress_path_for_output_dir


@dataclass(slots=True)
class CasePrepareResult:
    manifest: CasePrepManifest
    output_dir: Path
    case_prep_path: Path
    source_manifest_path: Path
    source_image_manifest_path: Path
    extraction_audit_path: Path
    warnings_path: Path
    local_source_manifest_path: Path | None = None


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _resolve_output_path(output_dir: Path, relative_path: str) -> Path:
    path = (output_dir / relative_path).resolve()
    if not is_relative_to(path, output_dir):
        raise ValueError(f"output path escapes output_dir: {relative_path}")
    return path


def _append_case_prep_audit(
    audit_path: Path,
    *,
    case_id: str,
    event_type: str,
    status: str,
    clock: Any,
    details: dict[str, Any] | None = None,
) -> None:
    existing_count = 0
    if audit_path.exists():
        with audit_path.open("r", encoding="utf-8") as handle:
            existing_count = sum(1 for line in handle if line.strip())
    event = {
        "case_id": case_id,
        "event_id": make_event_id(existing_count + 1),
        "event_type": event_type,
        "status": status,
        "timestamp_utc": clock(),
    }
    if details:
        event.update(details)
    append_event(audit_path, event)


def _source_roots_for_safety(manifest: SourceManifest) -> list[Path]:
    roots: list[Path] = []
    if manifest.source_root is not None:
        roots.append(Path(manifest.source_root))
    for source in manifest.sources:
        if source.local_path is None:
            continue
        roots.append(Path(source.local_path).parent)
    return roots


def _resolve_source_path(manifest: SourceManifest, source: SourceRecord) -> Path | None:
    if source.local_path is not None:
        return Path(source.local_path).resolve()
    if manifest.source_root is not None:
        return (Path(manifest.source_root) / source.source_ref).resolve()
    return None


def _refresh_source_status(manifest: SourceManifest) -> SourceManifest:
    refreshed: list[SourceRecord] = []
    for source in manifest.sources:
        source_path = _resolve_source_path(manifest, source)
        status = source.status
        size_bytes = source.size_bytes
        if source_path is None or not source_path.exists():
            status = "missing"
        elif source_path.is_file():
            size_bytes = source_path.stat().st_size
        refreshed.append(
            SourceRecord(
                source_id=source.source_id,
                role=source.role,
                kind=source.kind,
                display_name=source.display_name,
                source_ref=source.source_ref,
                sanitized_path=source.sanitized_path,
                size_bytes=size_bytes,
                sha256=source.sha256,
                hash_status=source.hash_status,
                status=status,
                analysis_scope=source.analysis_scope,
                local_path=str(source_path) if source_path is not None else None,
            )
        )
    return SourceManifest(
        case_id=manifest.case_id,
        source_set_id=manifest.source_set_id,
        created_at=manifest.created_at,
        source_root=manifest.source_root,
        sources=refreshed,
    )


def _impact_for_target(target: ArtifactTarget) -> str:
    if target.target_id == "mft":
        return "$MFT coverage is unavailable; file timeline coverage is incomplete."
    if target.target_id == "software":
        return "SOFTWARE hive coverage is unavailable; machine Run key coverage is incomplete."
    if target.registry_hive_type == "ntuser" or target.target_id == "ntuser":
        if target.profile_id:
            return (
                f"NTUSER.DAT coverage is unavailable for {target.profile_id}; "
                "Registry user-activity coverage is incomplete."
            )
        return (
            "NTUSER.DAT coverage is unavailable; Registry user-activity coverage "
            "is incomplete."
        )
    return "Amcache coverage is unavailable; execution metadata coverage is incomplete."


def _next_step_for_target(target: ArtifactTarget, reason: str) -> str:
    if reason == "extractor_unavailable":
        return "Install or enable ewfinfo, ewfmount, mmls, fls, and icat, then rerun case prepare."
    if reason in {"tool_error", "extraction_failed"}:
        return "Review extraction_audit.jsonl and extractor stderr logs under the run output."
    if target.target_id == "amcache":
        return (
            "Review disk path Windows/AppCompat/Programs/Amcache.hve or confirm "
            "artifact absence manually."
        )
    if target.registry_hive_type == "ntuser" or target.target_id == "ntuser":
        return "Review user profile hives on disk or confirm NTUSER.DAT absence manually."
    return f"Review disk source for {target.display_name} or confirm artifact absence manually."


def _coverage_gap_for_outcome(
    *,
    source: SourceRecord,
    outcome: ExtractionOutcome,
) -> CoverageGap | None:
    if outcome.status == "available":
        return None
    reason = outcome.reason or "not_found"
    artifact_type = outcome.target.artifact_type
    artifact_family = None
    if outcome.target.registry_hive_type == "ntuser" or outcome.target.target_id == "ntuser":
        artifact_type = "ntuser_hive"
        artifact_family = "registry_user_activity"
    return CoverageGap(
        gap_id=gap_id_for(
            source_id=source.source_id,
            target_id=outcome.target.target_id,
            reason=reason,
        ),
        artifact_type=artifact_type,
        source_id=source.source_id,
        reason=reason,
        impact=_impact_for_target(outcome.target),
        recommended_next_step=_next_step_for_target(outcome.target, reason),
        artifact_family=artifact_family,
        source_artifact_id=artifact_id_for(
            source_id=source.source_id,
            target_id=outcome.target.target_id,
            output_path=outcome.target.output_path,
        ),
        profile_id=outcome.target.profile_id,
        profile_display_name=outcome.target.profile_display_name,
        sanitized_profile_hint=outcome.target.sanitized_profile_hint,
        source_candidate_ref=outcome.target.source_candidate_ref,
    )


def _artifact_for_outcome(
    *,
    output_dir: Path,
    source: SourceRecord,
    outcome: ExtractionOutcome,
) -> PreparedArtifact:
    artifact_path = _resolve_output_path(output_dir, outcome.target.output_path)
    sha256: str | None = None
    hash_status = "skipped"
    if outcome.status == "available" and artifact_path.exists() and artifact_path.is_file():
        try:
            sha256 = sha256_file(artifact_path)
            hash_status = "computed"
        except OSError:
            hash_status = "failed"

    sidecars: list[ArtifactSidecar] = []
    for sidecar in outcome.sidecars:
        sidecar_sha256: str | None = None
        sidecar_hash_status = "skipped"
        sidecar_path = _resolve_output_path(output_dir, sidecar.path)
        if sidecar.status == "available" and sidecar_path.exists() and sidecar_path.is_file():
            try:
                sidecar_sha256 = sha256_file(sidecar_path)
                sidecar_hash_status = "computed"
            except OSError:
                sidecar_hash_status = "failed"
        sidecars.append(
            ArtifactSidecar(
                role=sidecar.role,
                display_name=sidecar.display_name,
                path=sidecar.path,
                source_candidate_ref=sidecar.source_candidate_ref,
                status=sidecar.status,
                sha256=sidecar_sha256,
                hash_status=sidecar_hash_status,
                warnings=list(sidecar.warnings),
            )
        )

    return PreparedArtifact(
        artifact_id=artifact_id_for(
            source_id=source.source_id,
            target_id=outcome.target.target_id,
            output_path=outcome.target.output_path,
        ),
        artifact_type=outcome.target.artifact_type,
        source_id=source.source_id,
        source_role=source.role,
        path=outcome.target.output_path,
        parser_eligible=outcome.status == "available",
        status=outcome.status,
        sha256=sha256,
        hash_status=hash_status,
        extraction_method=outcome.extraction_method,
        warnings=list(outcome.warnings),
        registry_hive_type=outcome.target.registry_hive_type,
        profile_id=outcome.target.profile_id,
        profile_display_name=outcome.target.profile_display_name,
        sanitized_profile_hint=outcome.target.sanitized_profile_hint,
        source_candidate_ref=outcome.target.source_candidate_ref,
        sidecars=sidecars,
    )


def _hash_gap_for_artifact(
    *,
    source: SourceRecord,
    artifact: PreparedArtifact,
) -> CoverageGap | None:
    if artifact.hash_status != "failed":
        return None
    artifact_type = (
        "ntuser_hive" if artifact.registry_hive_type == "ntuser" else artifact.artifact_type
    )
    artifact_family = (
        "registry_user_activity" if artifact.registry_hive_type == "ntuser" else None
    )
    return CoverageGap(
        gap_id=gap_id_for(
            source_id=source.source_id,
            target_id=artifact.artifact_id,
            reason="hash_failed",
        ),
        artifact_type=artifact_type,
        source_id=source.source_id,
        reason="hash_failed",
        impact=f"Hashing failed for prepared artifact {artifact.artifact_id}.",
        recommended_next_step="Review filesystem permissions and rerun case prepare.",
        artifact_family=artifact_family,
        source_artifact_id=artifact.artifact_id,
        profile_id=artifact.profile_id,
        profile_display_name=artifact.profile_display_name,
        sanitized_profile_hint=artifact.sanitized_profile_hint,
        source_candidate_ref=artifact.source_candidate_ref,
    )


def _status_for_run(
    *,
    disk_sources: list[SourceRecord],
    prepared_artifacts: list[PreparedArtifact],
    coverage_gaps: list[CoverageGap],
) -> str:
    if not disk_sources:
        return "failed"
    available_count = sum(1 for artifact in prepared_artifacts if artifact.status == "available")
    if available_count == 0 and coverage_gaps:
        return "partial_success"
    if coverage_gaps:
        return "partial_success"
    return "completed"


def _source_image_manifest(manifest: SourceManifest) -> dict[str, Any]:
    return {
        "case_id": manifest.case_id,
        "created_at": manifest.created_at,
        "schema_version": 1,
        "source_count": len(manifest.sources),
        "source_set_id": manifest.source_set_id,
        "sources": [
            source.to_dict(include_local_paths=False)
            for source in sorted(manifest.sources, key=lambda item: item.source_id)
        ],
    }


def _warnings_payload(case_id: str, warnings: list[str]) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "warning_count": len(warnings),
        "warnings": list(warnings),
    }


def _load_or_discover_manifest(
    *,
    case_id: str,
    source_root: Path | None,
    source_manifest_path: Path | None,
    source_manifest_out: Path | None,
    clock: Any,
) -> tuple[SourceManifest, Path | None]:
    if source_root is not None and source_manifest_path is not None:
        raise ValueError("--source-root and --source-manifest are mutually exclusive")
    if source_root is None and source_manifest_path is None:
        raise ValueError("one of --source-root or --source-manifest is required")
    if source_manifest_out is not None and source_root is None:
        raise ValueError("--source-manifest-out is allowed only with --source-root")

    if source_manifest_path is not None:
        reject_yaml_manifest_path(source_manifest_path)
        manifest = read_source_manifest(source_manifest_path)
        if manifest.case_id != case_id:
            raise ValueError(
                f"source manifest case_id '{manifest.case_id}' does not match '{case_id}'"
            )
        return manifest, None

    if source_root is None:
        raise ValueError("source_root is required for source discovery")

    manifest = discover_source_root(case_id=case_id, source_root=source_root, clock=clock)
    local_manifest_path = source_manifest_out or default_source_manifest_path(case_id)
    require_json_manifest_path(local_manifest_path)
    return manifest, local_manifest_path


def _primary_disk_sources(manifest: SourceManifest) -> list[SourceRecord]:
    return [
        source
        for source in sorted(manifest.sources, key=lambda item: item.source_ref)
        if (
            source.role == "disk_image"
            and source.status == "available"
            and source.analysis_scope == "primary"
        )
    ]


def prepare_case(
    *,
    case_id: str,
    output_dir: Path,
    source_root: Path | None = None,
    source_manifest_path: Path | None = None,
    source_manifest_out: Path | None = None,
    extractor: CasePrepExtractor | None = None,
    clock: Any = utc_now_z,
) -> CasePrepareResult:
    case_id = validate_parser_path_identifier(case_id, "case_id")
    manifest, local_manifest_path = _load_or_discover_manifest(
        case_id=case_id,
        source_root=source_root,
        source_manifest_path=source_manifest_path,
        source_manifest_out=source_manifest_out,
        clock=clock,
    )
    manifest = _refresh_source_status(manifest)

    resolved_output_dir = validate_generated_output_dir(
        output_dir,
        forbidden_roots=tuple(_source_roots_for_safety(manifest)),
    )
    resolved_output_dir.mkdir(parents=True, exist_ok=True)
    progress_path = progress_path_for_output_dir(resolved_output_dir)
    append_progress_event(
        progress_path,
        case_id=case_id,
        phase="prepare_case",
        status="started",
        message=f"prepare_case started for {len(manifest.sources)} source(s)",
        timestamp=clock(),
    )
    if local_manifest_path is not None:
        write_source_manifest(manifest, local_manifest_path, include_local_paths=True)

    case_prep_path = _resolve_output_path(resolved_output_dir, "case_prep.json")
    source_manifest_copy_path = _resolve_output_path(resolved_output_dir, "source_manifest.json")
    source_image_manifest_path = _resolve_output_path(
        resolved_output_dir,
        "source_image_manifest.json",
    )
    extraction_audit_path = _resolve_output_path(resolved_output_dir, "extraction_audit.jsonl")
    warnings_path = _resolve_output_path(resolved_output_dir, "warnings.json")

    warnings: list[str] = []
    for source in manifest.sources:
        if source.role == "memory_image":
            warnings.append(
                f"{source.display_name}: memory source inventoried only; "
                "final scope excludes memory forensics"
            )
        elif source.role == "archive":
            warnings.append(f"{source.display_name}: archive source inventoried only")

    _append_case_prep_audit(
        extraction_audit_path,
        case_id=case_id,
        event_type="case_prepare_started",
        status="started",
        clock=clock,
        details={"source_count": len(manifest.sources)},
    )

    active_extractor = extractor or SiftEwfExtractor()
    disk_sources = _primary_disk_sources(manifest)
    prepared_artifacts: list[PreparedArtifact] = []
    coverage_gaps: list[CoverageGap] = []
    if not disk_sources:
        warnings.append("no available primary disk image source was discovered")
    else:
        if len(disk_sources) > 1:
            warnings.append(
                "multiple primary disk image sources discovered; extracting the first by source_ref"
            )
        source = disk_sources[0]
        source_path = _resolve_source_path(manifest, source)
        if source_path is None:
            warnings.append(f"{source.display_name}: no local path available for extraction")
        else:
            outcomes = active_extractor.extract(
                ExtractorContext(
                    case_id=case_id,
                    source=source,
                    source_path=source_path,
                    output_dir=resolved_output_dir,
                    audit_path=extraction_audit_path,
                )
            )
            profile_outcome_count = sum(
                1 for outcome in outcomes if outcome.target.profile_id is not None
            )
            if profile_outcome_count:
                warnings.append(
                    f"discovered {profile_outcome_count} user profile NTUSER.DAT "
                    "hive candidate(s)"
                )
            for outcome in outcomes:
                artifact = _artifact_for_outcome(
                    output_dir=resolved_output_dir,
                    source=source,
                    outcome=outcome,
                )
                prepared_artifacts.append(artifact)
                warnings.extend(outcome.warnings)
                for sidecar in artifact.sidecars:
                    warnings.extend(sidecar.warnings)
                gap = _coverage_gap_for_outcome(source=source, outcome=outcome)
                if gap is not None:
                    coverage_gaps.append(gap)
                hash_gap = _hash_gap_for_artifact(source=source, artifact=artifact)
                if hash_gap is not None:
                    coverage_gaps.append(hash_gap)
                _append_case_prep_audit(
                    extraction_audit_path,
                    case_id=case_id,
                    event_type="artifact_prepared",
                    status=artifact.status,
                    clock=clock,
                    details={
                        "artifact_id": artifact.artifact_id,
                        "artifact_type": artifact.artifact_type,
                        "path": artifact.path,
                        "profile_id": artifact.profile_id,
                        "source_id": source.source_id,
                    },
                )

    status = _status_for_run(
        disk_sources=disk_sources,
        prepared_artifacts=prepared_artifacts,
        coverage_gaps=coverage_gaps,
    )
    case_prep = CasePrepManifest(
        case_id=case_id,
        source_set_id=manifest.source_set_id,
        status=status,
        sources=manifest.sources,
        prepared_artifacts=prepared_artifacts,
        coverage_gaps=coverage_gaps,
        warnings=warnings,
        output_dir=generated_output_display_path(resolved_output_dir),
        created_at=clock(),
    )

    write_source_manifest(manifest, source_manifest_copy_path, include_local_paths=False)
    _write_json(source_image_manifest_path, _source_image_manifest(manifest))
    _write_json(warnings_path, _warnings_payload(case_id, warnings))
    _write_json(case_prep_path, case_prep.to_dict())
    _append_case_prep_audit(
        extraction_audit_path,
        case_id=case_id,
        event_type="case_prepare_completed",
        status=status,
        clock=clock,
        details={
            "coverage_gap_count": len(coverage_gaps),
            "prepared_artifact_count": len(prepared_artifacts),
        },
    )
    progress_status = "completed" if status == "completed" else "partial_success"
    append_progress_event(
        progress_path,
        case_id=case_id,
        phase="prepare_case",
        status=progress_status,
        message=(
            f"prepare_case {progress_status} with {len(prepared_artifacts)} "
            f"prepared artifact(s) and {len(coverage_gaps)} coverage gap(s)"
        ),
        timestamp=clock(),
    )

    return CasePrepareResult(
        manifest=case_prep,
        output_dir=resolved_output_dir,
        case_prep_path=case_prep_path,
        source_manifest_path=source_manifest_copy_path,
        source_image_manifest_path=source_image_manifest_path,
        extraction_audit_path=extraction_audit_path,
        warnings_path=warnings_path,
        local_source_manifest_path=local_manifest_path,
    )
