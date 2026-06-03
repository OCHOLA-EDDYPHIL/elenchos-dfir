from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from siftguard.agent.case_manifest_adapter import AdaptedCaseManifest
from siftguard.agent.casebook import Casebook, CasebookAnalysisWindow
from siftguard.validation.claims import ClaimCandidate, validate_claim_candidate
from siftguard.validation.models import ClaimStatus, Confidence, EvidenceRef, FindingKind

USER_ACTIVITY_FAMILY = "registry_user_activity"
USER_ACTIVITY_ARTIFACT_TYPES = {
    "userassist",
    "recentdocs",
    "opensavepidlmru",
    "lastvisitedpidlmru",
    "typedpaths",
}
FILE_ACCESS_TYPES = {"recentdocs", "opensavepidlmru"}
PROGRAM_USE_TYPES = {"userassist", "lastvisitedpidlmru"}
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}
CLOUD_PATH_MARKERS = (
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "icloud",
    "box",
)
MAX_FINDINGS_PER_CATEGORY = 25


def _metadata(row: dict[str, Any]) -> dict[str, Any]:
    metadata = row.get("metadata", {})
    return dict(metadata) if isinstance(metadata, dict) else {}


def _artifact_family(row: dict[str, Any]) -> str:
    value = row.get("artifact_family")
    if isinstance(value, str):
        return value
    metadata = _metadata(row)
    value = metadata.get("artifact_family")
    return value if isinstance(value, str) else ""


def _artifact_type(row: dict[str, Any]) -> str:
    value = row.get("artifact_type")
    return value.casefold() if isinstance(value, str) else ""


def is_user_activity_event(row: dict[str, Any]) -> bool:
    artifact_type = _artifact_type(row)
    return (
        _artifact_family(row) == USER_ACTIVITY_FAMILY
        or artifact_type in USER_ACTIVITY_ARTIFACT_TYPES
        or str(row.get("event_type", "")).startswith("registry_")
        and "candidate" in str(row.get("event_type", ""))
    )


def _target(row: dict[str, Any]) -> str | None:
    metadata = _metadata(row)
    for key in ("target", "decoded_value", "path", "value_data", "subject"):
        value = row.get(key, metadata.get(key))
        if isinstance(value, str) and value:
            return value
    return None


def _event_id(row: dict[str, Any]) -> str:
    value = row.get("event_id")
    return value if isinstance(value, str) and value else "unknown-event"


def _artifact_id(row: dict[str, Any]) -> str:
    value = row.get("artifact_id")
    return value if isinstance(value, str) and value else "unknown-artifact"


def _profile_id(row: dict[str, Any]) -> str | None:
    value = row.get("profile_id")
    if isinstance(value, str) and value:
        return value
    value = _metadata(row).get("profile_id")
    return value if isinstance(value, str) and value else None


def _timestamp(row: dict[str, Any]) -> str | None:
    value = row.get("timestamp_utc")
    return value if isinstance(value, str) and value else None


def _utc_datetime(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _window_bounds(window: CasebookAnalysisWindow) -> tuple[datetime, datetime] | None:
    start = _utc_datetime(window.start)
    end = _utc_datetime(window.end)
    if start is None or end is None:
        return None
    return start, end


def _in_analysis_window(row: dict[str, Any], casebook: Casebook | None) -> bool:
    if casebook is None:
        return False
    timestamp = _utc_datetime(_timestamp(row))
    if timestamp is None:
        return False
    for window in casebook.analysis_windows:
        bounds = _window_bounds(window)
        if bounds is None:
            continue
        start, end = bounds
        if start <= timestamp <= end:
            return True
    return False


def _raw_record_ref(row: dict[str, Any]) -> str | None:
    raw = row.get("raw_record_ref")
    if isinstance(raw, dict):
        source_path = raw.get("source_path")
        row_number = raw.get("row_number")
        record_id = raw.get("record_id")
        byte_offset = raw.get("byte_offset")
        if isinstance(source_path, str) and isinstance(row_number, int):
            return f"csv:{Path(source_path).name}:{row_number}"
        if isinstance(record_id, str) and record_id:
            return record_id
        if isinstance(source_path, str) and source_path:
            return f"file:{Path(source_path).name}"
        if isinstance(byte_offset, int):
            return f"byte:{byte_offset}"
    if isinstance(raw, str) and raw:
        return raw
    return None


def _evidence_ref(row: dict[str, Any]) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=_event_id(row),
        artifact_id=_artifact_id(row),
        parser=str(row.get("parser_name") or "recmd"),
        source=str(row.get("artifact_type") or USER_ACTIVITY_FAMILY),
        raw_record_ref=_raw_record_ref(row),
        timestamp_field=row.get("timestamp_description")
        if isinstance(row.get("timestamp_description"), str)
        else None,
        description=f"Normalized parser event {_event_id(row)}.",
    )


def _artifact_hash_by_id(adapted: AdaptedCaseManifest) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for artifact in adapted.prepared_artifacts:
        artifact_id = artifact.get("artifact_id")
        sha256 = artifact.get("sha256")
        if isinstance(artifact_id, str) and isinstance(sha256, str) and sha256:
            hashes[artifact_id] = sha256
    return hashes


def _path_key(value: str | None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.replace("\\", "/").rstrip("/").casefold()


def _basename_key(value: str | None) -> str | None:
    path = _path_key(value)
    if path is None:
        return None
    return path.rsplit("/", 1)[-1]


def _matches_target(row: dict[str, Any], target: str | None) -> bool:
    target_path = _path_key(target)
    target_base = _basename_key(target)
    if target_path is None and target_base is None:
        return False
    row_values = (
        row.get("path"),
        row.get("value_data"),
        row.get("subject"),
        _metadata(row).get("target"),
    )
    for value in row_values:
        if not isinstance(value, str):
            continue
        row_path = _path_key(value)
        row_base = _basename_key(value)
        if row_path is not None and row_path == target_path:
            return True
        if row_base is not None and row_base == target_base:
            return True
    return False


def _corroborating_events(
    *,
    target: str | None,
    candidate_type: str,
    normalized_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    corroborating: list[dict[str, Any]] = []
    for row in normalized_events:
        if is_user_activity_event(row):
            continue
        event_type = row.get("event_type")
        artifact_type = row.get("artifact_type")
        if candidate_type == "file_access_candidate":
            supported = artifact_type == "mft"
        elif candidate_type == "program_use_candidate":
            supported = (
                event_type in {"amcache_execution", "registry_run_key"}
                or artifact_type == "mft"
            )
        else:
            supported = False
        if supported and _matches_target(row, target):
            corroborating.append(row)
    return corroborating


def _finding_id(*, category: str, rows: list[dict[str, Any]], target: str | None) -> str:
    payload = {
        "category": category,
        "target": target,
        "events": sorted(_event_id(row) for row in rows),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return f"F-UA-{digest}"


def _artifact_hashes_for_rows(
    rows: list[dict[str, Any]],
    artifact_hashes: dict[str, str],
) -> list[str]:
    values: list[str] = []
    for row in rows:
        artifact_hash = artifact_hashes.get(_artifact_id(row))
        if artifact_hash and artifact_hash not in values:
            values.append(artifact_hash)
    return values


def _profile_ids_for_rows(rows: list[dict[str, Any]]) -> list[str]:
    profile_ids: list[str] = []
    for row in rows:
        profile_id = _profile_id(row)
        if profile_id is not None and profile_id not in profile_ids:
            profile_ids.append(profile_id)
    return sorted(profile_ids)


def _candidate_from_rows(
    *,
    category: str,
    claim: str,
    requested_status: ClaimStatus,
    confidence: Confidence,
    rows: list[dict[str, Any]],
    target: str | None,
    artifact_hashes: dict[str, str],
    rationale: str,
    inference_rule: str | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    evidence_refs = [_evidence_ref(row) for row in rows]
    raw_record_refs = [
        raw_ref
        for row in rows
        if (raw_ref := _raw_record_ref(row)) is not None
    ]
    hashes = _artifact_hashes_for_rows(rows, artifact_hashes)
    candidate = ClaimCandidate(
        finding_id=_finding_id(category=category, rows=rows, target=target),
        claim=claim,
        requested_status=requested_status,
        confidence=confidence,
        kind=FindingKind.OBSERVATION,
        evidence_refs=evidence_refs,
        artifact_hashes=hashes,
        raw_record_refs=raw_record_refs,
        rationale=rationale,
        limitations=list(limitations or []),
        inference_rule=inference_rule,
    )
    result = validate_claim_candidate(candidate)
    finding = result.finding.to_dict()
    finding["finding_category"] = category
    finding["artifact_family"] = USER_ACTIVITY_FAMILY
    finding["linked_event_ids"] = sorted(_event_id(row) for row in rows)
    finding["profile_ids"] = _profile_ids_for_rows(rows)
    finding["user_activity_artifact_types"] = sorted(
        {
            artifact_type
            for row in rows
            if (artifact_type := _artifact_type(row)) in USER_ACTIVITY_ARTIFACT_TYPES
        }
    )
    finding["validation_notes"] = list(result.validation_notes)
    if result.downgrade_reason is not None:
        finding["downgrade_reason"] = result.downgrade_reason
    return finding


def _window_activity_finding(
    *,
    user_activity_events: list[dict[str, Any]],
    artifact_hashes: dict[str, str],
    casebook: Casebook | None,
) -> dict[str, Any] | None:
    window_events = [
        row for row in user_activity_events if _in_analysis_window(row, casebook)
    ]
    if not window_events:
        return None
    rows = sorted(window_events, key=lambda row: (_timestamp(row) or "", _event_id(row)))[:10]
    return _candidate_from_rows(
        category="user_activity_case_window",
        claim=(
            "Registry user-activity artifacts contain timestamped observations "
            "inside the configured analysis window."
        ),
        requested_status=ClaimStatus.CONFIRMED,
        confidence=Confidence.HIGH,
        rows=rows,
        target="analysis_window",
        artifact_hashes=artifact_hashes,
        rationale=(
            "The claim is limited to the presence of timestamped Registry user-activity "
            "observations inside the analysis window."
        ),
    )


def _candidate_claim(category: str, artifact_type: str, target: str | None) -> str:
    display_target = target or "an undecoded Registry user-activity value"
    if category == "file_access_candidate":
        return (
            f"Registry {artifact_type} data identifies a file access/recent-use "
            f"candidate: {display_target}"
        )
    if category == "program_use_candidate":
        return (
            f"Registry {artifact_type} data identifies a program-use candidate: "
            f"{display_target}"
        )
    if category == "typed_path_navigation_candidate":
        return f"Registry TypedPaths data identifies a user-navigation candidate: {display_target}"
    return (
        "Registry user-activity data identifies a cloud/archive review candidate; "
        f"successful transfer is not established: {display_target}"
    )


def _category_for_user_activity(row: dict[str, Any]) -> str | None:
    artifact_type = _artifact_type(row)
    if artifact_type in FILE_ACCESS_TYPES:
        return "file_access_candidate"
    if artifact_type in PROGRAM_USE_TYPES:
        return "program_use_candidate"
    if artifact_type == "typedpaths":
        return "typed_path_navigation_candidate"
    return None


def _is_cloud_or_archive_candidate(target: str | None) -> bool:
    path = _path_key(target)
    if path is None:
        return False
    if any(marker in path for marker in CLOUD_PATH_MARKERS):
        return True
    suffix = Path(path).suffix.casefold()
    return suffix in ARCHIVE_EXTENSIONS


def _candidate_findings(
    *,
    user_activity_events: list[dict[str, Any]],
    normalized_events: list[dict[str, Any]],
    artifact_hashes: dict[str, str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    category_counts: dict[str, int] = {}
    for row in sorted(
        user_activity_events,
        key=lambda item: (_target(item) or "", _event_id(item)),
    ):
        category = _category_for_user_activity(row)
        if category is None:
            continue
        if category_counts.get(category, 0) >= MAX_FINDINGS_PER_CATEGORY:
            continue
        target = _target(row)
        corroborating = _corroborating_events(
            target=target,
            candidate_type=category,
            normalized_events=normalized_events,
        )
        rows = [row, *corroborating[:3]]
        inferred = category in {"file_access_candidate", "program_use_candidate"} and bool(
            corroborating
        )
        artifact_type = _artifact_type(row)
        findings.append(
            _candidate_from_rows(
                category=category,
                claim=_candidate_claim(category, artifact_type, target),
                requested_status=ClaimStatus.INFERRED if inferred else ClaimStatus.NEEDS_REVIEW,
                confidence=Confidence.MEDIUM if inferred else Confidence.LOW,
                rows=rows,
                target=target,
                artifact_hashes=artifact_hashes,
                rationale=(
                    "User-activity evidence is independently corroborated by another "
                    "supported artifact class."
                    if inferred
                    else "Single-source Registry user-activity evidence requires analyst review."
                ),
                inference_rule=(
                    "registry_user_activity_independent_corroboration" if inferred else None
                ),
                limitations=(
                    []
                    if inferred
                    else [
                        "Single-source user-activity candidate is not proof of "
                        "theft or compromise."
                    ]
                ),
            )
        )
        category_counts[category] = category_counts.get(category, 0) + 1
        if _is_cloud_or_archive_candidate(target):
            transfer_category = "cloud_or_transfer_candidate"
            if category_counts.get(transfer_category, 0) < MAX_FINDINGS_PER_CATEGORY:
                findings.append(
                    _candidate_from_rows(
                        category=transfer_category,
                        claim=_candidate_claim(transfer_category, artifact_type, target),
                        requested_status=ClaimStatus.NEEDS_REVIEW,
                        confidence=Confidence.LOW,
                        rows=[row],
                        target=target,
                        artifact_hashes=artifact_hashes,
                        rationale=(
                            "Path or archive naming is a review lead only; no successful "
                            "transfer is established by this artifact."
                        ),
                        limitations=[
                            "Cloud/archive candidate does not prove transfer, "
                            "theft, or exfiltration."
                        ],
                    )
                )
                category_counts[transfer_category] = category_counts.get(transfer_category, 0) + 1
    return findings


def _dedupe_findings(
    existing: list[dict[str, Any]],
    generated: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    existing_ids = {
        finding.get("finding_id")
        for finding in existing
        if isinstance(finding.get("finding_id"), str)
    }
    output: list[dict[str, Any]] = []
    for finding in generated:
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or finding_id in existing_ids:
            continue
        output.append(finding)
        existing_ids.add(finding_id)
    return output


def _summary(
    *,
    adapted: AdaptedCaseManifest,
    generated: list[dict[str, Any]],
    user_activity_events: list[dict[str, Any]],
    coverage_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    event_counts: dict[str, int] = {}
    event_counts_by_profile: dict[str, int] = {}
    finding_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for row in user_activity_events:
        artifact_type = _artifact_type(row)
        event_counts[artifact_type] = event_counts.get(artifact_type, 0) + 1
        profile_id = _profile_id(row) or "unknown_profile"
        event_counts_by_profile[profile_id] = event_counts_by_profile.get(profile_id, 0) + 1
    for finding in generated:
        category = finding.get("finding_category")
        status = finding.get("status")
        if isinstance(category, str):
            finding_counts[category] = finding_counts.get(category, 0) + 1
        if isinstance(status, str):
            status_counts[status] = status_counts.get(status, 0) + 1
    prepared_hive_scope_warnings = _prepared_ntuser_scope_warnings(adapted)
    profile_coverage = _profile_hive_coverage(
        adapted=adapted,
        user_activity_events=user_activity_events,
        parser_coverage_gaps=coverage_gaps,
        prepared_hive_scope_warnings=prepared_hive_scope_warnings,
    )
    return {
        "mode": "registry_user_activity_initial",
        "event_count": len(user_activity_events),
        "event_counts_by_artifact_type": dict(sorted(event_counts.items())),
        "event_counts_by_profile": dict(sorted(event_counts_by_profile.items())),
        "finding_count": len(generated),
        "finding_counts_by_category": dict(sorted(finding_counts.items())),
        "finding_status_counts": dict(sorted(status_counts.items())),
        "coverage_gaps": list(coverage_gaps),
        "prepared_hive_scope_warnings": prepared_hive_scope_warnings,
        "profile_coverage": profile_coverage,
    }


def _is_ntuser_artifact(artifact: dict[str, Any]) -> bool:
    hive_type = artifact.get("registry_hive_type")
    path = artifact.get("path")
    normalized_path = path.replace("\\", "/").casefold() if isinstance(path, str) else ""
    return hive_type == "ntuser" or (
        normalized_path == "ntuser.dat" or normalized_path.endswith("/ntuser.dat")
    )


def _profile_hive_coverage(
    *,
    adapted: AdaptedCaseManifest,
    user_activity_events: list[dict[str, Any]],
    parser_coverage_gaps: list[dict[str, Any]],
    prepared_hive_scope_warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    ntuser_artifacts = [
        dict(artifact)
        for artifact in adapted.prepared_artifacts
        if _is_ntuser_artifact(artifact)
    ]
    discovered_profile_ids = sorted(
        {
            str(artifact.get("profile_id"))
            for artifact in ntuser_artifacts
            if isinstance(artifact.get("profile_id"), str)
        }
    )
    available_profile_ids = sorted(
        {
            str(artifact.get("profile_id"))
            for artifact in ntuser_artifacts
            if artifact.get("status") == "available"
            and isinstance(artifact.get("profile_id"), str)
        }
    )
    failed_profile_ids = sorted(
        {
            str(artifact.get("profile_id"))
            for artifact in ntuser_artifacts
            if artifact.get("status") in {"missing", "skipped", "extraction_failed"}
            and isinstance(artifact.get("profile_id"), str)
        }
    )
    parsed_profile_ids = sorted(
        {
            profile_id
            for row in user_activity_events
            if (profile_id := _profile_id(row)) is not None
        }
        | {
            str(gap.get("profile_id"))
            for gap in parser_coverage_gaps
            if isinstance(gap.get("profile_id"), str)
        }
    )
    case_prep_profile_gaps = [
        dict(gap)
        for gap in adapted.coverage_gaps
        if gap.get("artifact_type") == "ntuser_hive"
        or gap.get("artifact_family") == "registry_user_activity"
    ]
    if prepared_hive_scope_warnings or failed_profile_ids:
        status = "partial_scope"
    elif available_profile_ids:
        status = "assessed"
    else:
        status = "needs_review"
    return {
        "status": status,
        "discovered_profile_count": len(discovered_profile_ids),
        "available_profile_count": len(available_profile_ids),
        "failed_profile_count": len(failed_profile_ids),
        "parsed_profile_count": len(parsed_profile_ids),
        "discovered_profile_ids": discovered_profile_ids,
        "available_profile_ids": available_profile_ids,
        "failed_profile_ids": failed_profile_ids,
        "parsed_profile_ids": parsed_profile_ids,
        "case_prep_profile_gaps": case_prep_profile_gaps,
    }


def _prepared_ntuser_scope_warnings(adapted: AdaptedCaseManifest) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    for artifact in adapted.prepared_artifacts:
        path = artifact.get("path")
        artifact_warnings = artifact.get("warnings", [])
        if not isinstance(path, str) or "ntuser.dat" not in path.casefold():
            continue
        if not isinstance(artifact_warnings, list):
            continue
        relevant = [
            warning
            for warning in artifact_warnings
            if isinstance(warning, str)
            and (
                "multiple ntuser.dat" in warning.casefold()
                or "extracted first" in warning.casefold()
            )
        ]
        if not relevant:
            continue
        warnings.append(
            {
                "artifact_id": artifact.get("artifact_id"),
                "path": path,
                "warnings": relevant,
                "impact": (
                    "Registry user-activity coverage is limited to the prepared "
                    "NTUSER.DAT hive; other user profile hives were not extracted."
                ),
                "recommended_next_step": (
                    "Extract and inventory all user profile NTUSER.DAT hives before "
                    "treating user-activity coverage as complete."
                ),
            }
        )
    return warnings


def generate_user_activity_findings(
    *,
    adapted: AdaptedCaseManifest,
    normalized_events: list[dict[str, Any]],
    existing_findings: list[dict[str, Any]],
    coverage_summary: dict[str, Any],
    casebook: Casebook | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    user_activity_events = [
        dict(row) for row in normalized_events if is_user_activity_event(row)
    ]
    coverage_gaps = coverage_summary.get("registry_user_activity_gaps", [])
    if not isinstance(coverage_gaps, list):
        coverage_gaps = []
    if not user_activity_events:
        return [], _summary(
            adapted=adapted,
            generated=[],
            user_activity_events=[],
            coverage_gaps=[dict(gap) for gap in coverage_gaps if isinstance(gap, dict)],
        )

    artifact_hashes = _artifact_hash_by_id(adapted)
    generated: list[dict[str, Any]] = []
    window_finding = _window_activity_finding(
        user_activity_events=user_activity_events,
        artifact_hashes=artifact_hashes,
        casebook=casebook,
    )
    if window_finding is not None:
        generated.append(window_finding)
    generated.extend(
        _candidate_findings(
            user_activity_events=user_activity_events,
            normalized_events=normalized_events,
            artifact_hashes=artifact_hashes,
        )
    )
    deduped = _dedupe_findings(existing_findings, generated)
    return deduped, _summary(
        adapted=adapted,
        generated=deduped,
        user_activity_events=user_activity_events,
        coverage_gaps=[dict(gap) for gap in coverage_gaps if isinstance(gap, dict)],
    )
