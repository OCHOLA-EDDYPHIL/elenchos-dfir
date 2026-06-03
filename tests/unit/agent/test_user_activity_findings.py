from __future__ import annotations

from pathlib import Path
from typing import Any

from siftguard.agent.case_manifest_adapter import AdaptedCaseManifest
from siftguard.agent.casebook import casebook_from_dict
from siftguard.agent.user_activity_findings import generate_user_activity_findings
from siftguard.evidence.manifest import EvidenceManifest


def _adapted_manifest(tmp_path: Path) -> AdaptedCaseManifest:
    manifest = EvidenceManifest(
        case_id="case-001",
        generated_at_utc="2026-01-01T00:00:00Z",
        case_root=str(tmp_path),
        artifact_count=0,
        artifacts=[],
    )
    return AdaptedCaseManifest(
        case_id="case-001",
        case_prep_path=tmp_path / "case_prep.json",
        evidence_manifest=manifest,
        sources=[
            {
                "source_id": "src_disk",
                "role": "disk_image",
                "kind": "ewf_e01",
                "display_name": "disk.e01",
                "status": "available",
                "analysis_scope": "primary",
            }
        ],
        prepared_artifacts=[
            {
                "artifact_id": "prep_ntuser",
                "artifact_type": "registry_hive",
                "source_id": "src_disk",
                "source_role": "disk_image",
                "status": "available",
                "sha256": "d" * 64,
            }
        ],
        skipped_prepared_artifacts=[],
        coverage_gaps=[],
        memory_sources=[],
        case_background_sources=[],
        warnings=[],
        source_roots=[],
    )


def _casebook():
    return casebook_from_dict(
        {
            "case_id": "case-001",
            "display_name": "Synthetic Case",
            "analysis_windows": [
                {
                    "id": "window",
                    "start": "2020-11-13T00:00:00+00:00",
                    "end": "2020-11-14T00:00:00+00:00",
                    "description": "synthetic window",
                }
            ],
            "case_questions": [],
        }
    )


def _user_activity_event(
    *,
    artifact_type: str = "recentdocs",
    event_id: str = "ua1",
    target: str = r"C:\Users\analyst\Documents\ProjectAlpha\design.docx",
    timestamp: str | None = "2020-11-13T20:10:00Z",
) -> dict[str, Any]:
    event_type_by_artifact = {
        "recentdocs": "registry_recent_document_candidate",
        "opensavepidlmru": "registry_opensave_file_candidate",
        "userassist": "registry_userassist_program_use",
        "lastvisitedpidlmru": "registry_lastvisited_program_candidate",
        "typedpaths": "registry_typed_path_candidate",
    }
    return {
        "event_id": event_id,
        "case_id": "case-001",
        "artifact_id": "prep_ntuser",
        "artifact_type": artifact_type,
        "artifact_family": "registry_user_activity",
        "parser_name": "recmd",
        "source_tool": "RECmd",
        "event_type": event_type_by_artifact[artifact_type],
        "timestamp_utc": timestamp,
        "timestamp_description": "registry_key_last_write",
        "path": target,
        "subject": target,
        "evidence_refs": ["prep_ntuser"],
        "raw_record_ref": {
            "source_path": "recmd_user_activity.csv",
            "row_number": 2,
            "record_id": event_id,
        },
        "metadata": {
            "artifact_family": "registry_user_activity",
            "target": target,
            "source_id": "src_disk",
            "source_role": "disk_image",
        },
    }


def _mft_event(target: str) -> dict[str, Any]:
    return {
        "event_id": "mft1",
        "case_id": "case-001",
        "artifact_id": "prep_mft",
        "artifact_type": "mft",
        "parser_name": "mftecmd",
        "source_tool": "MFTECmd",
        "event_type": "file_created",
        "timestamp_utc": "2020-11-13T20:09:00Z",
        "path": target,
        "subject": target,
        "evidence_refs": ["prep_mft"],
        "raw_record_ref": {
            "source_path": "mft.csv",
            "row_number": 2,
            "record_id": "mft1",
        },
        "metadata": {},
    }


def _generate(
    tmp_path: Path,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings, _summary = generate_user_activity_findings(
        adapted=_adapted_manifest(tmp_path),
        normalized_events=events,
        existing_findings=[],
        coverage_summary={"registry_user_activity_gaps": []},
        casebook=_casebook(),
    )
    return findings


def test_single_source_user_activity_candidate_stays_needs_review(tmp_path: Path):
    findings = _generate(tmp_path, [_user_activity_event()])
    file_findings = [
        finding
        for finding in findings
        if finding.get("finding_category") == "file_access_candidate"
    ]

    assert file_findings
    assert {finding["status"] for finding in file_findings} == {"needs_review"}


def test_user_activity_with_independent_corroboration_can_be_inferred(tmp_path: Path):
    target = r"C:\Users\analyst\Documents\ProjectAlpha\design.docx"
    findings = _generate(
        tmp_path,
        [_user_activity_event(target=target), _mft_event(target)],
    )
    file_findings = [
        finding
        for finding in findings
        if finding.get("finding_category") == "file_access_candidate"
    ]

    assert file_findings
    assert file_findings[0]["status"] == "inferred"
    assert len(file_findings[0]["evidence_refs"]) >= 2


def test_confirmed_status_is_limited_to_activity_window_fact(tmp_path: Path):
    findings = _generate(tmp_path, [_user_activity_event()])
    confirmed = [finding for finding in findings if finding["status"] == "confirmed"]

    assert len(confirmed) == 1
    assert confirmed[0]["finding_category"] == "user_activity_case_window"
    assert "theft" not in confirmed[0]["claim"].casefold()
    assert confirmed[0]["evidence_refs"]


def test_cloud_or_archive_candidate_remains_needs_review(tmp_path: Path):
    target = r"C:\Users\analyst\OneDrive\Research\archive.zip"
    findings = _generate(
        tmp_path,
        [_user_activity_event(artifact_type="typedpaths", target=target)],
    )
    transfer_findings = [
        finding
        for finding in findings
        if finding.get("finding_category") == "cloud_or_transfer_candidate"
    ]

    assert transfer_findings
    assert transfer_findings[0]["status"] == "needs_review"
    assert "successful transfer is not established" in transfer_findings[0]["claim"]
