from __future__ import annotations

from pathlib import Path

from siftguard.agent.case_manifest_adapter import AdaptedCaseManifest
from siftguard.agent.gap_analysis import build_gap_analysis
from siftguard.agent.self_correction_events import (
    RECOMMENDED_NEXT_ARTIFACTS,
    THEFT_EXFILTRATION_SCOPE_BOUNDARY,
    THEFT_EXFILTRATION_STRICT_WORDING,
)
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
        prepared_artifacts=[],
        skipped_prepared_artifacts=[],
        coverage_gaps=[],
        memory_sources=[],
        case_background_sources=[],
        warnings=[],
        source_roots=[],
    )


def _gap_analysis(tmp_path: Path, questions: list[dict[str, str]]) -> dict[str, object]:
    return build_gap_analysis(
        adapted=_adapted_manifest(tmp_path),
        casebook=None,
        case_questions={"questions": questions},
        user_activity_summary=None,
        coverage_summary=None,
        warnings=[],
        created_at="2026-01-01T00:00:00Z",
    )


def test_gap_analysis_records_claim_boundary_for_real_theft_exfiltration_gap(
    tmp_path: Path,
) -> None:
    payload = _gap_analysis(
        tmp_path,
        [
            {"question_id": "q_what_was_stolen", "status": "not_assessed"},
            {"question_id": "q_where_transferred", "status": "not_assessed"},
            {"question_id": "q_how_stolen", "status": "not_assessed"},
            {"question_id": "q_memory", "status": "not_assessed"},
        ],
    )

    assert payload["claim_boundaries"] == [
        {
            "claim_area": "theft/exfiltration",
            "status": "not_assessed",
            "final_wording": THEFT_EXFILTRATION_STRICT_WORDING,
            "scope_boundary": THEFT_EXFILTRATION_SCOPE_BOUNDARY,
            "recommended_next_artifacts": list(RECOMMENDED_NEXT_ARTIFACTS),
            "source_question_ids": [
                "q_what_was_stolen",
                "q_where_transferred",
                "q_how_stolen",
                "q_memory",
            ],
        }
    ]


def test_gap_analysis_omits_claim_boundary_without_real_theft_exfiltration_gap(
    tmp_path: Path,
) -> None:
    payload = _gap_analysis(
        tmp_path,
        [
            {"question_id": "q_what_was_stolen", "status": "not_assessed"},
            {"question_id": "q_where_transferred", "status": "needs_review"},
            {"question_id": "q_how_stolen", "status": "not_assessed"},
        ],
    )

    assert payload["claim_boundaries"] == []
