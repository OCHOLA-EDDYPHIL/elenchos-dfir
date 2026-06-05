from __future__ import annotations

from pathlib import Path

from siftguard.agent.case_manifest_adapter import AdaptedCaseManifest
from siftguard.agent.casebook import casebook_from_dict
from siftguard.agent.gap_analysis import build_gap_analysis
from siftguard.evidence.manifest import EvidenceManifest

FINAL_WORDING = "SIFTGuard kept the configured claim not_assessed."
SCOPE_BOUNDARY = "The submitted artifact scope does not support this configured claim."
RECOMMENDED_NEXT_ARTIFACTS = ["network telemetry", "browser history"]


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


def _casebook():
    return casebook_from_dict(
        {
            "analysis_windows": [],
            "case_id": "case-001",
            "case_questions": [
                {
                    "evidence_classes": [],
                    "id": "q_claim_subject",
                    "question": "What claim subject is supported?",
                    "supported_by_scope": False,
                },
                {
                    "evidence_classes": [],
                    "id": "q_claim_transfer",
                    "question": "What transfer path is supported?",
                    "supported_by_scope": False,
                },
                {
                    "evidence_classes": [],
                    "id": "q_context",
                    "question": "What additional context is available?",
                    "supported_by_scope": False,
                },
            ],
            "claim_boundaries": [
                {
                    "claim_area": "configured claim",
                    "emit_when_all_statuses": ["not_assessed"],
                    "final_wording": FINAL_WORDING,
                    "question_ids": ["q_claim_subject", "q_claim_transfer"],
                    "recommended_next_artifacts": RECOMMENDED_NEXT_ARTIFACTS,
                    "related_question_ids": ["q_context"],
                    "scope_boundary": SCOPE_BOUNDARY,
                }
            ],
            "display_name": "Synthetic Claim Boundary Case",
            "key_dates": [],
            "time_zone": None,
        }
    )


def _gap_analysis(tmp_path: Path, questions: list[dict[str, str]]) -> dict[str, object]:
    return build_gap_analysis(
        adapted=_adapted_manifest(tmp_path),
        casebook=_casebook(),
        case_questions={"questions": questions},
        user_activity_summary=None,
        coverage_summary=None,
        warnings=[],
        created_at="2026-01-01T00:00:00Z",
    )


def test_gap_analysis_records_metadata_driven_claim_boundary(
    tmp_path: Path,
) -> None:
    payload = _gap_analysis(
        tmp_path,
        [
            {"question_id": "q_claim_subject", "status": "not_assessed"},
            {"question_id": "q_claim_transfer", "status": "not_assessed"},
            {"question_id": "q_context", "status": "not_assessed"},
        ],
    )

    assert payload["claim_boundaries"] == [
        {
            "claim_area": "configured claim",
            "emit_when_all_statuses": ["not_assessed"],
            "final_wording": FINAL_WORDING,
            "recommended_next_artifacts": RECOMMENDED_NEXT_ARTIFACTS,
            "scope_boundary": SCOPE_BOUNDARY,
            "source_question_ids": [
                "q_claim_subject",
                "q_claim_transfer",
                "q_context",
            ],
            "status": "not_assessed",
        }
    ]
    assert payload["unsupported_areas"][-1]["area"] == "configured claim"
    assert payload["unsupported_areas"][-1]["reason"] == SCOPE_BOUNDARY


def test_gap_analysis_omits_claim_boundary_without_matching_question_statuses(
    tmp_path: Path,
) -> None:
    payload = _gap_analysis(
        tmp_path,
        [
            {"question_id": "q_claim_subject", "status": "not_assessed"},
            {"question_id": "q_claim_transfer", "status": "needs_review"},
            {"question_id": "q_context", "status": "not_assessed"},
        ],
    )

    assert payload["claim_boundaries"] == []
