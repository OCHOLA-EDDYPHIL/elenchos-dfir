from __future__ import annotations

from typing import Any

from siftguard.agent.case_manifest_adapter import AdaptedCaseManifest
from siftguard.agent.case_questions import QUESTION_STATUSES
from siftguard.agent.casebook import Casebook


def build_gap_analysis(
    *,
    adapted: AdaptedCaseManifest,
    casebook: Casebook | None,
    case_questions: dict[str, Any] | None,
    warnings: list[str],
    created_at: str,
) -> dict[str, Any]:
    questions: list[dict[str, Any]] = []
    if case_questions is not None:
        raw_questions = case_questions.get("questions", [])
        if isinstance(raw_questions, list):
            questions = [
                {
                    "question_id": question.get("question_id"),
                    "question": question.get("question"),
                    "supported_by_current_scope": question.get("supported_by_current_scope"),
                    "evidence_classes_checked": question.get("evidence_classes_checked", []),
                    "status": question.get("status"),
                    "gaps": question.get("gaps", []),
                    "recommended_next_manual_review": question.get(
                        "recommended_next_manual_review",
                        [],
                    ),
                    "linked_finding_ids": question.get("linked_finding_ids", []),
                    "linked_evidence_refs": question.get("linked_evidence_refs", []),
                }
                for question in raw_questions
                if isinstance(question, dict)
            ]
    status_counts: dict[str, int] = {status: 0 for status in sorted(QUESTION_STATUSES)}
    for question in questions:
        status = question.get("status")
        if isinstance(status, str):
            status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "case_id": adapted.case_id,
        "created_at": created_at,
        "mode": "case_question_gap_analysis",
        "casebook_present": casebook is not None,
        "casebook_id": casebook.case_id if casebook is not None else None,
        "case_questions_count": len(questions),
        "case_questions": questions,
        "status_counts": status_counts,
        "carried_forward_case_prep_gaps": list(adapted.coverage_gaps),
        "memory_sources": [
            {
                "source_id": source["source_id"],
                "display_name": source["display_name"],
                "status": "not_assessed",
                "analysis_scope": source.get("analysis_scope"),
                "reason": "memory source inventoried only; final scope excludes memory forensics",
            }
            for source in adapted.memory_sources
        ],
        "unsupported_areas": [
            {
                "area": "memory forensics",
                "status": "not_assessed",
                "reason": "Memory is staged for provenance only.",
            },
            {
                "area": "theft and exfiltration reconstruction",
                "status": "not_assessed",
                "reason": (
                    "Current final scope excludes browser, cloud, USB, network, "
                    "file-open, and memory artifacts."
                ),
            },
        ],
        "missing_parser_eligible_artifacts": [
            artifact
            for artifact in adapted.prepared_artifacts
            if artifact.get("parser_eligible") is True and artifact.get("status") != "available"
        ],
        "skipped_prepared_artifacts": list(adapted.skipped_prepared_artifacts),
        "warnings": list(warnings),
    }
