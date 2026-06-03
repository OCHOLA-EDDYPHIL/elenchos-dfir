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
    user_activity_summary: dict[str, Any] | None,
    coverage_summary: dict[str, Any] | None,
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
    user_activity_gaps: list[dict[str, Any]] = []
    user_activity_event_counts: dict[str, int] = {}
    prepared_hive_scope_warnings: list[dict[str, Any]] = []
    profile_coverage: dict[str, Any] = {}
    if user_activity_summary is not None:
        raw_gaps = user_activity_summary.get("coverage_gaps", [])
        if isinstance(raw_gaps, list):
            user_activity_gaps = [dict(gap) for gap in raw_gaps if isinstance(gap, dict)]
        raw_counts = user_activity_summary.get("event_counts_by_artifact_type", {})
        if isinstance(raw_counts, dict):
            user_activity_event_counts = {
                str(key): value
                for key, value in raw_counts.items()
                if isinstance(value, int)
            }
        raw_scope_warnings = user_activity_summary.get("prepared_hive_scope_warnings", [])
        if isinstance(raw_scope_warnings, list):
            prepared_hive_scope_warnings = [
                dict(warning)
                for warning in raw_scope_warnings
                if isinstance(warning, dict)
            ]
        raw_profile_coverage = user_activity_summary.get("profile_coverage", {})
        if isinstance(raw_profile_coverage, dict):
            profile_coverage = dict(raw_profile_coverage)
    registry_user_activity_status = profile_coverage.get("status")
    if not isinstance(registry_user_activity_status, str):
        registry_user_activity_status = (
            "partial_scope"
            if prepared_hive_scope_warnings
            else "assessed"
            if user_activity_event_counts
            else "needs_review"
        )
    parser_coverage_gaps: list[dict[str, Any]] = []
    if coverage_summary is not None:
        per_artifact = coverage_summary.get("per_artifact", [])
        if isinstance(per_artifact, list):
            for artifact in per_artifact:
                if not isinstance(artifact, dict):
                    continue
                gaps = artifact.get("coverage_gaps", [])
                if not isinstance(gaps, list):
                    continue
                parser_coverage_gaps.extend(
                    dict(gap) for gap in gaps if isinstance(gap, dict)
                )
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
        "registry_user_activity": {
            "status": registry_user_activity_status,
            "event_counts_by_artifact_type": user_activity_event_counts,
            "coverage_gaps": user_activity_gaps,
            "prepared_hive_scope_warnings": prepared_hive_scope_warnings,
            "profile_coverage": profile_coverage,
        },
        "parser_coverage_gaps": parser_coverage_gaps,
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
