from __future__ import annotations

import pytest

from siftguard.correlation.models import SubjectTimeline, TimelineEvent, TimelineEventType
from siftguard.reporting.markdown_report import (
    ReportInput,
    generate_markdown_report,
    render_markdown_report,
)
from siftguard.validation.claims import ClaimCandidate, validate_claim_candidate
from siftguard.validation.models import ClaimStatus, Confidence, EvidenceRef, Finding, FindingKind

CASE_ID = "CASE-SYN-001"
SYNTHETIC_HASH = "sha256:" + ("a" * 64)
SYNTHETIC_PATH = "C:/Users/Alice/AppData/Local/Temp/example-a.exe"


def evidence_ref(
    evidence_id: str = "EV-SYN-MFT-001",
    parser: str = "mftecmd",
    source: str = "$MFT",
    raw_record_ref: str = "csv:mft.csv:1842",
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=evidence_id,
        parser=parser,
        source=source,
        raw_record_ref=raw_record_ref,
        description="Synthetic report evidence reference.",
    )


def finding(
    *,
    finding_id: str,
    claim: str,
    status: ClaimStatus,
    evidence_refs: list[EvidenceRef] | None = None,
    rationale: str = "Synthetic rationale for report rendering.",
    limitations: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        claim=claim,
        status=status,
        confidence=Confidence.HIGH,
        kind=FindingKind.CONCLUSION,
        evidence_refs=list(evidence_refs if evidence_refs is not None else [evidence_ref()]),
        audit_event_refs=["TR-SYN-001"],
        artifact_hashes=[SYNTHETIC_HASH] if status is ClaimStatus.CONFIRMED else [],
        raw_record_refs=[],
        rationale=rationale,
        limitations=list(limitations or []),
    )


def timeline_event(
    event_type: TimelineEventType = TimelineEventType.DROP,
    evidence_id: str = "EV-SYN-MFT-001",
    timestamp: str | None = "2026-01-01T00:00:00Z",
) -> TimelineEvent:
    return TimelineEvent(
        event_type=event_type,
        timestamp=timestamp,
        subject=SYNTHETIC_PATH,
        source="synthetic-normalized-events",
        details={"path": SYNTHETIC_PATH},
        evidence_refs=[evidence_ref(evidence_id=evidence_id)],
        path=SYNTHETIC_PATH,
    )


def subject_timeline(*, ambiguous: bool = False) -> SubjectTimeline:
    return SubjectTimeline(
        subject=SYNTHETIC_PATH,
        events=[
            timeline_event(TimelineEventType.PERSISTENCE, "EV-SYN-REG-001"),
            timeline_event(TimelineEventType.DROP, "EV-SYN-MFT-001"),
            timeline_event(TimelineEventType.EXECUTION, "EV-SYN-AMCACHE-001"),
        ],
        ambiguous=ambiguous,
        ambiguity_reason="Synthetic basename maps to multiple full paths." if ambiguous else None,
    )


def confirmed_finding() -> Finding:
    return finding(
        finding_id="F-SYN-CONFIRMED-001",
        claim=f"Synthetic direct artifact observation for {SYNTHETIC_PATH}.",
        status=ClaimStatus.CONFIRMED,
        evidence_refs=[evidence_ref()],
    )


def inferred_finding() -> Finding:
    return finding(
        finding_id="F-SYN-INFERRED-001",
        claim=f"Synthetic timeline inference for {SYNTHETIC_PATH}.",
        status=ClaimStatus.INFERRED,
        evidence_refs=[
            evidence_ref("EV-SYN-MFT-001"),
            evidence_ref("EV-SYN-REG-001", "recmd", "NTUSER.DAT", "json:runkeys.json:/entries/12"),
        ],
        rationale="Synthetic drop and persistence observations support a named inference.",
    )


def rejected_finding() -> Finding:
    return finding(
        finding_id="F-SYN-REJECTED-001",
        claim="Synthetic rejected claim.",
        status=ClaimStatus.REJECTED,
        evidence_refs=[evidence_ref("EV-SYN-REG-001", "recmd", "NTUSER.DAT")],
        rationale="Synthetic registry observation contradicts the proposed claim.",
    )


def needs_review_finding() -> Finding:
    return finding(
        finding_id="F-SYN-REVIEW-001",
        claim="Synthetic ambiguous claim.",
        status=ClaimStatus.NEEDS_REVIEW,
        evidence_refs=[],
        rationale="Synthetic ambiguity requires analyst review.",
        limitations=["Synthetic ambiguity remains unresolved."],
    )


def render_report(
    *,
    timelines: list[SubjectTimeline] | None = None,
    findings: list[Finding] | None = None,
    limitations: list[str] | None = None,
) -> str:
    return render_markdown_report(
        case_id=CASE_ID,
        timelines=list(timelines if timelines is not None else [subject_timeline()]),
        findings=list(
            findings
            if findings is not None
            else [
                confirmed_finding(),
                inferred_finding(),
                rejected_finding(),
                needs_review_finding(),
            ]
        ),
        limitations=list(limitations if limitations is not None else ["Synthetic report only."]),
    )


def section(report: str, heading: str) -> str:
    start = report.index(heading)
    next_start = report.find("\n## ", start + len(heading))
    if next_start == -1:
        return report[start:]
    return report[start:next_start]


def test_report_includes_all_required_sections():
    report = render_report()

    for heading in (
        "# Case Report",
        "## Case Summary",
        "## Evidence Coverage",
        "## Subject Timeline",
        "## Confirmed Findings",
        "## Inferred Findings",
        "## Rejected Claims",
        "## Needs Review",
        "## Limitations",
        "## Evidence References",
    ):
        assert heading in report


def test_confirmed_finding_appears_only_when_supported_and_displays_evidence():
    report = render_report(findings=[confirmed_finding()])
    confirmed = section(report, "## Confirmed Findings")

    assert "F-SYN-CONFIRMED-001" in confirmed
    assert "Evidence: `EV-SYN-MFT-001` parser=`mftecmd` source=`$MFT`" in confirmed
    assert "Artifact hashes:" in confirmed


def test_inferred_finding_appears_only_when_supported_and_displays_rationale():
    report = render_report(findings=[inferred_finding()])
    inferred = section(report, "## Inferred Findings")

    assert "F-SYN-INFERRED-001" in inferred
    assert "Synthetic drop and persistence observations support a named inference." in inferred
    assert "Evidence: `EV-SYN-REG-001` parser=`recmd`" in inferred


def test_rejected_finding_appears_under_rejected_claims_only():
    report = render_report(findings=[rejected_finding()])

    assert "F-SYN-REJECTED-001" in section(report, "## Rejected Claims")
    assert "F-SYN-REJECTED-001" not in section(report, "## Confirmed Findings")


def test_needs_review_finding_appears_under_needs_review_only():
    report = render_report(findings=[needs_review_finding()])

    assert "F-SYN-REVIEW-001" in section(report, "## Needs Review")
    assert "F-SYN-REVIEW-001" not in section(report, "## Confirmed Findings")


def test_evidence_free_confirmed_request_cannot_appear_in_confirmed_findings():
    result = validate_claim_candidate(
        ClaimCandidate(
            finding_id="F-SYN-UNSUPPORTED-001",
            claim=f"Unsupported synthetic claim for {SYNTHETIC_PATH}.",
            requested_status=ClaimStatus.CONFIRMED,
            confidence=Confidence.HIGH,
            kind=FindingKind.CONCLUSION,
            evidence_refs=[],
            artifact_hashes=[],
            raw_record_refs=[],
            rationale="Synthetic unsupported rationale.",
        )
    )
    report = render_report(findings=[result.finding])

    assert result.finding.status is ClaimStatus.NEEDS_REVIEW
    assert "F-SYN-UNSUPPORTED-001" not in section(report, "## Confirmed Findings")
    assert "F-SYN-UNSUPPORTED-001" in section(report, "## Needs Review")


def test_renderer_rejects_raw_claim_candidates():
    candidate = ClaimCandidate(
        finding_id="F-SYN-RAW-001",
        claim="Synthetic raw candidate should not be reportable.",
        requested_status=ClaimStatus.NEEDS_REVIEW,
        confidence=Confidence.LOW,
        kind=FindingKind.CONCLUSION,
    )

    with pytest.raises(TypeError, match="validated Finding"):
        render_markdown_report(case_id=CASE_ID, timelines=[], findings=[candidate])


def test_every_confirmed_or_inferred_finding_displays_evidence_refs():
    report = render_report(findings=[confirmed_finding(), inferred_finding()])

    confirmed = section(report, "## Confirmed Findings")
    inferred = section(report, "## Inferred Findings")
    assert "Evidence: `EV-SYN-MFT-001`" in confirmed
    assert "Evidence: `EV-SYN-MFT-001`" in inferred
    assert "Evidence: `EV-SYN-REG-001`" in inferred


def test_timeline_events_render_with_evidence_ids_and_ambiguity_markers():
    report = render_report(timelines=[subject_timeline(ambiguous=True)], findings=[])
    timeline = section(report, "## Subject Timeline")

    assert "Ambiguous: yes" in timeline
    assert "Synthetic basename maps to multiple full paths." in timeline
    assert "`2026-01-01T00:00:00Z` drop" in timeline
    assert "evidence=`EV-SYN-MFT-001`" in timeline


def test_report_renders_coverage_summary_when_provided():
    report = render_markdown_report(
        case_id=CASE_ID,
        timelines=[],
        findings=[],
        coverage_summary={
            "selection_profile": "forensic-triage",
            "max_normalized_events": 5000,
            "normalized_events_written": 12,
            "per_artifact": [
                {
                    "artifact_id": "EV-SYN-MFT-001",
                    "artifact_type": "mft",
                    "parser_status": "success",
                    "normalized_rows_selected": 10,
                    "bounded": True,
                }
            ],
            "selection_notes": {"deterministic_fill_selected": 10},
        },
    )
    coverage = section(report, "## Evidence Coverage")

    assert "Selection profile: `forensic-triage`" in coverage
    assert "`EV-SYN-MFT-001`" in coverage
    assert "deterministic_fill_selected=10" in coverage


def test_report_renders_execution_progress_when_provided():
    report = render_markdown_report(
        case_id=CASE_ID,
        timelines=[],
        findings=[],
        progress_events=[
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "case_id": CASE_ID,
                "phase": "normalize/select",
                "status": "completed",
                "message": "normalize/select completed with 3 selected event(s)",
            }
        ],
    )
    progress = section(report, "## Execution Progress")

    assert "Phase: `normalize/select`; status=`completed`" in progress
    assert "3 selected event(s)" in progress


def test_report_omits_execution_progress_without_events():
    report = render_markdown_report(case_id=CASE_ID, timelines=[], findings=[])

    assert "## Execution Progress" not in report


def test_report_output_is_deterministic_even_with_reversed_inputs():
    timelines = [subject_timeline(), SubjectTimeline(subject="example-a.exe", events=[])]
    findings = [
        needs_review_finding(),
        rejected_finding(),
        inferred_finding(),
        confirmed_finding(),
    ]

    first = render_report(timelines=timelines, findings=findings)
    second = render_report(timelines=list(reversed(timelines)), findings=list(reversed(findings)))

    assert first == second


def test_report_is_plain_markdown_string_and_has_one_trailing_newline():
    report = generate_markdown_report(
        ReportInput(
            case_id=CASE_ID,
            timelines=[],
            findings=[],
            limitations=[],
        )
    )

    assert isinstance(report, str)
    assert report.endswith("\n")
    assert not report.endswith("\n\n")
    assert "- No subject timelines." in report
    assert "- No confirmed findings." in report
    assert "- No additional limitations." in report


def test_synthetic_report_contains_no_forbidden_paths_or_legal_overclaims():
    report = render_report()
    lower_report = report.lower()

    for forbidden in ("/mnt/evidence", "/home/", "runs/", ".local/"):
        assert forbidden not in report
    for overclaim in (
        "proves " "compromise",
        "irrefutable",
        "guaranteed",
    ):
        assert overclaim not in lower_report
