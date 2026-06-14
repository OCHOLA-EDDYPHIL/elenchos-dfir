from __future__ import annotations

from elenchos.validation.models import ClaimStatus, Confidence, EvidenceRef, Finding, FindingKind
from elenchos.validation.provenance import validate_finding_has_evidence


def test_supported_confirmed_finding_passes_provenance_check():
    finding = Finding(
        finding_id="F-SYN-PROVENANCE",
        claim="Synthetic confirmed finding with claim-proof support.",
        status=ClaimStatus.CONFIRMED,
        confidence=Confidence.HIGH,
        kind=FindingKind.CONCLUSION,
        evidence_refs=[
            EvidenceRef(
                evidence_id="EV-SYN-001",
                parser="mftecmd",
                source="$MFT",
                raw_record_ref="csv:mft.csv:1842",
            )
        ],
        artifact_hashes=[
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ],
        rationale="Synthetic parser row supports the confirmed claim.",
    )

    ok, reason = validate_finding_has_evidence(finding)

    assert ok
    assert reason == "ok"


def test_rejected_finding_is_valid_but_not_report_supported():
    finding = Finding(
        finding_id="F-SYN-REJECTED-PROVENANCE",
        claim="Synthetic claim rejected by contradictory records.",
        status=ClaimStatus.REJECTED,
        confidence=Confidence.MEDIUM,
        kind=FindingKind.CONCLUSION,
        rationale="Synthetic records contradict the claim.",
    )

    ok, reason = validate_finding_has_evidence(finding)

    assert ok
    assert reason == "ok"
    assert finding.supports_final_report is False
