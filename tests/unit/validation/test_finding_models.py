from __future__ import annotations

import json

import pytest

from siftguard.validation.models import (
    ClaimStatus,
    Confidence,
    EvidenceRef,
    Finding,
    FindingKind,
)

SYNTHETIC_HASH = "sha256:" + ("a" * 64)


def synthetic_mft_ref(raw_record_ref: str | None = "csv:mft.csv:1842") -> EvidenceRef:
    return EvidenceRef(
        evidence_id="EV-SYN-MFT-001",
        parser="mftecmd",
        source="$MFT",
        raw_record_ref=raw_record_ref,
        timestamp_field="Created0x10",
        description="Synthetic MFT row reference.",
    )


def synthetic_registry_ref(
    raw_record_ref: str | None = "json:runkeys.json:/entries/12",
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id="EV-SYN-REG-001",
        parser="recmd",
        source="NTUSER.DAT",
        raw_record_ref=raw_record_ref,
        timestamp_field="LastWriteTimestamp",
        description="Synthetic Registry Run key reference.",
    )


def synthetic_confirmed_finding() -> Finding:
    return Finding(
        finding_id="F-SYN-001",
        claim="C:/Temp/payload.dll creation predates Run key persistence for the same path.",
        status=ClaimStatus.CONFIRMED,
        confidence=Confidence.HIGH,
        kind=FindingKind.CONCLUSION,
        evidence_refs=[synthetic_mft_ref(), synthetic_registry_ref()],
        audit_event_refs=["TR-SYN-001", "TR-SYN-002"],
        artifact_hashes=[SYNTHETIC_HASH],
        raw_record_refs=["csv:mft.csv:1842", "json:runkeys.json:/entries/12"],
        rationale=(
            "MFT creation timestamp and Run key value reference the same normalized path "
            "in chronological order."
        ),
        limitations=[],
    )


def test_claim_status_accepts_only_expected_values():
    assert {status.value for status in ClaimStatus} == {
        "confirmed",
        "inferred",
        "rejected",
        "needs_review",
    }

    with pytest.raises(ValueError):
        ClaimStatus("unsupported")


def test_finding_schema_includes_required_contract_fields():
    payload = synthetic_confirmed_finding().to_dict()

    assert {
        "finding_id",
        "claim",
        "status",
        "evidence_refs",
        "audit_event_refs",
        "artifact_hashes",
        "raw_record_refs",
        "confidence",
        "rationale",
        "kind",
        "limitations",
        "supports_final_report",
    } <= payload.keys()


def test_valid_confirmed_finding_serializes_to_deterministic_json_compatible_dict():
    payload = synthetic_confirmed_finding().to_dict()

    assert payload == {
        "finding_id": "F-SYN-001",
        "claim": "C:/Temp/payload.dll creation predates Run key persistence for the same path.",
        "status": "confirmed",
        "confidence": "high",
        "kind": "conclusion",
        "evidence_refs": [
            {
                "evidence_id": "EV-SYN-MFT-001",
                "artifact_id": None,
                "parser": "mftecmd",
                "source": "$MFT",
                "raw_record_ref": "csv:mft.csv:1842",
                "timestamp_field": "Created0x10",
                "description": "Synthetic MFT row reference.",
            },
            {
                "evidence_id": "EV-SYN-REG-001",
                "artifact_id": None,
                "parser": "recmd",
                "source": "NTUSER.DAT",
                "raw_record_ref": "json:runkeys.json:/entries/12",
                "timestamp_field": "LastWriteTimestamp",
                "description": "Synthetic Registry Run key reference.",
            },
        ],
        "audit_event_refs": ["TR-SYN-001", "TR-SYN-002"],
        "artifact_hashes": [SYNTHETIC_HASH],
        "raw_record_refs": ["csv:mft.csv:1842", "json:runkeys.json:/entries/12"],
        "rationale": (
            "MFT creation timestamp and Run key value reference the same normalized path "
            "in chronological order."
        ),
        "limitations": [],
        "supports_final_report": True,
    }
    assert json.loads(json.dumps(payload, sort_keys=True)) == payload
    assert Finding.from_dict(payload).to_dict() == payload


def test_confirmed_finding_without_evidence_refs_fails_validation():
    with pytest.raises(ValueError, match="evidence reference"):
        Finding(
            finding_id="F-SYN-NO-EVIDENCE",
            claim="Synthetic claim with no supporting evidence.",
            status="confirmed",
            confidence="high",
            kind="conclusion",
            evidence_refs=[],
            artifact_hashes=[SYNTHETIC_HASH],
            raw_record_refs=["csv:mft.csv:1842"],
            rationale="Synthetic rationale.",
        )


def test_confirmed_finding_requires_raw_record_refs_directly_or_through_evidence_refs():
    with pytest.raises(ValueError, match="raw record"):
        Finding(
            finding_id="F-SYN-NO-RAW",
            claim="Synthetic claim with evidence but no raw record reference.",
            status=ClaimStatus.CONFIRMED,
            confidence=Confidence.HIGH,
            kind=FindingKind.CONCLUSION,
            evidence_refs=[synthetic_mft_ref(raw_record_ref=None)],
            artifact_hashes=[SYNTHETIC_HASH],
            raw_record_refs=[],
            rationale="Synthetic rationale.",
        )

    finding = Finding(
        finding_id="F-SYN-RAW-VIA-EVIDENCE",
        claim="Synthetic claim with raw record support through evidence refs.",
        status=ClaimStatus.CONFIRMED,
        confidence=Confidence.HIGH,
        kind=FindingKind.CONCLUSION,
        evidence_refs=[synthetic_mft_ref()],
        artifact_hashes=[SYNTHETIC_HASH],
        raw_record_refs=[],
        rationale="Synthetic rationale.",
    )

    assert finding.supports_final_report is True


def test_confirmed_finding_requires_artifact_hashes_or_hash_limitation():
    with pytest.raises(ValueError, match="artifact hashes"):
        Finding(
            finding_id="F-SYN-NO-HASH",
            claim="Synthetic claim with no artifact hash.",
            status=ClaimStatus.CONFIRMED,
            confidence=Confidence.HIGH,
            kind=FindingKind.CONCLUSION,
            evidence_refs=[synthetic_mft_ref()],
            raw_record_refs=["csv:mft.csv:1842"],
            rationale="Synthetic rationale.",
        )

    finding = Finding(
        finding_id="F-SYN-HASH-LIMITATION",
        claim="Synthetic claim with documented hash limitation.",
        status=ClaimStatus.CONFIRMED,
        confidence=Confidence.MEDIUM,
        kind=FindingKind.CONCLUSION,
        evidence_refs=[synthetic_mft_ref()],
        raw_record_refs=["csv:mft.csv:1842"],
        rationale="Synthetic rationale.",
        limitations=["Artifact hashes are unavailable in this synthetic parser fixture."],
    )

    assert finding.supports_final_report is True


def test_inferred_finding_requires_evidence_refs_and_rationale():
    with pytest.raises(ValueError, match="evidence reference"):
        Finding(
            finding_id="F-SYN-INFERRED-NO-EVIDENCE",
            claim="Synthetic inferred claim with no evidence.",
            status=ClaimStatus.INFERRED,
            confidence=Confidence.LOW,
            kind=FindingKind.CONCLUSION,
            rationale="Synthetic rationale.",
        )

    with pytest.raises(ValueError, match="rationale"):
        Finding(
            finding_id="F-SYN-INFERRED-NO-RATIONALE",
            claim="Synthetic inferred claim with no rationale.",
            status=ClaimStatus.INFERRED,
            confidence=Confidence.LOW,
            kind=FindingKind.CONCLUSION,
            evidence_refs=[synthetic_mft_ref()],
        )

    finding = Finding(
        finding_id="F-SYN-INFERRED",
        claim="Synthetic inferred claim.",
        status=ClaimStatus.INFERRED,
        confidence=Confidence.MEDIUM,
        kind=FindingKind.CONCLUSION,
        evidence_refs=[synthetic_mft_ref()],
        rationale="Synthetic rationale.",
    )

    assert finding.to_dict()["supports_final_report"] is True


def test_rejected_finding_requires_rationale_and_does_not_support_final_report():
    with pytest.raises(ValueError, match="rationale"):
        Finding(
            finding_id="F-SYN-REJECTED-NO-RATIONALE",
            claim="Synthetic rejected claim with no rationale.",
            status=ClaimStatus.REJECTED,
            confidence=Confidence.HIGH,
            kind=FindingKind.CONCLUSION,
        )

    payload = Finding(
        finding_id="F-SYN-REJECTED",
        claim="Synthetic rejected claim.",
        status=ClaimStatus.REJECTED,
        confidence=Confidence.HIGH,
        kind=FindingKind.CONCLUSION,
        rationale="Synthetic records contradict the claim.",
    ).to_dict()

    assert payload["status"] == "rejected"
    assert payload["supports_final_report"] is False


def test_needs_review_finding_can_represent_ambiguity_without_final_report_support():
    payload = Finding(
        finding_id="F-SYN-REVIEW",
        claim="Synthetic ambiguous claim requiring analyst review.",
        status=ClaimStatus.NEEDS_REVIEW,
        confidence=Confidence.LOW,
        kind=FindingKind.CONCLUSION,
        limitations=["Synthetic example has incomplete evidence references."],
    ).to_dict()

    assert payload["status"] == "needs_review"
    assert payload["supports_final_report"] is False


def test_unsupported_evidence_free_finding_cannot_be_emitted_as_confirmed():
    payload = {
        "finding_id": "F-SYN-UNSUPPORTED",
        "claim": "Synthetic evidence-free claim.",
        "status": "confirmed",
        "confidence": "high",
        "kind": "conclusion",
        "evidence_refs": [],
        "audit_event_refs": [],
        "artifact_hashes": [],
        "raw_record_refs": [],
        "rationale": "Synthetic rationale.",
        "limitations": [],
        "supports_final_report": True,
    }

    with pytest.raises(ValueError, match="evidence reference"):
        Finding.from_dict(payload)


def test_observations_and_conclusions_are_distinguishable():
    observation = Finding(
        finding_id="F-SYN-OBS",
        claim="Synthetic parser observed a file creation record.",
        status=ClaimStatus.NEEDS_REVIEW,
        confidence=Confidence.MEDIUM,
        kind=FindingKind.OBSERVATION,
        evidence_refs=[synthetic_mft_ref()],
    )
    conclusion = Finding(
        finding_id="F-SYN-CONCLUSION",
        claim="Synthetic file creation predates persistence.",
        status=ClaimStatus.NEEDS_REVIEW,
        confidence=Confidence.MEDIUM,
        kind=FindingKind.CONCLUSION,
        evidence_refs=[synthetic_mft_ref()],
    )

    assert observation.to_dict()["kind"] == "observation"
    assert conclusion.to_dict()["kind"] == "conclusion"


def test_synthetic_example_contains_no_real_evidence_or_private_paths():
    payload = synthetic_confirmed_finding().to_dict()
    encoded = json.dumps(payload)

    assert payload["finding_id"] == "F-SYN-001"
    assert "C:/Temp/payload.dll" in encoded
    for forbidden in ("/mnt/evidence", "/home/", "runs/", ".local/", "CASE-"):
        assert forbidden not in encoded
