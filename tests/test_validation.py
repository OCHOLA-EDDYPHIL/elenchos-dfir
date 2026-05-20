from __future__ import annotations

from siftguard.validation.findings import EvidenceRef, Finding
from siftguard.validation.provenance import validate_finding_has_evidence


def test_confirmed_without_evidence_fails():
    finding = Finding(
        finding_id="f1",
        case_id="c1",
        type="persistence",
        status="confirmed",
        confidence="high",
        summary="test",
        evidence_refs=[],
        inference=False,
    )

    ok, _ = validate_finding_has_evidence(finding)
    assert not ok


def test_confirmed_with_evidence_passes():
    finding = Finding(
        finding_id="f2",
        case_id="c1",
        type="execution",
        status="confirmed",
        confidence="medium",
        summary="test",
        evidence_refs=[EvidenceRef(artifact_id="art_abc")],
        inference=False,
    )

    ok, _ = validate_finding_has_evidence(finding)
    assert ok
