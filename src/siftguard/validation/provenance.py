from __future__ import annotations

from siftguard.validation.findings import Finding


def validate_finding_has_evidence(finding: Finding) -> tuple[bool, str]:
    if finding.status == "confirmed" and not finding.evidence_refs:
        return False, "confirmed finding requires at least one evidence reference"

    if finding.status == "inferred" and not finding.inference:
        return False, "inferred finding must set inference=true"

    return True, "ok"


def validate_findings(findings: list[Finding]) -> list[dict]:
    results: list[dict] = []
    for finding in findings:
        valid, reason = validate_finding_has_evidence(finding)
        results.append(
            {
                "finding_id": finding.finding_id,
                "valid": valid,
                "reason": reason,
            }
        )
    return results
