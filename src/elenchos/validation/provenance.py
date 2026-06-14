from __future__ import annotations

from elenchos.validation.models import ClaimStatus, Finding


def validate_finding_has_evidence(finding: Finding) -> tuple[bool, str]:
    if finding.status is ClaimStatus.CONFIRMED and not finding.supports_final_report:
        return False, "confirmed finding requires evidence, raw record, and hash support"

    if finding.status is ClaimStatus.INFERRED and not finding.supports_final_report:
        return False, "inferred finding requires evidence and rationale"

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
