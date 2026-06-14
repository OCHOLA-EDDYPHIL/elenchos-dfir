from __future__ import annotations

from elenchos.validation.models import ClaimStatus, Confidence, EvidenceRef, Finding, FindingKind

VALID_CONFIDENCE = {confidence.value for confidence in Confidence}
VALID_STATUSES = {status.value for status in ClaimStatus}

__all__ = [
    "ClaimStatus",
    "Confidence",
    "EvidenceRef",
    "Finding",
    "FindingKind",
    "VALID_CONFIDENCE",
    "VALID_STATUSES",
]
