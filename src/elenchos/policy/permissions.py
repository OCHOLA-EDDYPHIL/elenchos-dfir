"""Minimal active permission policy declarations for evidence safety.

Enforcement lives in path validation, parser wrappers, subprocess execution,
and the deterministic agent runner. These constants name the current boundary
without claiming comprehensive sandboxing.
"""

READ_ONLY_EVIDENCE_REQUIRED = True
GENERATED_OUTPUTS_MUST_BE_OUTSIDE_EVIDENCE_ROOT = True
ARBITRARY_SHELL_AS_AGENT_INTERFACE_ALLOWED = False

__all__ = [
    "ARBITRARY_SHELL_AS_AGENT_INTERFACE_ALLOWED",
    "GENERATED_OUTPUTS_MUST_BE_OUTSIDE_EVIDENCE_ROOT",
    "READ_ONLY_EVIDENCE_REQUIRED",
]
