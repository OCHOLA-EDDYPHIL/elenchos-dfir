from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from siftguard.agent.models import AgentPhase, AgentRun, AgentStep
from siftguard.audit.execution_ledger import append_event, make_event_id, read_events, utc_now
from siftguard.policy.paths import is_relative_to

Clock = Callable[[], str]


class VerificationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"


class VerificationSeverity(str, Enum):
    ERROR = "error"


class VerificationFailureKind(str, Enum):
    MISSING_PARSER_OUTPUT = "missing_parser_output"
    MISSING_EVIDENCE_REFS = "missing_evidence_refs"
    UNSUPPORTED_CONFIRMED_FINDING = "unsupported_confirmed_finding"
    REPORTED_FINDING_MISSING = "reported_finding_missing"
    MALFORMED_OUTPUT = "malformed_output"


def _coerce_status(value: VerificationStatus | str) -> VerificationStatus:
    try:
        return VerificationStatus(value)
    except ValueError as exc:
        raise ValueError(f"invalid verification status: {value}") from exc


def _coerce_severity(value: VerificationSeverity | str) -> VerificationSeverity:
    try:
        return VerificationSeverity(value)
    except ValueError as exc:
        raise ValueError(f"invalid verification severity: {value}") from exc


def _coerce_failure_kind(value: VerificationFailureKind | str) -> VerificationFailureKind:
    try:
        return VerificationFailureKind(value)
    except ValueError as exc:
        raise ValueError(f"invalid verification failure kind: {value}") from exc


def _coerce_phase(value: AgentPhase | str | None) -> AgentPhase | None:
    if value is None:
        return None
    try:
        return AgentPhase(value)
    except ValueError as exc:
        raise ValueError(f"invalid verification phase: {value}") from exc


def _validate_required_string(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _validate_optional_string(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string when provided")
    return value


def _validate_failures(failures: list[VerificationFailure]) -> list[VerificationFailure]:
    if not isinstance(failures, list):
        raise TypeError("failures must be a list of VerificationFailure instances")
    if not all(isinstance(failure, VerificationFailure) for failure in failures):
        raise TypeError("failures must contain only VerificationFailure instances")
    return failures


def _validate_output_refs(output_refs: dict[str, str]) -> dict[str, str]:
    if not isinstance(output_refs, dict):
        raise TypeError("output_refs must be a dictionary")
    checked: dict[str, str] = {}
    for key, value in output_refs.items():
        checked[_validate_required_string("output_refs key", key)] = _validate_required_string(
            "output_refs value",
            value,
        )
    return checked


def _utc_timestamp(value: str | None) -> str:
    if value is None:
        return utc_now()
    if not isinstance(value, str) or not value:
        raise ValueError("checked_at must be a non-empty string")
    if not value.endswith("Z"):
        raise ValueError("checked_at must use explicit UTC with trailing Z")
    return value


@dataclass(slots=True)
class VerificationFailure:
    kind: VerificationFailureKind
    message: str
    severity: VerificationSeverity = VerificationSeverity.ERROR
    phase: AgentPhase | None = None
    step_id: str | None = None
    path: str | None = None
    finding_id: str | None = None

    def __post_init__(self) -> None:
        self.kind = _coerce_failure_kind(self.kind)
        self.message = _validate_required_string("message", self.message)
        self.severity = _coerce_severity(self.severity)
        self.phase = _coerce_phase(self.phase)
        self.step_id = _validate_optional_string("step_id", self.step_id)
        self.path = _validate_optional_string("path", self.path)
        self.finding_id = _validate_optional_string("finding_id", self.finding_id)

    def to_dict(self) -> dict[str, str | None]:
        return {
            "kind": self.kind.value,
            "message": self.message,
            "severity": self.severity.value,
            "phase": self.phase.value if self.phase is not None else None,
            "step_id": self.step_id,
            "path": self.path,
            "finding_id": self.finding_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationFailure:
        return cls(
            kind=data["kind"],
            message=data["message"],
            severity=data.get("severity", VerificationSeverity.ERROR.value),
            phase=data.get("phase"),
            step_id=data.get("step_id"),
            path=data.get("path"),
            finding_id=data.get("finding_id"),
        )


@dataclass(slots=True)
class VerificationResult:
    case_id: str
    status: VerificationStatus
    checked_at: str
    failures: list[VerificationFailure] = field(default_factory=list)
    output_refs: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.case_id = _validate_required_string("case_id", self.case_id)
        self.status = _coerce_status(self.status)
        self.checked_at = _utc_timestamp(self.checked_at)
        self.failures = _validate_failures(self.failures)
        self.output_refs = _validate_output_refs(self.output_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "status": self.status.value,
            "checked_at": self.checked_at,
            "failure_count": len(self.failures),
            "failures": [failure.to_dict() for failure in self.failures],
            "output_refs": dict(self.output_refs),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationResult:
        return cls(
            case_id=data["case_id"],
            status=data["status"],
            checked_at=data["checked_at"],
            failures=[
                VerificationFailure.from_dict(failure)
                for failure in data.get("failures", [])
            ],
            output_refs=dict(data.get("output_refs", {})),
        )


PARSER_OUTPUT_KEYS = (
    "normalized_events",
    "parser_events",
    "parser_output",
    "parser_result",
)
REPORT_FINDING_RE = re.compile(r"^- `([^`]+)`\s+")


def _step_for_phase(agent_run: AgentRun, phase: AgentPhase) -> AgentStep | None:
    for step in agent_run.steps:
        if step.phase is phase:
            return step
    return None


def _phase_exists(agent_run: AgentRun, phase: AgentPhase) -> bool:
    return _step_for_phase(agent_run, phase) is not None


def _display_path(output_dir: Path, path: Path | None, ref: str | None) -> str | None:
    if ref is not None and not Path(ref).is_absolute():
        return ref
    if path is not None and is_relative_to(path, output_dir):
        return path.relative_to(output_dir).as_posix()
    if ref is None:
        return None
    return Path(ref).name


def _resolve_output_ref(output_dir: Path, ref: str) -> Path | None:
    candidate = Path(ref)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (output_dir / candidate).resolve()
    )
    if not is_relative_to(resolved, output_dir):
        return None
    return resolved


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON output must contain an object")
    return payload


def _findings_output_ref(agent_run: AgentRun) -> str | None:
    if "findings" in agent_run.output_refs:
        return agent_run.output_refs["findings"]
    step = _step_for_phase(agent_run, AgentPhase.VALIDATE)
    if step is None:
        return None
    value = step.outputs.get("findings")
    return value if isinstance(value, str) else None


def _report_output_ref(agent_run: AgentRun) -> str | None:
    if "report" in agent_run.output_refs:
        return agent_run.output_refs["report"]
    step = _step_for_phase(agent_run, AgentPhase.REPORT)
    if step is None:
        return None
    value = step.outputs.get("report")
    return value if isinstance(value, str) else None


def _parser_output_refs(parse_step: AgentStep | None) -> list[tuple[str, str]]:
    if parse_step is None:
        return []
    refs: list[tuple[str, str]] = []
    for key in PARSER_OUTPUT_KEYS:
        value = parse_step.outputs.get(key)
        if isinstance(value, str):
            refs.append((key, value))
    return refs


def _has_evidence_refs(finding: dict[str, Any]) -> bool:
    refs = finding.get("evidence_refs")
    return isinstance(refs, list) and bool(refs)


def _has_raw_record_support(finding: dict[str, Any]) -> bool:
    raw_record_refs = finding.get("raw_record_refs")
    if isinstance(raw_record_refs, list) and bool(raw_record_refs):
        return True
    refs = finding.get("evidence_refs")
    if not isinstance(refs, list):
        return False
    return any(isinstance(ref, dict) and bool(ref.get("raw_record_ref")) for ref in refs)


def _has_hash_support(finding: dict[str, Any]) -> bool:
    artifact_hashes = finding.get("artifact_hashes")
    if isinstance(artifact_hashes, list) and bool(artifact_hashes):
        return True
    limitations = finding.get("limitations")
    if not isinstance(limitations, list):
        return False
    return any(isinstance(item, str) and "hash" in item.casefold() for item in limitations)


def _finding_id(finding: dict[str, Any]) -> str | None:
    value = finding.get("finding_id")
    return value if isinstance(value, str) and value else None


def _load_findings(
    *,
    case_id: str,
    output_dir: Path,
    agent_run: AgentRun,
    failures: list[VerificationFailure],
    output_refs: dict[str, str],
) -> list[dict[str, Any]]:
    ref = _findings_output_ref(agent_run)
    if ref is None:
        return []

    output_refs["findings"] = ref
    path = _resolve_output_ref(output_dir, ref)
    if path is None or not path.exists():
        failures.append(
            VerificationFailure(
                kind=VerificationFailureKind.MALFORMED_OUTPUT,
                message="Validated findings output is missing.",
                phase=AgentPhase.VALIDATE,
                step_id="step_validate",
                path=_display_path(output_dir, path, ref),
            )
        )
        return []

    try:
        payload = _load_json_object(path)
    except ValueError as exc:
        failures.append(
            VerificationFailure(
                kind=VerificationFailureKind.MALFORMED_OUTPUT,
                message=f"Validated findings output is invalid: {exc}",
                phase=AgentPhase.VALIDATE,
                step_id="step_validate",
                path=_display_path(output_dir, path, ref),
            )
        )
        return []

    if payload.get("case_id") not in {None, case_id}:
        failures.append(
            VerificationFailure(
                kind=VerificationFailureKind.MALFORMED_OUTPUT,
                message="Validated findings output case_id does not match the agent run.",
                phase=AgentPhase.VALIDATE,
                step_id="step_validate",
                path=_display_path(output_dir, path, ref),
            )
        )
        return []

    findings = payload.get("findings")
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        failures.append(
            VerificationFailure(
                kind=VerificationFailureKind.MALFORMED_OUTPUT,
                message="Validated findings output must contain a findings object list.",
                phase=AgentPhase.VALIDATE,
                step_id="step_validate",
                path=_display_path(output_dir, path, ref),
            )
        )
        return []
    return [dict(item) for item in findings]


def _check_parser_outputs(
    *,
    output_dir: Path,
    agent_run: AgentRun,
    failures: list[VerificationFailure],
    output_refs: dict[str, str],
) -> None:
    if not _phase_exists(agent_run, AgentPhase.CORRELATE):
        return

    parse_step = _step_for_phase(agent_run, AgentPhase.PARSE)
    refs = _parser_output_refs(parse_step)
    if not refs:
        failures.append(
            VerificationFailure(
                kind=VerificationFailureKind.MISSING_PARSER_OUTPUT,
                message="Correlation ran without a recorded parser output reference.",
                phase=AgentPhase.PARSE,
                step_id=parse_step.step_id if parse_step is not None else None,
            )
        )
        return

    for key, ref in refs:
        output_refs[key] = ref
        path = _resolve_output_ref(output_dir, ref)
        if path is None or not path.exists():
            failures.append(
                VerificationFailure(
                    kind=VerificationFailureKind.MISSING_PARSER_OUTPUT,
                    message=f"Parser output reference '{key}' does not exist.",
                    phase=AgentPhase.PARSE,
                    step_id=parse_step.step_id if parse_step is not None else None,
                    path=_display_path(output_dir, path, ref),
                )
            )


def _check_findings_have_support(
    findings: list[dict[str, Any]],
    failures: list[VerificationFailure],
) -> None:
    for finding in findings:
        finding_id = _finding_id(finding)
        status = finding.get("status")
        if status in {"confirmed", "inferred"} and not _has_evidence_refs(finding):
            failures.append(
                VerificationFailure(
                    kind=VerificationFailureKind.MISSING_EVIDENCE_REFS,
                    message=f"{status} finding lacks evidence_refs.",
                    phase=AgentPhase.VALIDATE,
                    step_id="step_validate",
                    finding_id=finding_id,
                )
            )

        if status != "confirmed":
            continue

        if (
            finding.get("supports_final_report") is not True
            or not _has_evidence_refs(finding)
            or not _has_raw_record_support(finding)
            or not _has_hash_support(finding)
            or not finding.get("rationale")
        ):
            failures.append(
                VerificationFailure(
                    kind=VerificationFailureKind.UNSUPPORTED_CONFIRMED_FINDING,
                    message="confirmed finding lacks final-report support.",
                    phase=AgentPhase.VALIDATE,
                    step_id="step_validate",
                    finding_id=finding_id,
                )
            )


def _reported_finding_ids(report_text: str) -> set[str]:
    finding_ids: set[str] = set()
    for line in report_text.splitlines():
        match = REPORT_FINDING_RE.match(line)
        if match is not None:
            finding_ids.add(match.group(1))
    return finding_ids


def _check_reported_findings(
    *,
    output_dir: Path,
    agent_run: AgentRun,
    findings: list[dict[str, Any]],
    failures: list[VerificationFailure],
    output_refs: dict[str, str],
) -> None:
    ref = _report_output_ref(agent_run)
    if ref is None:
        return

    output_refs["report"] = ref
    path = _resolve_output_ref(output_dir, ref)
    if path is None or not path.exists():
        failures.append(
            VerificationFailure(
                kind=VerificationFailureKind.MALFORMED_OUTPUT,
                message="Markdown report output is missing.",
                phase=AgentPhase.REPORT,
                step_id="step_report",
                path=_display_path(output_dir, path, ref),
            )
        )
        return

    valid_finding_ids = {finding_id for finding in findings if (finding_id := _finding_id(finding))}
    for finding_id in sorted(_reported_finding_ids(path.read_text(encoding="utf-8"))):
        if finding_id not in valid_finding_ids:
            failures.append(
                VerificationFailure(
                    kind=VerificationFailureKind.REPORTED_FINDING_MISSING,
                    message="Markdown report references a finding absent from validated output.",
                    phase=AgentPhase.REPORT,
                    step_id="step_report",
                    path=_display_path(output_dir, path, ref),
                    finding_id=finding_id,
                )
            )


def _append_verification_events(
    *,
    audit_log_path: Path,
    case_id: str,
    status: VerificationStatus,
    failures: list[VerificationFailure],
    output_refs: dict[str, str],
    clock: Clock,
) -> None:
    def append(action: str, payload: dict[str, Any]) -> None:
        event = {
            "event_id": make_event_id(len(read_events(audit_log_path)) + 1),
            "timestamp_utc": clock(),
            "action": action,
            "case_id": case_id,
            **payload,
        }
        append_event(audit_log_path, event)

    append("verification_started", {"status": "running", "output_refs": dict(output_refs)})
    for failure in failures:
        append(
            "verification_failed",
            {
                "status": VerificationStatus.FAILED.value,
                "failure": failure.to_dict(),
            },
        )
    append(
        "verification_completed",
        {
            "status": status.value,
            "failure_count": len(failures),
            "output_refs": dict(output_refs),
        },
    )


def verify_agent_outputs(
    *,
    case_id: str,
    output_dir: Path,
    agent_run: AgentRun,
    audit_log_path: Path | None = None,
    clock: Clock = utc_now,
) -> VerificationResult:
    if not isinstance(agent_run, AgentRun):
        raise TypeError("agent_run must be an AgentRun instance")
    if agent_run.case_id != case_id:
        raise ValueError("agent_run case_id must match verification case_id")

    resolved_output_dir = output_dir.resolve()
    failures: list[VerificationFailure] = []
    output_refs: dict[str, str] = {}

    _check_parser_outputs(
        output_dir=resolved_output_dir,
        agent_run=agent_run,
        failures=failures,
        output_refs=output_refs,
    )
    findings = _load_findings(
        case_id=case_id,
        output_dir=resolved_output_dir,
        agent_run=agent_run,
        failures=failures,
        output_refs=output_refs,
    )
    _check_findings_have_support(findings, failures)
    _check_reported_findings(
        output_dir=resolved_output_dir,
        agent_run=agent_run,
        findings=findings,
        failures=failures,
        output_refs=output_refs,
    )

    status = VerificationStatus.FAILED if failures else VerificationStatus.PASSED
    checked_at = clock()
    if audit_log_path is not None:
        _append_verification_events(
            audit_log_path=audit_log_path,
            case_id=case_id,
            status=status,
            failures=failures,
            output_refs=output_refs,
            clock=clock,
        )

    return VerificationResult(
        case_id=case_id,
        status=status,
        checked_at=checked_at,
        failures=failures,
        output_refs=output_refs,
    )
