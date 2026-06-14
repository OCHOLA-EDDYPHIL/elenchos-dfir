from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from elenchos.evidence.manifest import EvidenceArtifact
from elenchos.validation.models import EvidenceRef

JSON_SCALAR = str | int | float | bool | None
BLOCKED_EXECUTION_KEYS = {
    "argv",
    "bash",
    "cmd",
    "command",
    "executable",
    "powershell",
    "raw_command",
    "script",
    "shell",
    "subprocess",
}


class AgentPhase(str, Enum):
    INVENTORY = "inventory"
    PARSE = "parse"
    CORRELATE = "correlate"
    VALIDATE = "validate"
    REPORT = "report"
    VERIFY = "verify"


class AgentStepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AgentRunStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"


class CorrectionTrigger(str, Enum):
    MISSING_OUTPUT = "missing_output"
    INVALID_OUTPUT = "invalid_output"
    UNSUPPORTED_FINDING = "unsupported_finding"
    CONTRADICTION = "contradiction"
    MAX_ITERATIONS = "max_iterations"


class CorrectionAction(str, Enum):
    RETRY = "retry"
    RECHECK_INVENTORY = "recheck_inventory"
    DOWNGRADE_FINDING = "downgrade_finding"
    REJECT_FINDING = "reject_finding"
    BLOCK_FINALIZATION = "block_finalization"


def _coerce_agent_phase(value: AgentPhase | str) -> AgentPhase:
    try:
        return AgentPhase(value)
    except ValueError as exc:
        raise ValueError(f"invalid phase: {value}") from exc


def _coerce_step_status(value: AgentStepStatus | str) -> AgentStepStatus:
    try:
        return AgentStepStatus(value)
    except ValueError as exc:
        raise ValueError(f"invalid step status: {value}") from exc


def _coerce_run_status(value: AgentRunStatus | str) -> AgentRunStatus:
    try:
        return AgentRunStatus(value)
    except ValueError as exc:
        raise ValueError(f"invalid run status: {value}") from exc


def _coerce_correction_trigger(value: CorrectionTrigger | str) -> CorrectionTrigger:
    try:
        return CorrectionTrigger(value)
    except ValueError as exc:
        raise ValueError(f"invalid correction trigger: {value}") from exc


def _coerce_correction_action(value: CorrectionAction | str) -> CorrectionAction:
    try:
        return CorrectionAction(value)
    except ValueError as exc:
        raise ValueError(f"invalid correction action: {value}") from exc


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


def _validate_string_list(name: str, values: list[str]) -> list[str]:
    if not isinstance(values, list):
        raise TypeError(f"{name} must be a list of strings")
    if not all(isinstance(item, str) and item for item in values):
        raise ValueError(f"{name} must contain only non-empty strings")
    return values


def _utc_timestamp(value: datetime | str | None) -> str | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp datetime must be timezone-aware")
        return (
            value.astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    if not isinstance(value, str):
        raise TypeError("timestamp must be a datetime, string, or None")
    if not value:
        raise ValueError("timestamp must not be empty when provided")
    if value.endswith("+00:00"):
        return value[:-6] + "Z"
    if not value.endswith("Z"):
        raise ValueError("timestamp string must use explicit UTC with trailing Z")
    return value


def _required_timestamp(name: str, value: datetime | str) -> str:
    timestamp = _utc_timestamp(value)
    if timestamp is None:
        raise ValueError(f"{name} must be provided")
    return timestamp


def _validate_json_value(name: str, value: Any) -> JSON_SCALAR | list[Any] | dict[str, Any]:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, list):
        return [_validate_json_value(f"{name}[]", item) for item in value]
    if isinstance(value, dict):
        return _validate_json_object(name, value)
    raise TypeError(f"{name} must contain only JSON-compatible values")


def _validate_json_object(name: str, values: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(values, Mapping):
        raise TypeError(f"{name} must be a dictionary")

    checked: dict[str, Any] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{name} keys must be non-empty strings")
        if key.casefold() in BLOCKED_EXECUTION_KEYS:
            raise ValueError(f"{name} contains blocked execution key: {key}")
        checked[key] = _validate_json_value(f"{name}.{key}", value)
    return checked


def _validate_output_refs(output_refs: dict[str, str]) -> dict[str, str]:
    if not isinstance(output_refs, dict):
        raise TypeError("output_refs must be a dictionary")
    for key, value in output_refs.items():
        _validate_required_string("output_refs key", key)
        _validate_required_string("output_refs value", value)
    return dict(output_refs)


def _validate_attempts(attempts: dict[str, int]) -> dict[str, int]:
    if not isinstance(attempts, dict):
        raise TypeError("attempts must be a dictionary")
    checked: dict[str, int] = {}
    for key, value in attempts.items():
        _validate_required_string("attempts key", key)
        if not isinstance(value, int) or value < 0:
            raise ValueError("attempts values must be non-negative integers")
        checked[key] = value
    return checked


def _validate_evidence_refs(evidence_refs: list[EvidenceRef]) -> list[EvidenceRef]:
    if not isinstance(evidence_refs, list):
        raise TypeError("evidence_refs must be a list of EvidenceRef instances")
    if not all(isinstance(item, EvidenceRef) for item in evidence_refs):
        raise TypeError("evidence_refs must contain only EvidenceRef instances")
    return evidence_refs


def _validate_artifacts(artifacts: list[AgentArtifactRef]) -> list[AgentArtifactRef]:
    if not isinstance(artifacts, list):
        raise TypeError("artifacts must be a list of AgentArtifactRef instances")
    if not all(isinstance(item, AgentArtifactRef) for item in artifacts):
        raise TypeError("artifacts must contain only AgentArtifactRef instances")
    return artifacts


def _validate_steps(steps: list[AgentStep]) -> list[AgentStep]:
    if not isinstance(steps, list):
        raise TypeError("steps must be a list of AgentStep instances")
    if not all(isinstance(item, AgentStep) for item in steps):
        raise TypeError("steps must contain only AgentStep instances")
    return steps


def _validate_corrections(corrections: list[AgentCorrection]) -> list[AgentCorrection]:
    if not isinstance(corrections, list):
        raise TypeError("corrections must be a list of AgentCorrection instances")
    if not all(isinstance(item, AgentCorrection) for item in corrections):
        raise TypeError("corrections must contain only AgentCorrection instances")
    return corrections


@dataclass(slots=True)
class AgentArtifactRef:
    artifact_id: str
    artifact_type: str
    relative_path: str | None = None
    sha256: str | None = None
    source_image_id: str | None = None
    source_image_label: str | None = None

    def __post_init__(self) -> None:
        self.artifact_id = _validate_required_string("artifact_id", self.artifact_id)
        self.artifact_type = _validate_required_string("artifact_type", self.artifact_type)
        self.relative_path = _validate_optional_string("relative_path", self.relative_path)
        self.sha256 = _validate_optional_string("sha256", self.sha256)
        self.source_image_id = _validate_optional_string(
            "source_image_id",
            self.source_image_id,
        )
        self.source_image_label = _validate_optional_string(
            "source_image_label",
            self.source_image_label,
        )

    @classmethod
    def from_artifact(cls, artifact: EvidenceArtifact) -> AgentArtifactRef:
        return cls(
            artifact_id=artifact.artifact_id,
            artifact_type=artifact.artifact_type,
            relative_path=artifact.relative_path,
            sha256=artifact.sha256,
            source_image_id=artifact.source_image_id,
            source_image_label=artifact.source_image_label,
        )

    def to_dict(self) -> dict[str, str | None]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "source_image_id": self.source_image_id,
            "source_image_label": self.source_image_label,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentArtifactRef:
        return cls(
            artifact_id=data["artifact_id"],
            artifact_type=data["artifact_type"],
            relative_path=data.get("relative_path"),
            sha256=data.get("sha256"),
            source_image_id=data.get("source_image_id"),
            source_image_label=data.get("source_image_label"),
        )


@dataclass(slots=True)
class AgentStep:
    step_id: str
    phase: AgentPhase
    status: AgentStepStatus
    attempt: int = 1
    max_attempts: int = 1
    started_at: datetime | str | None = None
    completed_at: datetime | str | None = None
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    action: str | None = None

    def __post_init__(self) -> None:
        self.step_id = _validate_required_string("step_id", self.step_id)
        self.phase = _coerce_agent_phase(self.phase)
        self.status = _coerce_step_status(self.status)
        if not isinstance(self.attempt, int) or self.attempt <= 0:
            raise ValueError("attempt must be a positive integer")
        if not isinstance(self.max_attempts, int) or self.max_attempts <= 0:
            raise ValueError("max_attempts must be a positive integer")
        if self.attempt > self.max_attempts:
            raise ValueError("attempt must not exceed max_attempts")
        self.started_at = _utc_timestamp(self.started_at)
        self.completed_at = _utc_timestamp(self.completed_at)
        self.inputs = _validate_json_object("inputs", self.inputs)
        self.outputs = _validate_json_object("outputs", self.outputs)
        self.error = _validate_optional_string("error", self.error)
        self.evidence_refs = _validate_evidence_refs(self.evidence_refs)
        self.action = _validate_optional_string("action", self.action)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "phase": self.phase.value,
            "status": self.status.value,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "inputs": dict(self.inputs),
            "outputs": dict(self.outputs),
            "error": self.error,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "action": self.action,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentStep:
        return cls(
            step_id=data["step_id"],
            phase=data["phase"],
            status=data["status"],
            attempt=data.get("attempt", 1),
            max_attempts=data.get("max_attempts", 1),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            inputs=dict(data.get("inputs", {})),
            outputs=dict(data.get("outputs", {})),
            error=data.get("error"),
            evidence_refs=[
                EvidenceRef.from_dict(ref) for ref in data.get("evidence_refs", [])
            ],
            action=data.get("action"),
        )


@dataclass(slots=True)
class AgentCorrection:
    correction_id: str
    trigger: CorrectionTrigger
    diagnosis: str
    action: CorrectionAction
    result: str
    created_at: datetime | str
    related_step_id: str | None = None
    evidence_refs: list[EvidenceRef] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.correction_id = _validate_required_string("correction_id", self.correction_id)
        self.trigger = _coerce_correction_trigger(self.trigger)
        self.diagnosis = _validate_required_string("diagnosis", self.diagnosis)
        self.action = _coerce_correction_action(self.action)
        self.result = _validate_required_string("result", self.result)
        self.created_at = _required_timestamp("created_at", self.created_at)
        self.related_step_id = _validate_optional_string("related_step_id", self.related_step_id)
        self.evidence_refs = _validate_evidence_refs(self.evidence_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "correction_id": self.correction_id,
            "trigger": self.trigger.value,
            "diagnosis": self.diagnosis,
            "action": self.action.value,
            "result": self.result,
            "created_at": self.created_at,
            "related_step_id": self.related_step_id,
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCorrection:
        return cls(
            correction_id=data["correction_id"],
            trigger=data["trigger"],
            diagnosis=data["diagnosis"],
            action=data["action"],
            result=data["result"],
            created_at=data["created_at"],
            related_step_id=data.get("related_step_id"),
            evidence_refs=[
                EvidenceRef.from_dict(ref) for ref in data.get("evidence_refs", [])
            ],
        )


@dataclass(slots=True)
class AgentPlan:
    plan_id: str
    case_id: str
    objective: str
    steps: list[AgentStep]
    created_at: datetime | str

    def __post_init__(self) -> None:
        self.plan_id = _validate_required_string("plan_id", self.plan_id)
        self.case_id = _validate_required_string("case_id", self.case_id)
        self.objective = _validate_required_string("objective", self.objective)
        self.steps = _validate_steps(self.steps)
        self.created_at = _required_timestamp("created_at", self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "case_id": self.case_id,
            "objective": self.objective,
            "steps": [step.to_dict() for step in self.steps],
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentPlan:
        return cls(
            plan_id=data["plan_id"],
            case_id=data["case_id"],
            objective=data["objective"],
            steps=[AgentStep.from_dict(step) for step in data.get("steps", [])],
            created_at=data["created_at"],
        )


@dataclass(slots=True)
class AgentState:
    case_id: str
    artifacts: list[AgentArtifactRef] = field(default_factory=list)
    completed_steps: list[str] = field(default_factory=list)
    attempts: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    corrections: list[AgentCorrection] = field(default_factory=list)
    final_status: AgentRunStatus = AgentRunStatus.PLANNED

    def __post_init__(self) -> None:
        self.case_id = _validate_required_string("case_id", self.case_id)
        self.artifacts = _validate_artifacts(self.artifacts)
        self.completed_steps = _validate_string_list("completed_steps", self.completed_steps)
        self.attempts = _validate_attempts(self.attempts)
        self.errors = _validate_string_list("errors", self.errors)
        self.corrections = _validate_corrections(self.corrections)
        self.final_status = _coerce_run_status(self.final_status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "completed_steps": list(self.completed_steps),
            "attempts": dict(self.attempts),
            "errors": list(self.errors),
            "corrections": [correction.to_dict() for correction in self.corrections],
            "final_status": self.final_status.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentState:
        return cls(
            case_id=data["case_id"],
            artifacts=[
                AgentArtifactRef.from_dict(artifact)
                for artifact in data.get("artifacts", [])
            ],
            completed_steps=list(data.get("completed_steps", [])),
            attempts=dict(data.get("attempts", {})),
            errors=list(data.get("errors", [])),
            corrections=[
                AgentCorrection.from_dict(correction)
                for correction in data.get("corrections", [])
            ],
            final_status=data.get("final_status", AgentRunStatus.PLANNED.value),
        )


@dataclass(slots=True)
class AgentRun:
    run_id: str
    case_id: str
    status: AgentRunStatus
    plan: AgentPlan
    state: AgentState
    started_at: datetime | str
    max_iterations: int
    max_normalized_events: int | None = None
    event_selection_profile: str = "first-n"
    input_source: str | None = None
    steps: list[AgentStep] = field(default_factory=list)
    corrections: list[AgentCorrection] = field(default_factory=list)
    completed_at: datetime | str | None = None
    output_refs: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.run_id = _validate_required_string("run_id", self.run_id)
        self.case_id = _validate_required_string("case_id", self.case_id)
        self.status = _coerce_run_status(self.status)
        if not isinstance(self.plan, AgentPlan):
            raise TypeError("plan must be an AgentPlan instance")
        if not isinstance(self.state, AgentState):
            raise TypeError("state must be an AgentState instance")
        if self.plan.case_id != self.case_id:
            raise ValueError("plan case_id must match run case_id")
        if self.state.case_id != self.case_id:
            raise ValueError("state case_id must match run case_id")
        self.started_at = _required_timestamp("started_at", self.started_at)
        self.completed_at = _utc_timestamp(self.completed_at)
        if not isinstance(self.max_iterations, int) or self.max_iterations <= 0:
            raise ValueError("max_iterations must be a positive integer")
        if self.max_normalized_events is not None and (
            not isinstance(self.max_normalized_events, int)
            or self.max_normalized_events < 1
        ):
            raise ValueError(
                "max_normalized_events must be a positive integer when provided"
            )
        self.event_selection_profile = _validate_required_string(
            "event_selection_profile",
            self.event_selection_profile,
        )
        self.input_source = _validate_optional_string("input_source", self.input_source)
        self.steps = _validate_steps(self.steps)
        self.corrections = _validate_corrections(self.corrections)
        self.output_refs = _validate_output_refs(self.output_refs)
        self.warnings = _validate_string_list("warnings", self.warnings)
        self.errors = _validate_string_list("errors", self.errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "status": self.status.value,
            "plan": self.plan.to_dict(),
            "state": self.state.to_dict(),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "max_iterations": self.max_iterations,
            "max_normalized_events": self.max_normalized_events,
            "event_selection_profile": self.event_selection_profile,
            "input_source": self.input_source,
            "steps": [step.to_dict() for step in self.steps],
            "corrections": [correction.to_dict() for correction in self.corrections],
            "output_refs": dict(self.output_refs),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentRun:
        return cls(
            run_id=data["run_id"],
            case_id=data["case_id"],
            status=data["status"],
            plan=AgentPlan.from_dict(data["plan"]),
            state=AgentState.from_dict(data["state"]),
            started_at=data["started_at"],
            max_iterations=data["max_iterations"],
            max_normalized_events=data.get("max_normalized_events"),
            event_selection_profile=data.get("event_selection_profile", "first-n"),
            input_source=data.get("input_source"),
            steps=[AgentStep.from_dict(step) for step in data.get("steps", [])],
            corrections=[
                AgentCorrection.from_dict(correction)
                for correction in data.get("corrections", [])
            ],
            completed_at=data.get("completed_at"),
            output_refs=dict(data.get("output_refs", {})),
            warnings=list(data.get("warnings", [])),
            errors=list(data.get("errors", [])),
        )
