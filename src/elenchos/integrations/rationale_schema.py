from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

from elenchos.audit.execution_ledger import utc_now

JSONValue = str | int | float | bool | None | list["JSONValue"] | dict[str, "JSONValue"]
PolicyDecision = Literal["allowed", "rejected"]


def _required_string(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_string(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    return _required_string(name, value)


def _string_list(name: str, values: list[str]) -> list[str]:
    if not isinstance(values, list):
        raise TypeError(f"{name} must be a list")
    if not all(isinstance(item, str) and item for item in values):
        raise ValueError(f"{name} must contain only non-empty strings")
    return list(values)


def _json_value(name: str, value: Any) -> JSONValue:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, list):
        return [_json_value(f"{name}[]", item) for item in value]
    if isinstance(value, dict):
        return _json_object(name, value)
    raise TypeError(f"{name} must contain only JSON-compatible values")


def _json_object(name: str, value: Mapping[str, Any]) -> dict[str, JSONValue]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    checked: dict[str, JSONValue] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{name} keys must be non-empty strings")
        checked[key] = _json_value(f"{name}.{key}", item)
    return checked


def _bool_map(name: str, value: Mapping[str, bool]) -> dict[str, bool]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    checked: dict[str, bool] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{name} keys must be non-empty strings")
        if not isinstance(item, bool):
            raise TypeError(f"{name}.{key} must be a boolean")
        checked[key] = item
    return checked


def _int_map(name: str, value: Mapping[str, int]) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    checked: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{name} keys must be non-empty strings")
        if not isinstance(item, int):
            raise TypeError(f"{name}.{key} must be an integer")
        checked[key] = item
    return checked


def _utc_timestamp(value: str | None = None) -> str:
    timestamp = value or utc_now()
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("timestamp must be UTC with trailing Z")
    return timestamp


@dataclass(frozen=True, slots=True)
class ModelRationaleRecord:
    rationale_id: str
    timestamp_utc: str
    phase: str
    visible_message: str
    proposed_action: str
    rationale_summary: str
    basis_files: list[str]
    observed_state: dict[str, JSONValue]
    forbidden_claims_avoided: list[str]
    confidence: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "rationale_id",
            _required_string("rationale_id", self.rationale_id),
        )
        object.__setattr__(self, "timestamp_utc", _utc_timestamp(self.timestamp_utc))
        object.__setattr__(self, "phase", _required_string("phase", self.phase))
        object.__setattr__(
            self,
            "visible_message",
            _required_string("visible_message", self.visible_message),
        )
        object.__setattr__(
            self,
            "proposed_action",
            _required_string("proposed_action", self.proposed_action),
        )
        object.__setattr__(
            self,
            "rationale_summary",
            _required_string("rationale_summary", self.rationale_summary),
        )
        object.__setattr__(self, "basis_files", _string_list("basis_files", self.basis_files))
        object.__setattr__(
            self,
            "observed_state",
            _json_object("observed_state", self.observed_state),
        )
        object.__setattr__(
            self,
            "forbidden_claims_avoided",
            _string_list("forbidden_claims_avoided", self.forbidden_claims_avoided),
        )
        object.__setattr__(self, "confidence", _required_string("confidence", self.confidence))

    def to_dict(self) -> dict[str, object]:
        return {
            "rationale_id": self.rationale_id,
            "timestamp_utc": self.timestamp_utc,
            "phase": self.phase,
            "visible_message": self.visible_message,
            "proposed_action": self.proposed_action,
            "rationale_summary": self.rationale_summary,
            "basis_files": list(self.basis_files),
            "observed_state": dict(self.observed_state),
            "forbidden_claims_avoided": list(self.forbidden_claims_avoided),
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class PolicyDecisionRecord:
    policy_decision_id: str
    timestamp_utc: str
    rationale_id: str | None
    proposed_action: str
    decision: PolicyDecision
    reason: str
    safety_checks: dict[str, bool]
    rejected_fields: list[str]
    normalized_action: str | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "policy_decision_id",
            _required_string("policy_decision_id", self.policy_decision_id),
        )
        object.__setattr__(self, "timestamp_utc", _utc_timestamp(self.timestamp_utc))
        object.__setattr__(
            self,
            "rationale_id",
            _optional_string("rationale_id", self.rationale_id),
        )
        object.__setattr__(
            self,
            "proposed_action",
            _required_string("proposed_action", self.proposed_action),
        )
        if self.decision not in {"allowed", "rejected"}:
            raise ValueError("decision must be allowed or rejected")
        object.__setattr__(self, "reason", _required_string("reason", self.reason))
        object.__setattr__(
            self,
            "safety_checks",
            _bool_map("safety_checks", self.safety_checks),
        )
        object.__setattr__(
            self,
            "rejected_fields",
            _string_list("rejected_fields", self.rejected_fields),
        )
        object.__setattr__(
            self,
            "normalized_action",
            _optional_string("normalized_action", self.normalized_action),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_decision_id": self.policy_decision_id,
            "timestamp_utc": self.timestamp_utc,
            "rationale_id": self.rationale_id,
            "proposed_action": self.proposed_action,
            "decision": self.decision,
            "reason": self.reason,
            "safety_checks": dict(self.safety_checks),
            "rejected_fields": list(self.rejected_fields),
            "normalized_action": self.normalized_action,
        }


@dataclass(frozen=True, slots=True)
class RunStateSummary:
    case_id: str | None
    output_dir: str
    agent_run_dir: str | None
    required_outputs_present: dict[str, bool]
    finding_status_counts: dict[str, int]
    case_question_status_counts: dict[str, int]
    coverage_gap_count: int
    self_correction_count: int
    validation_status: str | None
    active_job: dict[str, JSONValue] | None
    recommended_next_actions: list[str]
    allowed_actions: list[str]
    claim_boundary_required: bool
    basis_files: list[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_id", _optional_string("case_id", self.case_id))
        object.__setattr__(self, "output_dir", _required_string("output_dir", self.output_dir))
        object.__setattr__(
            self,
            "agent_run_dir",
            _optional_string("agent_run_dir", self.agent_run_dir),
        )
        object.__setattr__(
            self,
            "required_outputs_present",
            _bool_map("required_outputs_present", self.required_outputs_present),
        )
        object.__setattr__(
            self,
            "finding_status_counts",
            _int_map("finding_status_counts", self.finding_status_counts),
        )
        object.__setattr__(
            self,
            "case_question_status_counts",
            _int_map("case_question_status_counts", self.case_question_status_counts),
        )
        if self.coverage_gap_count < 0 or self.self_correction_count < 0:
            raise ValueError("counts must be non-negative")
        object.__setattr__(
            self,
            "validation_status",
            _optional_string("validation_status", self.validation_status),
        )
        if self.active_job is not None:
            object.__setattr__(self, "active_job", _json_object("active_job", self.active_job))
        object.__setattr__(
            self,
            "recommended_next_actions",
            _string_list("recommended_next_actions", self.recommended_next_actions),
        )
        object.__setattr__(
            self,
            "allowed_actions",
            _string_list("allowed_actions", self.allowed_actions),
        )
        object.__setattr__(self, "basis_files", _string_list("basis_files", self.basis_files))

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "output_dir": self.output_dir,
            "agent_run_dir": self.agent_run_dir,
            "required_outputs_present": dict(self.required_outputs_present),
            "finding_status_counts": dict(self.finding_status_counts),
            "case_question_status_counts": dict(self.case_question_status_counts),
            "coverage_gap_count": self.coverage_gap_count,
            "self_correction_count": self.self_correction_count,
            "validation_status": self.validation_status,
            "active_job": None if self.active_job is None else dict(self.active_job),
            "recommended_next_actions": list(self.recommended_next_actions),
            "allowed_actions": list(self.allowed_actions),
            "claim_boundary_required": self.claim_boundary_required,
            "basis_files": list(self.basis_files),
        }


@dataclass(frozen=True, slots=True)
class ActionProposal:
    proposed_action: str
    action_args: dict[str, JSONValue] = field(default_factory=dict)
    rationale_id: str | None = None
    output_dir: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "proposed_action",
            _required_string("proposed_action", self.proposed_action),
        )
        object.__setattr__(self, "action_args", _json_object("action_args", self.action_args))
        object.__setattr__(
            self,
            "rationale_id",
            _optional_string("rationale_id", self.rationale_id),
        )
        object.__setattr__(self, "output_dir", _optional_string("output_dir", self.output_dir))

    def to_dict(self) -> dict[str, object]:
        return {
            "proposed_action": self.proposed_action,
            "action_args": dict(self.action_args),
            "rationale_id": self.rationale_id,
            "output_dir": self.output_dir,
        }


@dataclass(frozen=True, slots=True)
class ActionPolicyResult:
    decision: PolicyDecision
    reason: str
    safety_checks: dict[str, bool]
    rejected_fields: list[str]
    normalized_action: str | None
    next_allowed_tools: list[str]
    visible_policy_message: str

    def __post_init__(self) -> None:
        if self.decision not in {"allowed", "rejected"}:
            raise ValueError("decision must be allowed or rejected")
        object.__setattr__(self, "reason", _required_string("reason", self.reason))
        object.__setattr__(self, "safety_checks", _bool_map("safety_checks", self.safety_checks))
        object.__setattr__(
            self,
            "rejected_fields",
            _string_list("rejected_fields", self.rejected_fields),
        )
        object.__setattr__(
            self,
            "normalized_action",
            _optional_string("normalized_action", self.normalized_action),
        )
        object.__setattr__(
            self,
            "next_allowed_tools",
            _string_list("next_allowed_tools", self.next_allowed_tools),
        )
        object.__setattr__(
            self,
            "visible_policy_message",
            _required_string("visible_policy_message", self.visible_policy_message),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "safety_checks": dict(self.safety_checks),
            "rejected_fields": list(self.rejected_fields),
            "normalized_action": self.normalized_action,
            "next_allowed_tools": list(self.next_allowed_tools),
            "visible_policy_message": self.visible_policy_message,
        }


@dataclass(frozen=True, slots=True)
class OrchestrationTrace:
    schema_version: int
    output_dir: str
    created_at_utc: str
    updated_at_utc: str
    events: list[dict[str, JSONValue]]

    def __post_init__(self) -> None:
        if self.schema_version < 1:
            raise ValueError("schema_version must be positive")
        object.__setattr__(self, "output_dir", _required_string("output_dir", self.output_dir))
        object.__setattr__(self, "created_at_utc", _utc_timestamp(self.created_at_utc))
        object.__setattr__(self, "updated_at_utc", _utc_timestamp(self.updated_at_utc))
        if not isinstance(self.events, list):
            raise TypeError("events must be a list")
        object.__setattr__(
            self,
            "events",
            [_json_object("events[]", event) for event in self.events],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "output_dir": self.output_dir,
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "events": [dict(event) for event in self.events],
        }
