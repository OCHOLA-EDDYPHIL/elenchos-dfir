"""Structured decision contract for the autonomy loop.

Every model/provider step must produce an :class:`AutonomyDecision`. The contract
forces the provider to state a hypothesis, the single bounded action it wants, the
signal that would support it, and the signal that would force a plan change -- so a
judge can read *why* the loop chose each step. The decision can never smuggle a
shell/evidence key: ``action_args`` is validated against the same
``BLOCKED_ARG_KEYS`` denylist the deterministic policy engine enforces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from elenchos.integrations.rationale_policy import BLOCKED_ARG_KEYS
from elenchos.integrations.rationale_schema import (
    JSONValue,
    _json_object,
    _optional_string,
    _required_string,
    _string_list,
    _utc_timestamp,
)

Confidence = Literal["low", "medium", "high"]
_CONFIDENCE_VALUES = ("low", "medium", "high")


def _confidence(value: str) -> Confidence:
    if value not in _CONFIDENCE_VALUES:
        raise ValueError("confidence must be one of low, medium, high")
    return value  # type: ignore[return-value]


def _blocked_arg_keys(name: str, args: dict[str, JSONValue]) -> dict[str, JSONValue]:
    """Reject any decision that tries to carry an execution/evidence key."""

    def _walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if isinstance(key, str) and key.casefold() in BLOCKED_ARG_KEYS:
                    raise ValueError(f"{path}.{key} is a blocked execution/evidence key")
                _walk(child, f"{path}.{key}")
        elif isinstance(node, list):
            for index, child in enumerate(node):
                _walk(child, f"{path}[{index}]")

    _walk(args, name)
    return args


@dataclass(frozen=True, slots=True)
class AutonomyDecision:
    """One bounded step the provider proposes, with its supporting reasoning.

    ``rationale`` is operational narration only -- it is never treated as forensic
    evidence, and the deterministic verifier/report gates prevent any final claim
    from resting on it.
    """

    decision_id: str
    timestamp_utc: str
    phase: str
    hypothesis: str
    proposed_action: str
    action_args: dict[str, JSONValue]
    expected_signal: str
    failure_or_gap_signal: str
    confidence: Confidence
    rationale: str
    observed_state_refs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision_id", _required_string("decision_id", self.decision_id))
        object.__setattr__(self, "timestamp_utc", _utc_timestamp(self.timestamp_utc))
        object.__setattr__(self, "phase", _required_string("phase", self.phase))
        object.__setattr__(self, "hypothesis", _required_string("hypothesis", self.hypothesis))
        object.__setattr__(
            self,
            "proposed_action",
            _required_string("proposed_action", self.proposed_action),
        )
        object.__setattr__(
            self,
            "action_args",
            _blocked_arg_keys("action_args", _json_object("action_args", self.action_args)),
        )
        object.__setattr__(
            self,
            "expected_signal",
            _required_string("expected_signal", self.expected_signal),
        )
        object.__setattr__(
            self,
            "failure_or_gap_signal",
            _required_string("failure_or_gap_signal", self.failure_or_gap_signal),
        )
        object.__setattr__(self, "confidence", _confidence(self.confidence))
        object.__setattr__(self, "rationale", _required_string("rationale", self.rationale))
        object.__setattr__(
            self,
            "observed_state_refs",
            _string_list("observed_state_refs", self.observed_state_refs)
            if self.observed_state_refs
            else [],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "decision_id": self.decision_id,
            "timestamp_utc": self.timestamp_utc,
            "phase": self.phase,
            "hypothesis": self.hypothesis,
            "proposed_action": self.proposed_action,
            "action_args": dict(self.action_args),
            "expected_signal": self.expected_signal,
            "failure_or_gap_signal": self.failure_or_gap_signal,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "observed_state_refs": list(self.observed_state_refs),
            "model_output_used_as_evidence": False,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AutonomyDecision:
        if not isinstance(data, dict):
            raise TypeError("decision payload must be an object")
        args = data.get("action_args", {})
        if not isinstance(args, dict):
            raise TypeError("action_args must be an object")
        refs = data.get("observed_state_refs", [])
        if not isinstance(refs, list):
            raise TypeError("observed_state_refs must be a list")
        return cls(
            decision_id=str(data.get("decision_id") or "decision_replay"),
            timestamp_utc=str(data["timestamp_utc"]) if data.get("timestamp_utc") else None,  # type: ignore[arg-type]
            phase=str(data.get("phase", "")),
            hypothesis=str(data.get("hypothesis", "")),
            proposed_action=str(data.get("proposed_action", "")),
            action_args=dict(args),
            expected_signal=str(data.get("expected_signal", "")),
            failure_or_gap_signal=str(data.get("failure_or_gap_signal", "")),
            confidence=str(data.get("confidence", "")),  # type: ignore[arg-type]
            rationale=str(data.get("rationale", "")),
            observed_state_refs=[str(item) for item in refs],
        )


@dataclass(frozen=True, slots=True)
class StateObservation:
    """A snapshot of the deterministic state the provider was allowed to see."""

    observation_id: str
    timestamp_utc: str
    iteration: int
    run_state: dict[str, JSONValue]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "observation_id",
            _required_string("observation_id", self.observation_id),
        )
        object.__setattr__(self, "timestamp_utc", _utc_timestamp(self.timestamp_utc))
        if not isinstance(self.iteration, int) or self.iteration < 0:
            raise ValueError("iteration must be a non-negative integer")
        object.__setattr__(self, "run_state", _json_object("run_state", self.run_state))

    def to_dict(self) -> dict[str, object]:
        return {
            "observation_id": self.observation_id,
            "timestamp_utc": self.timestamp_utc,
            "iteration": self.iteration,
            "run_state": dict(self.run_state),
        }


@dataclass(frozen=True, slots=True)
class PlanRevision:
    """A recorded change of plan driven by an actual failure/gap signal."""

    revision_id: str
    timestamp_utc: str
    iteration: int
    trigger: str
    observed_signal: str
    superseded_action: str | None
    revised_action: str
    rationale: str
    evidence_refs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(self, "revision_id", _required_string("revision_id", self.revision_id))
        object.__setattr__(self, "timestamp_utc", _utc_timestamp(self.timestamp_utc))
        if not isinstance(self.iteration, int) or self.iteration < 0:
            raise ValueError("iteration must be a non-negative integer")
        object.__setattr__(self, "trigger", _required_string("trigger", self.trigger))
        object.__setattr__(
            self,
            "observed_signal",
            _required_string("observed_signal", self.observed_signal),
        )
        object.__setattr__(
            self,
            "superseded_action",
            _optional_string("superseded_action", self.superseded_action),
        )
        object.__setattr__(
            self,
            "revised_action",
            _required_string("revised_action", self.revised_action),
        )
        object.__setattr__(self, "rationale", _required_string("rationale", self.rationale))
        object.__setattr__(
            self,
            "evidence_refs",
            _string_list("evidence_refs", self.evidence_refs) if self.evidence_refs else [],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "revision_id": self.revision_id,
            "timestamp_utc": self.timestamp_utc,
            "iteration": self.iteration,
            "trigger": self.trigger,
            "observed_signal": self.observed_signal,
            "superseded_action": self.superseded_action,
            "revised_action": self.revised_action,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
            "human_intervention": False,
        }
