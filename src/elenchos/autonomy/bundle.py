"""Emission of the autonomy run-bundle files.

These reuse the existing generated-output JSONL machinery verbatim
(:func:`append_jsonl`, :func:`next_sequence_id`, :func:`validate_generated_trace_path`)
so the new files inherit the same evidence-root write rejection and path validation
as ``model_rationale.jsonl`` / ``policy_decisions.jsonl``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from elenchos.autonomy.decision import AutonomyDecision, PlanRevision, StateObservation
from elenchos.integrations.rationale_trace import (
    agent_run_dir_from_output_dir,
    append_jsonl,
    next_sequence_id,
    validate_generated_trace_path,
)

AUTONOMY_DECISIONS_FILENAME = "autonomy_decisions.jsonl"
STATE_OBSERVATIONS_FILENAME = "state_observations.jsonl"
PLAN_REVISIONS_FILENAME = "plan_revisions.jsonl"
TOOL_EXECUTIONS_FILENAME = "tool_executions.jsonl"
TRACE_MAP_FILENAME = "trace_map.json"

AUTONOMY_BUNDLE_FILENAMES = (
    AUTONOMY_DECISIONS_FILENAME,
    STATE_OBSERVATIONS_FILENAME,
    PLAN_REVISIONS_FILENAME,
    TOOL_EXECUTIONS_FILENAME,
    TRACE_MAP_FILENAME,
)


def resolve_agent_run_dir(output_dir: Path) -> Path:
    return agent_run_dir_from_output_dir(output_dir)


def autonomy_decisions_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / AUTONOMY_DECISIONS_FILENAME)


def state_observations_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / STATE_OBSERVATIONS_FILENAME)


def plan_revisions_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / PLAN_REVISIONS_FILENAME)


def tool_executions_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / TOOL_EXECUTIONS_FILENAME)


def trace_map_path(agent_run_dir: Path) -> Path:
    return validate_generated_trace_path(agent_run_dir / TRACE_MAP_FILENAME)


def next_decision_id(agent_run_dir: Path) -> str:
    return next_sequence_id("decision", autonomy_decisions_path(agent_run_dir))


def next_observation_id(agent_run_dir: Path) -> str:
    return next_sequence_id("observation", state_observations_path(agent_run_dir))


def next_revision_id(agent_run_dir: Path) -> str:
    return next_sequence_id("revision", plan_revisions_path(agent_run_dir))


def next_execution_id(agent_run_dir: Path) -> str:
    return next_sequence_id("execution", tool_executions_path(agent_run_dir))


def append_decision(agent_run_dir: Path, decision: AutonomyDecision) -> None:
    append_jsonl(autonomy_decisions_path(agent_run_dir), decision.to_dict())


def append_observation(agent_run_dir: Path, observation: StateObservation) -> None:
    append_jsonl(state_observations_path(agent_run_dir), observation.to_dict())


def append_plan_revision(agent_run_dir: Path, revision: PlanRevision) -> None:
    append_jsonl(plan_revisions_path(agent_run_dir), revision.to_dict())


def append_tool_execution(agent_run_dir: Path, record: Mapping[str, object]) -> None:
    append_jsonl(tool_executions_path(agent_run_dir), record)
