from __future__ import annotations

import pytest

from elenchos.agent.models import AgentPlan, AgentStepStatus
from elenchos.agent.planner import (
    AGENT_PHASES,
    build_default_agent_plan,
    plan_next_actions,
)

CASE_ID = "CASE-SYN-001"
FIXED_TIME = "2026-01-01T00:00:00Z"
EXPECTED_PHASES = [
    "inventory",
    "parse",
    "correlate",
    "validate",
    "report",
    "verify",
]


def test_build_default_agent_plan_returns_deterministic_pending_plan():
    plan = build_default_agent_plan(CASE_ID, created_at=FIXED_TIME)

    assert isinstance(plan, AgentPlan)
    assert plan.plan_id == f"plan_{CASE_ID}"
    assert plan.case_id == CASE_ID
    assert plan.created_at == FIXED_TIME
    assert [phase.value for phase in AGENT_PHASES] == EXPECTED_PHASES
    assert [step.phase.value for step in plan.steps] == EXPECTED_PHASES
    assert [step.status for step in plan.steps] == [AgentStepStatus.PENDING] * len(
        EXPECTED_PHASES
    )
    assert [step.step_id for step in plan.steps] == [
        f"step_{phase}" for phase in EXPECTED_PHASES
    ]
    assert [step.action for step in plan.steps] == [
        f"elenchos.agent.{phase}" for phase in EXPECTED_PHASES
    ]


def test_plan_next_actions_matches_default_plan():
    assert plan_next_actions(CASE_ID, created_at=FIXED_TIME).to_dict() == (
        build_default_agent_plan(CASE_ID, created_at=FIXED_TIME).to_dict()
    )


def test_build_default_agent_plan_rejects_empty_case_id():
    with pytest.raises(ValueError, match="case_id must be a non-empty string"):
        build_default_agent_plan("", created_at=FIXED_TIME)


def test_build_default_agent_plan_rejects_empty_created_at():
    with pytest.raises(ValueError, match="created_at must be a non-empty string"):
        build_default_agent_plan(CASE_ID, created_at="")
