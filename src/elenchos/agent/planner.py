from __future__ import annotations

from elenchos.agent.models import AgentPhase, AgentPlan, AgentStep, AgentStepStatus

AGENT_PHASES = (
    AgentPhase.INVENTORY,
    AgentPhase.PARSE,
    AgentPhase.CORRELATE,
    AgentPhase.VALIDATE,
    AgentPhase.REPORT,
    AgentPhase.VERIFY,
)

DEFAULT_AGENT_OBJECTIVE = "Run the constrained deterministic Elenchos workflow."


def _require_non_empty_string(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _plan_step(phase: AgentPhase) -> AgentStep:
    return AgentStep(
        step_id=f"step_{phase.value}",
        phase=phase,
        status=AgentStepStatus.PENDING,
        action=f"elenchos.agent.{phase.value}",
    )


def build_default_agent_plan(case_id: str, *, created_at: str) -> AgentPlan:
    """Build the deterministic Elenchos agent plan."""
    case_id = _require_non_empty_string("case_id", case_id)
    created_at = _require_non_empty_string("created_at", created_at)
    return AgentPlan(
        plan_id=f"plan_{case_id}",
        case_id=case_id,
        objective=DEFAULT_AGENT_OBJECTIVE,
        steps=[_plan_step(phase) for phase in AGENT_PHASES],
        created_at=created_at,
    )


def plan_next_actions(case_id: str, *, created_at: str) -> AgentPlan:
    """Return the next deterministic workflow plan for a case."""
    return build_default_agent_plan(case_id, created_at=created_at)


__all__ = [
    "AGENT_PHASES",
    "DEFAULT_AGENT_OBJECTIVE",
    "build_default_agent_plan",
    "plan_next_actions",
]
