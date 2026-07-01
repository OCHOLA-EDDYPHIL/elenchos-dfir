"""Policy-gated agentic orchestration for Elenchos.

This package adds a real, evidence-visible autonomy loop on top of the existing
deterministic forensic engine. It *composes* the deterministic parser, verifier,
policy, and self-correction layers rather than replacing them: the deterministic
``run_agent_workflow`` remains the execution primitive, and a
:class:`~elenchos.autonomy.supervisor.AutonomySupervisor` drives an
observe -> decide -> validate -> execute -> verify -> reflect -> stop loop over it.

A model never becomes evidence here. Providers may only *propose* one bounded,
allow-listed action per step; every proposal is gated by the deterministic policy
engine, executed through typed operations, and recorded to an auditable bundle.
"""

from __future__ import annotations

from elenchos.autonomy.decision import AutonomyDecision, PlanRevision, StateObservation
from elenchos.autonomy.providers import (
    ClaudeCodeDecisionProvider,
    DecisionProvider,
    OpenClawDecisionProvider,
    ReplayDecisionProvider,
)
from elenchos.autonomy.supervisor import AutonomyResult, AutonomySupervisor, run_autonomy

__all__ = [
    "AutonomyDecision",
    "PlanRevision",
    "StateObservation",
    "DecisionProvider",
    "ReplayDecisionProvider",
    "ClaudeCodeDecisionProvider",
    "OpenClawDecisionProvider",
    "AutonomySupervisor",
    "AutonomyResult",
    "run_autonomy",
]
