from __future__ import annotations

import pytest

from elenchos.autonomy.decision import AutonomyDecision
from elenchos.autonomy.providers import OpenClawDecisionProvider, ReplayDecisionProvider
from elenchos.config.runtime import ModelProviderConfig, load_model_provider_config
from elenchos.integrations.rationale_schema import RunStateSummary

TS = "2026-01-01T00:00:00Z"


def _decision_kwargs(**overrides):
    base = dict(
        decision_id="decision_000001",
        timestamp_utc=TS,
        phase="analyze",
        hypothesis="Persistence may exist for updater.exe.",
        proposed_action="analyze_case",
        action_args={},
        expected_signal="A supported finding is produced.",
        failure_or_gap_signal="No parser output is produced.",
        confidence="high",
        rationale="Bounded first step.",
        observed_state_refs=["observation_000001"],
    )
    base.update(overrides)
    return base


def _run_state() -> RunStateSummary:
    return RunStateSummary(
        case_id="case_x",
        output_dir="runs/case_x/agent-run",
        agent_run_dir="runs/case_x/agent-run",
        required_outputs_present={"findings.json": False},
        finding_status_counts={},
        case_question_status_counts={},
        coverage_gap_count=0,
        self_correction_count=0,
        validation_status=None,
        active_job=None,
        recommended_next_actions=["prepare_case"],
        allowed_actions=["analyze_case", "stop"],
        claim_boundary_required=False,
        basis_files=["runs/case_x/agent-run"],
    )


def test_decision_roundtrips_and_marks_model_output_non_evidence():
    decision = AutonomyDecision(**_decision_kwargs())
    payload = decision.to_dict()
    assert payload["model_output_used_as_evidence"] is False
    assert AutonomyDecision.from_dict(payload).proposed_action == "analyze_case"


def test_decision_requires_hypothesis_and_expected_signal():
    with pytest.raises(ValueError):
        AutonomyDecision(**_decision_kwargs(hypothesis=""))
    with pytest.raises(ValueError):
        AutonomyDecision(**_decision_kwargs(expected_signal=""))


def test_decision_rejects_bad_confidence():
    with pytest.raises(ValueError):
        AutonomyDecision(**_decision_kwargs(confidence="certain"))


@pytest.mark.parametrize(
    "args",
    [
        {"command": "rm -rf /"},
        {"shell": "bash"},
        {"nested": {"raw_evidence_path": "/mnt/evidence/x"}},
    ],
)
def test_decision_rejects_blocked_execution_and_evidence_keys(args):
    with pytest.raises(ValueError):
        AutonomyDecision(**_decision_kwargs(action_args=args))


def test_replay_provider_returns_in_order_then_stops():
    rows = [
        _decision_kwargs(proposed_action="analyze_case"),
        _decision_kwargs(proposed_action="verify_outputs"),
    ]
    provider = ReplayDecisionProvider.from_dicts(rows)
    state = _run_state()
    first = provider.propose(state=state, history=[], iteration=1)
    second = provider.propose(state=state, history=[], iteration=2)
    exhausted = provider.propose(state=state, history=[], iteration=3)
    assert first.proposed_action == "analyze_case"
    assert second.proposed_action == "verify_outputs"
    assert exhausted.proposed_action == "stop"


def test_openclaw_provider_parses_injected_transport_decision():
    config = ModelProviderConfig(
        provider="openai_compatible",
        base_url="https://endpoint.example/v1",
        api_key="key",
        model_name="model",
    )
    captured: dict[str, str] = {}

    def fake_transport(cfg: ModelProviderConfig, prompt: str) -> str:
        captured["prompt"] = prompt
        assert cfg is config
        return (
            '{"phase":"verify","hypothesis":"check support",'
            '"proposed_action":"verify_outputs","action_args":{},'
            '"expected_signal":"passes","failure_or_gap_signal":"fails",'
            '"confidence":"medium","rationale":"bounded step",'
            '"observed_state_refs":["observation_000001"]}'
        )

    provider = OpenClawDecisionProvider(config, transport=fake_transport)
    decision = provider.propose(state=_run_state(), history=[], iteration=1)
    assert decision.proposed_action == "verify_outputs"
    assert decision.confidence == "medium"
    assert "allowed_actions" in captured["prompt"]


def test_openclaw_provider_rejects_non_json_response():
    config = ModelProviderConfig(
        provider="p", base_url="https://x/v1", api_key="k", model_name="m"
    )
    provider = OpenClawDecisionProvider(config, transport=lambda cfg, prompt: "not json")
    with pytest.raises(ValueError):
        provider.propose(state=_run_state(), history=[], iteration=1)


def test_load_model_provider_config_requires_non_placeholder_values():
    good = {
        "OPENAI_BASE_URL": "https://endpoint.example/v1",
        "OPENAI_API_KEY": "sk-real",
        "MODEL_NAME": "gpt-x",
    }
    config = load_model_provider_config(good)
    assert config.chat_completions_url() == "https://endpoint.example/v1/chat/completions"

    for placeholder in (
        {
            "OPENAI_BASE_URL": "https://your-endpoint.example.com/v1",
            "OPENAI_API_KEY": "k",
            "MODEL_NAME": "m",
        },
        {"OPENAI_BASE_URL": "https://x/v1", "OPENAI_API_KEY": "replace-me", "MODEL_NAME": "m"},
        {"OPENAI_BASE_URL": "https://x/v1", "OPENAI_API_KEY": "k"},
    ):
        with pytest.raises(ValueError):
            load_model_provider_config(placeholder)
