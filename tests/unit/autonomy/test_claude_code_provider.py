from __future__ import annotations

import json
import subprocess

import pytest

from elenchos.autonomy.providers import ClaudeCodeDecisionProvider, CommandResult
from elenchos.config.runtime import ClaudeCodeConfig, load_claude_code_config
from elenchos.integrations.rationale_schema import RunStateSummary

DECISION = {
    "phase": "verify",
    "hypothesis": "check finding support",
    "proposed_action": "verify_outputs",
    "action_args": {},
    "expected_signal": "verification passes",
    "failure_or_gap_signal": "a finding lacks support",
    "confidence": "medium",
    "rationale": "bounded step",
    "observed_state_refs": ["observation_000001"],
}


def _state() -> RunStateSummary:
    return RunStateSummary(
        case_id="case_x",
        output_dir="runs/case_x/agent-run",
        agent_run_dir="runs/case_x/agent-run",
        required_outputs_present={"findings.json": True},
        finding_status_counts={},
        case_question_status_counts={},
        coverage_gap_count=0,
        self_correction_count=0,
        validation_status=None,
        active_job=None,
        recommended_next_actions=["verify_outputs"],
        allowed_actions=["verify_outputs", "stop"],
        claim_boundary_required=False,
        basis_files=["runs/case_x/agent-run"],
    )


def _provider(runner, config=None) -> ClaudeCodeDecisionProvider:
    return ClaudeCodeDecisionProvider(config or ClaudeCodeConfig(), runner=runner)


def _run(provider: ClaudeCodeDecisionProvider):
    return provider.propose(state=_state(), history=[], iteration=1)


def test_parses_direct_decision_json():
    captured: dict[str, list[str]] = {}

    def runner(argv, timeout):
        captured["argv"] = argv
        return CommandResult(0, json.dumps(DECISION), "")

    decision = _run(_provider(runner))
    assert decision.proposed_action == "verify_outputs"
    # Proposal-only argv: bare, print, json output, no tools.
    argv = captured["argv"]
    assert argv[:6] == ["claude", "--bare", "-p", argv[3], "--output-format", "json"]
    assert "--max-turns" in argv and "--tools" in argv


def test_parses_result_wrapper_json():
    wrapper = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": json.dumps(DECISION),
        "session_id": "abc",
    }

    def runner(argv, timeout):
        return CommandResult(0, json.dumps(wrapper), "")

    decision = _run(_provider(runner))
    assert decision.proposed_action == "verify_outputs"


def test_parses_structured_output_json():
    wrapper = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": None,
        "structured_output": DECISION,
    }

    def runner(argv, timeout):
        return CommandResult(0, json.dumps(wrapper), "")

    decision = _run(_provider(runner))
    assert decision.proposed_action == "verify_outputs"


def test_non_json_output_fails_closed():
    provider = _provider(lambda argv, timeout: CommandResult(0, "not json at all", ""))
    with pytest.raises(ValueError, match="not valid JSON"):
        _run(provider)


def test_error_result_wrapper_fails_closed():
    wrapper = {
        "type": "result",
        "subtype": "error_during_execution",
        "is_error": True,
        "result": None,
        "errors": ["boom"],
    }
    provider = _provider(lambda argv, timeout: CommandResult(0, json.dumps(wrapper), ""))
    with pytest.raises(ValueError, match="error result"):
        _run(provider)


def test_missing_decision_fields_fail_closed():
    wrapper = {"type": "result", "subtype": "success", "is_error": False, "result": "{}"}
    provider = _provider(lambda argv, timeout: CommandResult(0, json.dumps(wrapper), ""))
    with pytest.raises(ValueError):
        _run(provider)


def test_nonzero_exit_reports_actionable_error():
    provider = _provider(lambda argv, timeout: CommandResult(2, "", "auth failed"))
    with pytest.raises(ValueError, match="exited with status 2"):
        _run(provider)


def test_missing_binary_reports_env_hint():
    def runner(argv, timeout):
        raise FileNotFoundError(2, "No such file", "claude")

    with pytest.raises(ValueError, match="CLAUDE_CODE_BIN"):
        _run(_provider(runner))


def test_timeout_reports_clear_error():
    def runner(argv, timeout):
        raise subprocess.TimeoutExpired(cmd="claude", timeout=timeout)

    with pytest.raises(ValueError, match="timed out"):
        _run(_provider(runner))


def test_argv_includes_configured_model_mcp_and_allowed_tools():
    config = ClaudeCodeConfig(
        binary="claude",
        model="opus",
        mcp_config="/tmp/mcp.json",
        allowed_tools=("Read", "Grep"),
    )
    captured: dict[str, list[str]] = {}

    def runner(argv, timeout):
        captured["argv"] = argv
        return CommandResult(0, json.dumps(DECISION), "")

    _run(_provider(runner, config))
    argv = captured["argv"]
    assert "--model" in argv and argv[argv.index("--model") + 1] == "opus"
    assert "--mcp-config" in argv and argv[argv.index("--mcp-config") + 1] == "/tmp/mcp.json"
    assert "--allowed-tools" in argv and argv[argv.index("--allowed-tools") + 1] == "Read,Grep"
    # allowed tools set => no forced empty --tools
    assert "--tools" not in argv


def test_load_config_defaults_and_rejects_bad_values():
    default = load_claude_code_config({})
    assert default.binary == "claude"
    assert default.timeout_seconds == 120
    assert default.allowed_tools == ()

    configured = load_claude_code_config(
        {
            "CLAUDE_CODE_BIN": "/opt/claude",
            "CLAUDE_CODE_MODEL": "sonnet",
            "CLAUDE_CODE_TIMEOUT_SECONDS": "45",
            "CLAUDE_CODE_ALLOWED_TOOLS": "Read, Grep ,",
        }
    )
    assert configured.binary == "/opt/claude"
    assert configured.model == "sonnet"
    assert configured.timeout_seconds == 45
    assert configured.allowed_tools == ("Read", "Grep")

    with pytest.raises(ValueError):
        load_claude_code_config({"CLAUDE_CODE_BIN": "   "})
    with pytest.raises(ValueError):
        load_claude_code_config({"CLAUDE_CODE_TIMEOUT_SECONDS": "abc"})
    with pytest.raises(ValueError):
        load_claude_code_config({"CLAUDE_CODE_TIMEOUT_SECONDS": "0"})
