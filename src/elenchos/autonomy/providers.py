"""Decision providers for the autonomy loop.

Three implementations sit behind one :class:`DecisionProvider` protocol:

* :class:`ReplayDecisionProvider` -- deterministic, offline, replays a captured
  decision sequence. The CI/test/public-reproducibility driver; no model or network.
* :class:`ClaudeCodeDecisionProvider` -- the preferred live provider. Shells out to the
  Claude Code headless CLI (``claude --bare -p ... --output-format json``) and parses a
  single bounded decision back. The runner is injectable so parsing/validation is
  unit-tested; the live CLI path runs only where ``claude`` is installed/authenticated.
* :class:`OpenClawDecisionProvider` -- legacy openai-compatible client, retained for
  back-compat but no longer the preferred autonomy provider.

A provider may only *propose* a bounded action. Model output is never evidence; the
supervisor gates, executes, and verifies every proposal deterministically.
"""

from __future__ import annotations

import json
import subprocess
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

from elenchos.autonomy.decision import AutonomyDecision
from elenchos.config.runtime import (
    ClaudeCodeConfig,
    ModelProviderConfig,
    load_claude_code_config,
    load_model_provider_config,
)
from elenchos.integrations.rationale_schema import RunStateSummary
from elenchos.integrations.rationale_trace import iter_jsonl

_SYSTEM_PROMPT = (
    "You are a bounded DFIR triage supervisor for Elenchos. You may only PROPOSE one "
    "bounded action per step from the provided allowed_actions. You never inspect raw "
    "evidence, never run shell, never upgrade a finding's status, and never assert a "
    "confirmed conclusion; the deterministic engine owns all evidence and claims. "
    "Respond with a single JSON object with keys: hypothesis, proposed_action, "
    "action_args, expected_signal, failure_or_gap_signal, confidence "
    "(low|medium|high), rationale, observed_state_refs, phase."
)


@runtime_checkable
class DecisionProvider(Protocol):
    """Return the next bounded decision given the observed deterministic state."""

    name: str

    def propose(
        self,
        *,
        state: RunStateSummary,
        history: Sequence[AutonomyDecision],
        iteration: int,
    ) -> AutonomyDecision: ...


def build_decision_prompt(
    *,
    state: RunStateSummary,
    history: Sequence[AutonomyDecision],
    iteration: int,
) -> str:
    """Serialize the observed state + allowed actions for a live model provider."""

    return json.dumps(
        {
            "iteration": iteration,
            "allowed_actions": list(state.allowed_actions),
            "recommended_next_actions": list(state.recommended_next_actions),
            "observed_state": state.to_dict(),
            "prior_actions": [decision.proposed_action for decision in history],
            "instructions": _SYSTEM_PROMPT,
        },
        sort_keys=True,
    )


def _decision_from_payload(payload: object) -> AutonomyDecision:
    if not isinstance(payload, dict):
        raise ValueError("model decision must be a JSON object")
    return AutonomyDecision.from_dict(payload)


def _stop_decision(reason: str) -> AutonomyDecision:
    return AutonomyDecision(
        decision_id="decision_pending",
        timestamp_utc=None,  # type: ignore[arg-type]
        phase="finalize",
        hypothesis="The investigation has reached a terminal or exhausted state.",
        proposed_action="stop",
        action_args={},
        expected_signal="Run is finalized with a validated, traceable bundle.",
        failure_or_gap_signal="No further bounded action is available.",
        confidence="high",
        rationale=reason,
        observed_state_refs=[],
    )


class ReplayDecisionProvider:
    """Replays a captured decision sequence; deterministic and offline."""

    name = "replay"

    def __init__(self, decisions: Sequence[AutonomyDecision]):
        self._decisions = list(decisions)
        self._index = 0

    @classmethod
    def from_dicts(cls, rows: Sequence[dict[str, object]]) -> "ReplayDecisionProvider":
        return cls([AutonomyDecision.from_dict(dict(row)) for row in rows])

    @classmethod
    def from_jsonl(cls, path: Path) -> "ReplayDecisionProvider":
        return cls.from_dicts(iter_jsonl(path))

    def propose(
        self,
        *,
        state: RunStateSummary,
        history: Sequence[AutonomyDecision],
        iteration: int,
    ) -> AutonomyDecision:
        if self._index >= len(self._decisions):
            return _stop_decision("Replay decision sequence is exhausted.")
        decision = self._decisions[self._index]
        self._index += 1
        return decision


# -- Claude Code (preferred live provider) --------------------------------------


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


ClaudeCodeRunner = Callable[[list[str], "float | None"], CommandResult]
"""(argv, timeout_seconds) -> completed command result. Injectable for tests."""


def _subprocess_runner(argv: list[str], timeout: float | None) -> CommandResult:
    completed = subprocess.run(  # noqa: S603 - argv is fixed, shell=False, no user command string
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


class ClaudeCodeDecisionProvider:
    """Preferred live provider: Claude Code headless CLI proposes bounded decisions.

    Claude Code proposes; Elenchos policy/verifier executes, gates, and corrects. The
    default is proposal-only (``--tools ""``): the model has no tools and cannot act on
    evidence -- it only returns one decision object.
    """

    name = "claude-code"

    def __init__(
        self,
        config: ClaudeCodeConfig | None = None,
        *,
        runner: ClaudeCodeRunner = _subprocess_runner,
    ):
        self._config = config or load_claude_code_config()
        self._runner = runner

    def propose(
        self,
        *,
        state: RunStateSummary,
        history: Sequence[AutonomyDecision],
        iteration: int,
    ) -> AutonomyDecision:
        prompt = build_decision_prompt(state=state, history=history, iteration=iteration)
        argv = self._build_argv(prompt)
        try:
            result = self._runner(argv, float(self._config.timeout_seconds))
        except FileNotFoundError as exc:
            raise ValueError(
                f"Claude Code binary '{self._config.binary}' was not found; "
                "install Claude Code or set CLAUDE_CODE_BIN"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError(
                f"Claude Code timed out after {self._config.timeout_seconds}s"
            ) from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise ValueError(
                f"Claude Code exited with status {result.returncode}: {detail[:200]}"
            )
        return self._parse(result.stdout)

    def _build_argv(self, prompt: str) -> list[str]:
        argv = [
            self._config.binary,
            "--bare",
            "-p",
            prompt,
            "--output-format",
            "json",
            "--max-turns",
            "1",
            "--append-system-prompt",
            _SYSTEM_PROMPT,
        ]
        if self._config.model:
            argv += ["--model", self._config.model]
        if self._config.mcp_config:
            argv += ["--mcp-config", self._config.mcp_config]
        if self._config.allowed_tools:
            argv += ["--allowed-tools", ",".join(self._config.allowed_tools)]
        else:
            # Proposal-only: disable all built-in tools so the model cannot act.
            argv += ["--tools", ""]
        return argv

    def _parse(self, stdout: str) -> AutonomyDecision:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Claude Code output was not valid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise ValueError("Claude Code output must be a JSON object")

        # Direct decision object (no result-wrapper).
        if "proposed_action" in payload:
            return _decision_from_payload(payload)

        # Claude Code --output-format json result-wrapper.
        subtype = payload.get("subtype")
        if payload.get("is_error") is True or (subtype is not None and subtype != "success"):
            errors = payload.get("errors") or payload.get("result") or subtype
            raise ValueError(f"Claude Code returned an error result: {errors}")

        # --json-schema mode places the object in structured_output.
        structured = payload.get("structured_output")
        if isinstance(structured, dict) and "proposed_action" in structured:
            return _decision_from_payload(structured)

        result_text = payload.get("result")
        if not isinstance(result_text, str) or not result_text.strip():
            raise ValueError("Claude Code result contained no decision text")
        try:
            decision_payload = json.loads(result_text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Claude Code result was not a JSON decision object: {exc.msg}"
            ) from exc
        return _decision_from_payload(decision_payload)


# -- OpenClaw (legacy) ----------------------------------------------------------


ModelTransport = Callable[[ModelProviderConfig, str], str]
"""(config, prompt) -> raw model response text containing a JSON decision object."""


def _http_transport(config: ModelProviderConfig, prompt: str) -> str:
    """Default openai-compatible chat/completions transport (stdlib only, legacy)."""

    body = json.dumps(
        {
            "model": config.model_name,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url=config.chat_completions_url(),
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:  # noqa: S310
        payload = json.loads(response.read().decode("utf-8"))
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("model response contained no choices")
    message = choices[0].get("message", {})
    content = message.get("content")
    if not isinstance(content, str) or not content:
        raise ValueError("model response contained no message content")
    return content


class OpenClawDecisionProvider:
    """Legacy openai-compatible model provider (superseded by Claude Code)."""

    name = "openclaw"

    def __init__(
        self,
        config: ModelProviderConfig | None = None,
        *,
        transport: ModelTransport = _http_transport,
    ):
        self._config = config or load_model_provider_config()
        self._transport = transport

    def propose(
        self,
        *,
        state: RunStateSummary,
        history: Sequence[AutonomyDecision],
        iteration: int,
    ) -> AutonomyDecision:
        prompt = build_decision_prompt(state=state, history=history, iteration=iteration)
        raw = self._transport(self._config, prompt)
        return _decision_from_payload(json.loads(raw) if raw.strip() else {})
