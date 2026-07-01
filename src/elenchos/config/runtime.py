from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_PREPARE_CASE_TIMEOUT_SECONDS: int | None = None
DEFAULT_PARSER_TIMEOUT_SECONDS = 900
DEFAULT_TUI_REFRESH_SECONDS = 1.0
DEFAULT_TUI_INPUT_POLL_SECONDS = 0.02
MIN_TUI_REFRESH_SECONDS = 0.1

ELENCHOS_PREPARE_TIMEOUT_SECONDS = "ELENCHOS_PREPARE_TIMEOUT_SECONDS"
_NO_TIMEOUT_VALUES = {"0", "none", "off", "disabled"}

MODEL_PROVIDER_ENV = "MODEL_PROVIDER"
OPENAI_BASE_URL_ENV = "OPENAI_BASE_URL"
OPENAI_API_KEY_ENV = "OPENAI_API_KEY"
MODEL_NAME_ENV = "MODEL_NAME"
DEFAULT_MODEL_PROVIDER = "openai_compatible"
DEFAULT_MODEL_TIMEOUT_SECONDS = 120
# Values shipped in .env.example that must never be used as a live configuration.
_PLACEHOLDER_VALUES = {
    "replace-me",
    "https://your-endpoint.example.com/v1",
    "",
}


@dataclass(frozen=True, slots=True)
class ModelProviderConfig:
    """Resolved model-provider settings for the live OpenClaw decision provider."""

    provider: str
    base_url: str
    api_key: str
    model_name: str
    timeout_seconds: int = DEFAULT_MODEL_TIMEOUT_SECONDS

    def chat_completions_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/chat/completions"


def _require_configured(name: str, value: str | None) -> str:
    if value is None or value.strip().casefold() in _PLACEHOLDER_VALUES:
        raise ValueError(
            f"{name} is not configured; set it in the environment (see .env.example) "
            "before using the live OpenClaw provider"
        )
    return value.strip()


CLAUDE_CODE_BIN_ENV = "CLAUDE_CODE_BIN"
CLAUDE_CODE_MODEL_ENV = "CLAUDE_CODE_MODEL"
CLAUDE_CODE_TIMEOUT_ENV = "CLAUDE_CODE_TIMEOUT_SECONDS"
CLAUDE_CODE_MCP_CONFIG_ENV = "CLAUDE_CODE_MCP_CONFIG"
CLAUDE_CODE_ALLOWED_TOOLS_ENV = "CLAUDE_CODE_ALLOWED_TOOLS"
DEFAULT_CLAUDE_CODE_BIN = "claude"
DEFAULT_CLAUDE_CODE_TIMEOUT_SECONDS = 120


@dataclass(frozen=True, slots=True)
class ClaudeCodeConfig:
    """Resolved Claude Code headless-CLI settings for the live decision provider."""

    binary: str = DEFAULT_CLAUDE_CODE_BIN
    model: str | None = None
    timeout_seconds: int = DEFAULT_CLAUDE_CODE_TIMEOUT_SECONDS
    mcp_config: str | None = None
    # Empty = proposal-only mode (Elenchos executes/gates all actions; the model
    # only proposes). Non-empty auto-approves the listed Claude Code tools.
    allowed_tools: tuple[str, ...] = ()


def _parse_positive_int(name: str, value: str) -> int:
    try:
        parsed = int(value.strip(), 10)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


def _optional_stripped(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped.casefold() in _PLACEHOLDER_VALUES:
        return None
    return stripped


def load_claude_code_config(
    environ: Mapping[str, str] | None = None,
) -> ClaudeCodeConfig:
    """Read Claude Code CLI configuration from the environment.

    Fails closed (``ValueError``) on an empty binary name or an invalid timeout so a
    live run errors clearly rather than shelling out to a broken command. The Replay
    provider needs none of this. Auth is handled by Claude Code itself
    (``ANTHROPIC_API_KEY`` / Foundry / Bedrock / Vertex), not by Elenchos.
    """

    env = os.environ if environ is None else environ
    binary = (env.get(CLAUDE_CODE_BIN_ENV) or DEFAULT_CLAUDE_CODE_BIN).strip()
    if not binary:
        raise ValueError(f"{CLAUDE_CODE_BIN_ENV} must not be empty")
    raw_timeout = env.get(CLAUDE_CODE_TIMEOUT_ENV)
    timeout_seconds = (
        DEFAULT_CLAUDE_CODE_TIMEOUT_SECONDS
        if raw_timeout is None or not raw_timeout.strip()
        else _parse_positive_int(CLAUDE_CODE_TIMEOUT_ENV, raw_timeout)
    )
    allowed_raw = env.get(CLAUDE_CODE_ALLOWED_TOOLS_ENV) or ""
    allowed_tools = tuple(
        tool.strip() for tool in allowed_raw.split(",") if tool.strip()
    )
    return ClaudeCodeConfig(
        binary=binary,
        model=_optional_stripped(env.get(CLAUDE_CODE_MODEL_ENV)),
        timeout_seconds=timeout_seconds,
        mcp_config=_optional_stripped(env.get(CLAUDE_CODE_MCP_CONFIG_ENV)),
        allowed_tools=allowed_tools,
    )


def load_model_provider_config(
    environ: Mapping[str, str] | None = None,
    *,
    timeout_seconds: int = DEFAULT_MODEL_TIMEOUT_SECONDS,
) -> ModelProviderConfig:
    """Read the model-provider configuration from the environment.

    Raises ``ValueError`` with an actionable message when the endpoint, key, or model
    is still at its ``.env.example`` placeholder -- so a live run fails fast and clearly
    rather than issuing a broken request. The Replay provider needs none of this.
    """

    env = os.environ if environ is None else environ
    provider = (env.get(MODEL_PROVIDER_ENV) or DEFAULT_MODEL_PROVIDER).strip()
    base_url = _require_configured(OPENAI_BASE_URL_ENV, env.get(OPENAI_BASE_URL_ENV))
    api_key = _require_configured(OPENAI_API_KEY_ENV, env.get(OPENAI_API_KEY_ENV))
    model_name = _require_configured(MODEL_NAME_ENV, env.get(MODEL_NAME_ENV))
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    return ModelProviderConfig(
        provider=provider,
        base_url=base_url,
        api_key=api_key,
        model_name=model_name,
        timeout_seconds=timeout_seconds,
    )


def get_prepare_case_timeout_seconds(
    explicit: int | None = None,
    environ: Mapping[str, str] | None = None,
) -> int | None:
    if explicit is not None:
        return _coerce_timeout(explicit, source="timeout_seconds")

    env = os.environ if environ is None else environ
    raw = env.get(ELENCHOS_PREPARE_TIMEOUT_SECONDS)
    if raw is None or raw.strip() == "":
        return DEFAULT_PREPARE_CASE_TIMEOUT_SECONDS
    return _coerce_timeout(raw, source=ELENCHOS_PREPARE_TIMEOUT_SECONDS)


def _coerce_timeout(value: int | str, *, source: str) -> int | None:
    if isinstance(value, bool):
        raise ValueError(f"{source} must be a positive integer or no-timeout marker")
    if isinstance(value, int):
        if value == 0:
            return None
        if value < 0:
            raise ValueError(f"{source} must not be negative")
        return value

    normalized = value.strip().casefold()
    if normalized in _NO_TIMEOUT_VALUES:
        return None
    try:
        parsed = int(normalized, 10)
    except ValueError as exc:
        raise ValueError(
            f"{source} must be a positive integer or one of: "
            f"{', '.join(sorted(_NO_TIMEOUT_VALUES))}"
        ) from exc
    return _coerce_timeout(parsed, source=source)
