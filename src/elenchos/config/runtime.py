from __future__ import annotations

import os
from collections.abc import Mapping

DEFAULT_PREPARE_CASE_TIMEOUT_SECONDS: int | None = None
DEFAULT_PARSER_TIMEOUT_SECONDS = 900
DEFAULT_TUI_REFRESH_SECONDS = 1.0
DEFAULT_TUI_INPUT_POLL_SECONDS = 0.02
MIN_TUI_REFRESH_SECONDS = 0.1

ELENCHOS_PREPARE_TIMEOUT_SECONDS = "ELENCHOS_PREPARE_TIMEOUT_SECONDS"
_NO_TIMEOUT_VALUES = {"0", "none", "off", "disabled"}


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
