from __future__ import annotations

import re

ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CARET_CSI_RE = re.compile(r"\^\[\[[0-?]*[ -/]*[@-~]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize_display_text(value: str) -> str:
    """Remove terminal control sequences from TUI display text only."""
    sanitized = ANSI_CSI_RE.sub("", value)
    sanitized = CARET_CSI_RE.sub("", sanitized)
    return CONTROL_RE.sub("", sanitized)
