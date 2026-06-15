from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from elenchos.config.runtime import DEFAULT_TUI_INPUT_POLL_SECONDS

ELENCHOS_TUI_ASCII = "ELENCHOS_TUI_ASCII"
NO_COLOR = "NO_COLOR"
DUMB_TERM = "dumb"
INPUT_POLL_SECONDS = DEFAULT_TUI_INPUT_POLL_SECONDS
INPUT_TIMEOUT_MS = int(INPUT_POLL_SECONDS * 1000)

PAIR_MUTED = 1
PAIR_ACCENT = 2
PAIR_SUCCESS = 3
PAIR_WARNING = 4
PAIR_DANGER = 5

STYLE_DEFAULT = "default"
STYLE_HEADER = "header"
STYLE_FOOTER = "footer"
STYLE_MUTED = "muted"
STYLE_ACCENT = "accent"
STYLE_ACTIVE_BORDER = "active_border"
STYLE_INACTIVE_BORDER = "inactive_border"
STYLE_SUCCESS = "success"
STYLE_WARNING = "warning"
STYLE_DANGER = "danger"

POSITIVE_LABELS = {
    "ALLOWED",
    "COMPLETED",
    "PASS",
    "READY",
    "VALID",
}
WARNING_LABELS = {
    "BLOCKED",
    "EXITED",
    "INFERRED",
    "MIXED",
    "NEEDS_REVIEW",
    "OBSERVED",
    "PENDING",
    "REQUIRED",
    "RUNNING",
    "WATCH",
}
DANGER_LABELS = {
    "ERROR",
    "FAIL",
    "FAILED",
    "INVALID",
    "REJECTED",
}


@dataclass(frozen=True, slots=True)
class BorderChars:
    top_left: str
    top_right: str
    bottom_left: str
    bottom_right: str
    horizontal: str
    vertical: str
    tee_left: str
    tee_right: str
    tee_top: str
    tee_bottom: str
    cross: str


UNICODE_BORDERS = BorderChars(
    top_left="┌",
    top_right="┐",
    bottom_left="└",
    bottom_right="┘",
    horizontal="─",
    vertical="│",
    tee_left="├",
    tee_right="┤",
    tee_top="┬",
    tee_bottom="┴",
    cross="┼",
)
ASCII_BORDERS = BorderChars(
    top_left="+",
    top_right="+",
    bottom_left="+",
    bottom_right="+",
    horizontal="-",
    vertical="|",
    tee_left="+",
    tee_right="+",
    tee_top="+",
    tee_bottom="+",
    cross="+",
)


@dataclass(frozen=True, slots=True)
class TuiTheme:
    color_enabled: bool
    ascii_borders: bool
    borders: BorderChars
    attrs: Mapping[str, int]

    def attr(self, style: str) -> int:
        return self.attrs.get(style, self.attrs.get(STYLE_DEFAULT, 0))

    def badge_attr(self, label: str) -> int:
        normalized = normalize_label(label)
        if normalized in POSITIVE_LABELS:
            return self.attr(STYLE_SUCCESS)
        if normalized in DANGER_LABELS:
            return self.attr(STYLE_DANGER)
        if normalized in WARNING_LABELS:
            return self.attr(STYLE_WARNING)
        return self.attr(STYLE_MUTED)


def normalize_label(label: str | None) -> str:
    if not label:
        return "PENDING"
    return label.strip().replace("-", "_").replace(" ", "_").upper()


def wants_ascii_borders(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return env.get(ELENCHOS_TUI_ASCII, "").strip().lower() in {"1", "true", "yes", "on"}


def supports_color(
    *,
    has_colors: bool,
    environ: Mapping[str, str] | None = None,
) -> bool:
    env = os.environ if environ is None else environ
    if NO_COLOR in env:
        return False
    if env.get("TERM", "").strip().lower() == DUMB_TERM:
        return False
    return has_colors


def build_theme(
    *,
    color_enabled: bool,
    ascii_borders: bool,
    curses_module: Any | None = None,
) -> TuiTheme:
    cmod = curses_module
    bold = int(getattr(cmod, "A_BOLD", 0)) if cmod is not None else 0
    dim = int(getattr(cmod, "A_DIM", 0)) if cmod is not None else 0
    reverse = int(getattr(cmod, "A_REVERSE", 0)) if cmod is not None else 0

    def color_attr(pair: int) -> int:
        if not color_enabled or cmod is None:
            return 0
        return int(cmod.color_pair(pair))

    attrs = {
        STYLE_DEFAULT: 0,
        STYLE_HEADER: bold | color_attr(PAIR_ACCENT),
        STYLE_FOOTER: dim | color_attr(PAIR_MUTED),
        STYLE_MUTED: dim | color_attr(PAIR_MUTED),
        STYLE_ACCENT: bold | color_attr(PAIR_ACCENT),
        STYLE_ACTIVE_BORDER: bold | color_attr(PAIR_ACCENT),
        STYLE_INACTIVE_BORDER: dim | color_attr(PAIR_MUTED),
        STYLE_SUCCESS: bold | color_attr(PAIR_SUCCESS),
        STYLE_WARNING: bold | color_attr(PAIR_WARNING),
        STYLE_DANGER: bold | color_attr(PAIR_DANGER),
    }
    if not color_enabled:
        attrs[STYLE_HEADER] = bold
        attrs[STYLE_ACTIVE_BORDER] = bold
        attrs[STYLE_ACCENT] = bold
        attrs[STYLE_SUCCESS] = bold
        attrs[STYLE_WARNING] = reverse
        attrs[STYLE_DANGER] = reverse | bold
    return TuiTheme(
        color_enabled=color_enabled,
        ascii_borders=ascii_borders,
        borders=ASCII_BORDERS if ascii_borders else UNICODE_BORDERS,
        attrs=attrs,
    )


def init_curses_theme(curses_module: Any, environ: Mapping[str, str] | None = None) -> TuiTheme:
    has_colors = bool(curses_module.has_colors())
    color_enabled = supports_color(has_colors=has_colors, environ=environ)
    if color_enabled:
        curses_module.start_color()
        try:
            curses_module.use_default_colors()
            background = -1
        except Exception:
            background = curses_module.COLOR_BLACK
        curses_module.init_pair(PAIR_MUTED, curses_module.COLOR_WHITE, background)
        curses_module.init_pair(PAIR_ACCENT, curses_module.COLOR_CYAN, background)
        curses_module.init_pair(PAIR_SUCCESS, curses_module.COLOR_GREEN, background)
        curses_module.init_pair(PAIR_WARNING, curses_module.COLOR_YELLOW, background)
        curses_module.init_pair(PAIR_DANGER, curses_module.COLOR_RED, background)
    return build_theme(
        color_enabled=color_enabled,
        ascii_borders=wants_ascii_borders(environ),
        curses_module=curses_module,
    )


def badge_text(label: str, value: str) -> str:
    return f"{label} {normalize_label(value)}"
