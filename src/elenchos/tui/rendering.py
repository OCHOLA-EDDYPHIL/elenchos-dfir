from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from elenchos.tui.layout import (
    FINAL_PANEL,
    PANEL_ORDER,
    POLICY_PANEL,
    PROMPT_PANEL,
    RATIONALE_PANEL,
    RUN_STATUS_PANEL,
    SELF_CORRECTION_PANEL,
    ScreenLayout,
)
from elenchos.tui.state import ConsoleEvent, ConsoleState
from elenchos.tui.text import sanitize_display_text
from elenchos.tui.theme import badge_text, normalize_label

PAGE_SCROLL_LINES = 8
END_SCROLL_SENTINEL = 10_000


@dataclass(frozen=True, slots=True)
class Badge:
    label: str
    value: str
    text: str


@dataclass(slots=True)
class PanelWindow:
    lines: list[str]
    hidden_before: int
    hidden_after: int


@dataclass(frozen=True, slots=True)
class PanelModel:
    panel_id: str
    title: str
    lines: list[str]


@dataclass(frozen=True, slots=True)
class TuiModel:
    header: str
    header_badges: tuple[Badge, ...]
    output_path: str
    panels: tuple[PanelModel, ...]
    footer: str


@dataclass(slots=True)
class FocusState:
    panel_ids: tuple[str, ...] = PANEL_ORDER
    focused_panel_id: str = PROMPT_PANEL
    scroll_offsets: dict[str, int] = field(default_factory=dict)

    def offset(self, panel_id: str) -> int:
        return max(0, self.scroll_offsets.get(panel_id, 0))


def sync_focus_state(focus: FocusState, layout: ScreenLayout) -> FocusState:
    panel_ids = layout.panel_ids()
    if focus.focused_panel_id not in panel_ids:
        focus.focused_panel_id = panel_ids[0] if panel_ids else PROMPT_PANEL
    focus.panel_ids = panel_ids
    focus.scroll_offsets = {
        panel_id: offset
        for panel_id, offset in focus.scroll_offsets.items()
        if panel_id in panel_ids
    }
    return focus


def focus_next(focus: FocusState) -> str:
    return _focus_delta(focus, 1)


def focus_previous(focus: FocusState) -> str:
    return _focus_delta(focus, -1)


def _focus_delta(focus: FocusState, delta: int) -> str:
    if not focus.panel_ids:
        focus.focused_panel_id = PROMPT_PANEL
        return focus.focused_panel_id
    current = focus.panel_ids.index(focus.focused_panel_id)
    focus.focused_panel_id = focus.panel_ids[(current + delta) % len(focus.panel_ids)]
    return focus.focused_panel_id


def scroll_focused_panel(focus: FocusState, delta: int) -> int:
    panel_id = focus.focused_panel_id
    offset = max(0, focus.offset(panel_id) + delta)
    focus.scroll_offsets[panel_id] = offset
    return offset


def set_focused_scroll(focus: FocusState, offset: int) -> int:
    panel_id = focus.focused_panel_id
    focus.scroll_offsets[panel_id] = max(0, offset)
    return focus.scroll_offsets[panel_id]


def wrap_panel_lines(lines: list[str], width: int) -> list[str]:
    wrapped: list[str] = []
    safe_width = max(10, width)
    for raw_line in lines:
        split_lines = sanitize_display_text(raw_line).splitlines() or [""]
        for line in split_lines:
            wrapped.extend(_wrap_single_panel_line(line, safe_width))
    return wrapped


def _wrap_single_panel_line(line: str, safe_width: int) -> list[str]:
    if not line:
        return [""]
    indent = len(line) - len(line.lstrip(" "))
    subsequent_indent = " " * min(indent, max(0, safe_width - 1))
    return (
        textwrap.wrap(
            line,
            width=safe_width,
            replace_whitespace=False,
            drop_whitespace=True,
            break_long_words=True,
            break_on_hyphens=False,
            subsequent_indent=subsequent_indent,
        )
        or [""]
    )


def visible_panel_lines(
    lines: list[str],
    height: int,
    *,
    scroll_offset: int = 0,
) -> PanelWindow:
    if height <= 0:
        return PanelWindow([], 0, len(lines))
    if len(lines) <= height:
        return PanelWindow(lines, 0, 0)
    max_offset = max(0, len(lines) - height)
    offset = min(max(scroll_offset, 0), max_offset)
    hidden_before = offset
    hidden_after = max(0, len(lines) - offset - height)
    visible = list(lines[offset : offset + height])
    if hidden_before and visible:
        visible[0] = f"... {hidden_before} earlier lines. Home/PgUp/Up"
    if hidden_after and visible:
        visible[-1] = f"... {hidden_after} more lines. Down/PgDn/End"
    return PanelWindow(visible, hidden_before, hidden_after)


def shorten_path(path: Path | str, max_width: int) -> str:
    text = str(path)
    if max_width <= 0:
        return ""
    if len(text) <= max_width:
        return text
    if max_width <= 3:
        return "." * max_width
    parts = Path(text).parts
    if len(parts) >= 2:
        candidate = f".../{parts[-2]}/{parts[-1]}"
        if len(candidate) <= max_width:
            return candidate
        candidate = f".../{parts[-1]}"
        if len(candidate) <= max_width:
            return candidate
    return "..." + text[-(max_width - 3) :]


def build_tui_model(
    state: ConsoleState,
    *,
    openclaw_status: str,
    watch_only: bool,
    width: int,
) -> TuiModel:
    badges = build_status_badges(state, openclaw_status=openclaw_status)
    path_width = max(10, width - 16 - sum(len(badge.text) + 3 for badge in badges))
    output_path = shorten_path(state.output_dir, path_width)
    return TuiModel(
        header="Elenchos",
        header_badges=badges,
        output_path=output_path,
        panels=build_panel_models(state, watch_only=watch_only),
        footer=(
            "Tab/Shift-Tab focus | arrows/k/j scroll | PgUp/PgDn | Home/End | "
            "r refresh | q quit"
        ),
    )


def build_panel_models(state: ConsoleState, *, watch_only: bool) -> tuple[PanelModel, ...]:
    output_state = ", ".join(
        f"{name}={'yes' if present else 'no'}"
        for name, present in sorted(state.required_outputs_present.items())
    )
    prompt = state.prompt or "Watch-only mode. No prompt will be launched."
    return (
        PanelModel(
            PROMPT_PANEL,
            "Prompt",
            [
                prompt,
                f"Output: {state.output_dir}",
            ],
        ),
        PanelModel(
            RATIONALE_PANEL,
            "Rationale History" if state.validation_status == "pass" else "Live Rationale",
            _event_lines(
                state.rationale_events,
                limit=8,
                empty_message="waiting for OpenClaw/Elenchos rationale events...",
            ),
        ),
        PanelModel(
            POLICY_PANEL,
            "Policy Gate",
            [
                *_event_lines(
                    state.policy_events,
                    limit=8,
                    empty_message="waiting for policy decisions...",
                ),
                f"raw policy events: {state.raw_policy_event_count}",
            ],
        ),
        PanelModel(
            SELF_CORRECTION_PANEL,
            "Self-Correction",
            [_self_correction_line(state)],
        ),
        PanelModel(
            RUN_STATUS_PANEL,
            "Run Status",
            [
                f"job: {(state.job_status or 'pending').upper()}",
                f"return code: {state.returncode if state.returncode is not None else 'pending'}",
                f"validation: {validation_status_label(state.validation_status)}",
                f"findings: {_format_counts(state.finding_counts) or 'none yet'}",
                f"case questions: {_format_counts(state.case_question_counts) or 'none yet'}",
                "normalized events: "
                f"{state.normalized_events if state.normalized_events is not None else 'pending'}",
                f"finalized: {'yes' if state.finalized else 'no'}",
                f"required outputs: {output_state or 'pending'}",
                "",
                *_event_lines(
                    state.progress_events,
                    limit=8,
                    empty_message="waiting for run progress events...",
                ),
            ],
        ),
        PanelModel(
            FINAL_PANEL,
            "Summary / Claim Boundary / Log",
            _final_panel_lines(state),
        ),
    )


def render_panel_model(
    panel: PanelModel,
    *,
    content_width: int,
    content_height: int,
    scroll_offset: int,
) -> PanelWindow:
    wrapped = wrap_panel_lines(panel.lines, content_width)
    return visible_panel_lines(wrapped, content_height, scroll_offset=scroll_offset)


def build_status_badges(state: ConsoleState, *, openclaw_status: str) -> tuple[Badge, ...]:
    badges = [
        _badge("OpenClaw", openclaw_status_label(openclaw_status)),
        _badge("Validation", validation_status_label(state.validation_status)),
        _badge("Policy", policy_status_label(state.policy_events)),
        _badge("Self-correction", self_correction_status_label(state.self_correction_status)),
    ]
    finding_text = findings_status_label(state.finding_counts)
    if finding_text:
        badges.append(_badge("Findings", finding_text))
    return tuple(badges)


def _badge(label: str, value: str) -> Badge:
    normalized = normalize_label(value)
    return Badge(label=label, value=normalized, text=badge_text(label, normalized))


def openclaw_status_label(status: str) -> str:
    lower = status.lower()
    if "done" in lower or "finalized" in lower:
        return "DONE"
    if "blocked" in lower:
        return "BLOCKED"
    if "failed" in lower or "rc=1" in lower or "rc=2" in lower:
        return "FAILED"
    if "running" in lower:
        return "RUNNING"
    if "exited" in lower:
        return "EXITED"
    if "watch" in lower:
        return "WATCH"
    return "READY"


def validation_status_label(status: str | None) -> str:
    if status is None:
        return "PENDING"
    lower = status.lower()
    if lower in {"pass", "passed", "completed", "valid"}:
        return "PASS"
    if lower in {"fail", "failed", "invalid", "rejected"}:
        return "FAIL"
    if lower in {"pending", "not_assessed", "not-assessed"}:
        return "PENDING"
    return normalize_label(status)


def policy_status_label(events: list[ConsoleEvent]) -> str:
    if not events:
        return "PENDING"
    messages = [event.message.lower() for event in events]
    has_allowed = any("allowed" in message for message in messages)
    has_rejected = any("rejected" in message for message in messages)
    if has_allowed and has_rejected:
        return "MIXED"
    if has_rejected:
        return "REJECTED"
    if has_allowed:
        return "ALLOWED"
    return "PENDING"


def self_correction_status_label(status: str | None) -> str:
    normalized = normalize_label(status)
    if normalized == "OBSERVED":
        return "OBSERVED"
    if normalized == "REQUIRED":
        return "REQUIRED"
    if normalized == "PENDING":
        return "PENDING"
    return "NONE"


def findings_status_label(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    compact_names = {
        "confirmed": "C",
        "inferred": "I",
        "needs_review": "NR",
        "not_assessed": "NA",
        "rejected": "R",
    }
    return "/".join(
        f"{compact_names.get(key, key.upper())}{value}"
        for key, value in sorted(counts.items())
    )


def _event_lines(
    events: list[ConsoleEvent],
    *,
    limit: int,
    empty_message: str,
) -> list[str]:
    if not events:
        return [empty_message]
    return [event.display_message for event in events[-limit:]]


def _self_correction_line(state: ConsoleState) -> str:
    if not state.self_correction_count:
        if self_correction_status_label(state.self_correction_status) == "PENDING":
            return "PENDING: waiting for self-correction artifact check..."
        return "NONE: no self-correction artifact events observed."
    suffix = (
        f"; corrected status: {state.latest_corrected_claim_status}"
        if state.latest_corrected_claim_status
        else ""
    )
    return (
        f"OBSERVED: {state.self_correction_count} event(s); "
        f"latest: {state.latest_self_correction or 'not summarized'}{suffix}"
    )


def _final_panel_lines(state: ConsoleState) -> list[str]:
    lines = [
        state.final_summary or "Pending generated Elenchos summary.",
        "",
        f"Claim boundary: {state.claim_boundary}",
    ]
    if state.errors:
        lines.extend(["", "Warnings / failures"])
        lines.extend(state.errors[-8:])
    if state.openclaw_log_tail:
        lines.extend(["", "OpenClaw log tail"])
        lines.extend(state.openclaw_log_tail)
    return lines


def state_body_lines(state: ConsoleState, *, watch_only: bool) -> list[str]:
    lines: list[str] = []
    for panel in build_panel_models(state, watch_only=watch_only):
        lines.extend([panel.title, *panel.lines, ""])
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
