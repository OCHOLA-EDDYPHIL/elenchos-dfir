from __future__ import annotations

from pathlib import Path

from elenchos.tui.layout import PANEL_ORDER, choose_layout
from elenchos.tui.rendering import (
    FocusState,
    build_panel_models,
    build_status_badges,
    focus_next,
    focus_previous,
    policy_status_label,
    render_panel_model,
    scroll_focused_panel,
    self_correction_status_label,
    set_focused_scroll,
    shorten_path,
    validation_status_label,
    wrap_panel_lines,
)
from elenchos.tui.state import ConsoleEvent, ConsoleState
from elenchos.tui.text import sanitize_display_text
from elenchos.tui.theme import (
    ASCII_BORDERS,
    ELENCHOS_TUI_ASCII,
    NO_COLOR,
    UNICODE_BORDERS,
    build_theme,
    supports_color,
    wants_ascii_borders,
)


def _state(
    tmp_path: Path,
    *,
    validation_status: str | None = "pending",
    job_status: str | None = None,
    finding_counts: dict[str, int] | None = None,
    policy_events: list[ConsoleEvent] | None = None,
    raw_policy_event_count: int = 0,
    self_correction_status: str = "none",
    self_correction_count: int = 0,
    latest_self_correction: str | None = None,
) -> ConsoleState:
    return ConsoleState(
        output_dir=tmp_path,
        run_dir=None,
        prompt="Triage this case.",
        job_status=job_status,
        returncode=None,
        validation_status=validation_status,
        finding_counts=finding_counts or {},
        case_question_counts={},
        normalized_events=None,
        rationale_events=[],
        policy_events=policy_events or [],
        raw_policy_event_count=raw_policy_event_count,
        progress_events=[],
        self_correction_count=self_correction_count,
        self_correction_status=self_correction_status,
        latest_self_correction=latest_self_correction,
        latest_corrected_claim_status=None,
        final_summary=None,
        claim_boundary="No unsupported conclusion is supported.",
        openclaw_log_tail=[],
        errors=[],
        required_outputs_present={},
    )


def test_theme_honors_no_color_and_dumb_terminal():
    assert (
        supports_color(has_colors=True, environ={NO_COLOR: "1", "TERM": "xterm-256color"})
        is False
    )
    assert supports_color(has_colors=True, environ={"TERM": "dumb"}) is False
    assert supports_color(has_colors=False, environ={"TERM": "xterm-256color"}) is False
    assert supports_color(has_colors=True, environ={"TERM": "xterm-256color"}) is True

    theme = build_theme(color_enabled=False, ascii_borders=False)

    assert theme.color_enabled is False
    assert theme.borders == UNICODE_BORDERS


def test_theme_ascii_fallback_border_selection():
    assert wants_ascii_borders({ELENCHOS_TUI_ASCII: "1"}) is True
    assert wants_ascii_borders({ELENCHOS_TUI_ASCII: "0"}) is False

    theme = build_theme(color_enabled=False, ascii_borders=True)

    assert theme.ascii_borders is True
    assert theme.borders == ASCII_BORDERS


def test_layout_selection_for_wide_and_narrow_terminals():
    wide = choose_layout(133, 22)
    narrow = choose_layout(100, 24)

    assert wide.is_wide is True
    assert narrow.is_wide is False
    assert wide.panel_ids() == PANEL_ORDER
    assert narrow.panel_ids() == PANEL_ORDER
    assert max(panel.rect.y + panel.rect.height for panel in wide.panels) <= wide.footer.y
    assert max(panel.rect.y + panel.rect.height for panel in narrow.panels) <= narrow.footer.y


def test_status_badge_text_for_core_states(tmp_path: Path):
    allowed = ConsoleEvent(None, "policy", "[policy] proposed run_case -> allowed")
    rejected = ConsoleEvent(None, "policy", "[policy] proposed shell -> rejected")
    state = _state(
        tmp_path,
        validation_status="pass",
        finding_counts={"confirmed": 1, "needs_review": 2},
        policy_events=[allowed],
        self_correction_status="observed",
        self_correction_count=1,
        latest_self_correction="Downgraded unsupported claim.",
    )

    badge_text = [badge.text for badge in build_status_badges(state, openclaw_status="running")]

    assert "OpenClaw RUNNING" in badge_text
    assert "Validation PASS" in badge_text
    assert "Policy ALLOWED" in badge_text
    assert "Self-correction OBSERVED" in badge_text
    assert "Findings C1/NR2" in badge_text
    assert validation_status_label("failed") == "FAIL"
    assert self_correction_status_label("required") == "REQUIRED"
    assert policy_status_label([allowed, rejected]) == "MIXED"


def test_focused_panel_changes_and_scroll_helpers():
    focus = FocusState(panel_ids=("prompt", "policy", "final"), focused_panel_id="prompt")

    assert focus_next(focus) == "policy"
    assert scroll_focused_panel(focus, 3) == 3
    assert scroll_focused_panel(focus, -1) == 2
    assert set_focused_scroll(focus, 0) == 0
    assert focus_previous(focus) == "prompt"


def test_policy_panel_keeps_raw_event_count_visible(tmp_path: Path):
    events = [
        ConsoleEvent(None, "policy", "[policy] proposed inspect_run_state -> allowed"),
    ]
    state = _state(tmp_path, policy_events=events, raw_policy_event_count=4)

    policy_panel = next(
        panel
        for panel in build_panel_models(state, watch_only=True)
        if panel.panel_id == "policy"
    )

    assert "raw policy events: 4" in policy_panel.lines


def test_empty_panels_show_intentional_waiting_copy(tmp_path: Path):
    state = _state(tmp_path, self_correction_status="pending")
    panels = {
        panel.panel_id: panel
        for panel in build_panel_models(state, watch_only=True)
    }

    assert panels["rationale"].lines == [
        "waiting for OpenClaw/Elenchos rationale events..."
    ]
    assert panels["policy"].lines == [
        "waiting for policy decisions...",
        "raw policy events: 0",
    ]
    assert "findings: none yet" in panels["run_status"].lines
    assert "PENDING: waiting for self-correction artifact check..." in panels[
        "self_correction"
    ].lines


def test_self_correction_panel_reflects_generated_artifact_state(tmp_path: Path):
    state = _state(
        tmp_path,
        self_correction_status="observed",
        self_correction_count=2,
        latest_self_correction="Rejected unsupported claim path.",
    )

    panel = next(
        panel
        for panel in build_panel_models(state, watch_only=True)
        if panel.panel_id == "self_correction"
    )

    assert panel.lines == ["OBSERVED: 2 event(s); latest: Rejected unsupported claim path."]


def test_shorten_path_preserves_leaf_name():
    path = "/tmp/elenchos/runs/rocba-standard-20260615-120000"

    shortened = shorten_path(path, 40)

    assert shortened.startswith("...")
    assert shortened.endswith("rocba-standard-20260615-120000")


def test_sanitize_display_text_removes_actual_ansi_sgr_sequences():
    raw = "\x1b[35m[plugins]\x1b[39m \x1b[33mplugins.allow is empty\x1b[39m"

    assert sanitize_display_text(raw) == "[plugins] plugins.allow is empty"


def test_sanitize_display_text_removes_caret_rendered_sgr_sequences():
    raw = "^[[35m[plugins]^[[39m ^[[33mplugins.allow is empty^[[39m"

    assert sanitize_display_text(raw) == "[plugins] plugins.allow is empty"


def test_sanitize_display_text_preserves_normal_log_text_and_forensic_identifiers():
    raw = (
        "[warning] case_id=rocba-standard finding_id=finding-001 "
        "path=/mnt/evidence/rocba/Users/Alice/NTUSER.DAT"
    )

    assert sanitize_display_text(raw) == raw


def test_wrap_panel_lines_measures_width_after_sanitization():
    raw = "\x1b[35m[plugins]\x1b[39m \x1b[33mplugins.allow is empty\x1b[39m"

    wrapped = wrap_panel_lines([raw], width=30)

    assert "\x1b" not in "\n".join(wrapped)
    assert wrapped == ["[plugins] plugins.allow is", "empty"]
    assert all(len(line) <= 30 for line in wrapped)


def test_prompt_panel_wraps_output_path_and_reports_overflow(tmp_path: Path):
    state = _state(
        tmp_path
        / "runs"
        / "rocba-standard-20260615-120000-with-a-long-generated-output-directory"
    )
    panel = next(
        panel
        for panel in build_panel_models(state, watch_only=True)
        if panel.panel_id == "prompt"
    )

    window = render_panel_model(
        panel,
        content_width=34,
        content_height=2,
        scroll_offset=0,
    )
    visible = "\n".join(window.lines)

    assert "Triage this case." in visible
    assert window.hidden_after > 0
    assert window.lines[-1].startswith("... ")
