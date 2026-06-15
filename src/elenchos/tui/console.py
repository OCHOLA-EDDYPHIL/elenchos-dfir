from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elenchos.config.runtime import (
    DEFAULT_TUI_REFRESH_SECONDS,
    MIN_TUI_REFRESH_SECONDS,
)
from elenchos.policy.paths import (
    MOUNTED_EVIDENCE_ROOT,
    is_generated_output_path,
    is_relative_to,
)
from elenchos.tui.layout import Rect, choose_layout
from elenchos.tui.rendering import (
    END_SCROLL_SENTINEL,
    PAGE_SCROLL_LINES,
    FocusState,
    PanelModel,
    build_tui_model,
    focus_next,
    focus_previous,
    openclaw_status_label,
    render_panel_model,
    scroll_focused_panel,
    self_correction_status_label,
    set_focused_scroll,
    state_body_lines,
    sync_focus_state,
    validation_status_label,
    visible_panel_lines,
    wrap_panel_lines,
)
from elenchos.tui.runner import (
    DEFAULT_AGENT,
    OPENCLAW_LOG_FILENAME,
    ActiveRunError,
    build_wrapped_prompt,
    complete_active_run,
    ensure_no_active_run,
    launch_openclaw,
    plan_output_dir,
    write_active_run_lock,
    write_run_context,
)
from elenchos.tui.state import (
    ConsoleState,
    read_console_state,
    render_text_snapshot,
)
from elenchos.tui.theme import (
    INPUT_TIMEOUT_MS,
    STYLE_ACCENT,
    STYLE_ACTIVE_BORDER,
    STYLE_FOOTER,
    STYLE_HEADER,
    STYLE_INACTIVE_BORDER,
    STYLE_MUTED,
    TuiTheme,
    init_curses_theme,
)

__all__ = [
    "INPUT_TIMEOUT_MS",
    "PromptInputBuffer",
    "RefreshClock",
    "openclaw_status_label",
    "self_correction_status_label",
    "validation_status_label",
    "visible_panel_lines",
    "wrap_panel_lines",
]

TERMINAL_JOB_STATUSES = {
    "completed",
    "completed_unknown_exit",
    "failed",
    "rejected",
    "not_found",
}
TRANSCRIPT_FILENAME = "case_console_transcript.md"
MIN_REFRESH_SECONDS = MIN_TUI_REFRESH_SECONDS
KEY_CTRL_C = 3
KEY_ENTER = 10
KEY_CARRIAGE_RETURN = 13
KEY_BACKSPACE_VALUES = (127, 8)
KEY_TAB = 9


@dataclass(slots=True)
class PromptKeyResult:
    submitted_prompt: str | None = None
    should_quit: bool = False
    exit_code: int | None = None
    changed: bool = False


class PromptInputBuffer:
    def __init__(self) -> None:
        self.text = ""

    def handle_key(self, key: int, *, backspace_keys: tuple[int, ...]) -> PromptKeyResult:
        if key == -1:
            return PromptKeyResult()
        if key == KEY_CTRL_C:
            return PromptKeyResult(should_quit=True, exit_code=130)
        if key in (KEY_ENTER, KEY_CARRIAGE_RETURN):
            prompt = self.text.strip()
            if prompt:
                return PromptKeyResult(submitted_prompt=prompt)
            return PromptKeyResult()
        if key in (ord("q"), ord("Q")) and not self.text:
            return PromptKeyResult(should_quit=True, exit_code=0)
        if key in backspace_keys:
            if not self.text:
                return PromptKeyResult()
            self.text = self.text[:-1]
            return PromptKeyResult(changed=True)
        if 32 <= key <= 126:
            self.text += chr(key)
            return PromptKeyResult(changed=True)
        return PromptKeyResult()


@dataclass(slots=True)
class RefreshClock:
    interval_seconds: float
    next_refresh_at: float = 0.0

    def __post_init__(self) -> None:
        self.interval_seconds = max(self.interval_seconds, MIN_REFRESH_SECONDS)

    def should_refresh(self, now: float, *, forced: bool = False) -> bool:
        return forced or now >= self.next_refresh_at

    def mark_refreshed(self, now: float) -> None:
        self.next_refresh_at = now + self.interval_seconds


def run_tui(
    *,
    source_root: str | None,
    case_id: str | None,
    output_dir: Path | None,
    runs_root: Path = Path("runs"),
    agent: str = DEFAULT_AGENT,
    prompt: str | None = None,
    prompt_file: Path | None = None,
    watch_only: bool = False,
    refresh_seconds: float = DEFAULT_TUI_REFRESH_SECONDS,
    once: bool = False,
) -> int:
    try:
        analyst_prompt = _resolve_analyst_prompt(
            prompt=prompt,
            prompt_file=prompt_file,
            watch_only=watch_only,
        )
        resolved_output_dir = _resolve_initial_output_dir(
            output_dir=output_dir,
            case_id=case_id,
            runs_root=runs_root,
            watch_only=watch_only,
        )
    except ValueError as exc:
        print(f"error={exc}")
        return 2

    if once:
        if not watch_only:
            print("error=--once is supported only with --watch-only")
            return 2
        if resolved_output_dir is None:
            print("error=output_dir is required with --watch-only")
            return 2
        state = read_console_state(resolved_output_dir, prompt=analyst_prompt)
        _mirror_visible_transcript(resolved_output_dir, state)
        print(render_text_snapshot(state), end="")
        return 0

    try:
        import curses
    except ImportError as exc:
        print(f"error=curses is unavailable: {exc}")
        return 2

    def _wrapped(stdscr: Any) -> int:
        return _run_curses(
            stdscr=stdscr,
            output_dir=resolved_output_dir,
            agent=agent,
            analyst_prompt=analyst_prompt,
            case_id=case_id,
            runs_root=runs_root,
            source_root=source_root,
            watch_only=watch_only,
            refresh_seconds=refresh_seconds,
        )

    try:
        result = curses.wrapper(_wrapped)
    except KeyboardInterrupt:
        result = 130
    print(f"output_dir={resolved_output_dir}")
    return int(result)


def _resolve_initial_output_dir(
    *,
    output_dir: Path | None,
    case_id: str | None,
    runs_root: Path,
    watch_only: bool,
) -> Path | None:
    if watch_only:
        if output_dir is None:
            raise ValueError("output_dir is required with --watch-only")
        resolved = output_dir.expanduser().resolve()
        if is_relative_to(resolved, MOUNTED_EVIDENCE_ROOT):
            raise ValueError("output_dir must not be under /mnt/evidence")
        return resolved
    if output_dir is None:
        resolved = plan_output_dir(case_id, runs_root=runs_root)
        _require_generated_output_dir(resolved)
        return resolved
    resolved = output_dir.expanduser().resolve()
    if is_relative_to(resolved, MOUNTED_EVIDENCE_ROOT):
        raise ValueError("output_dir must not be under /mnt/evidence")
    _require_generated_output_dir(resolved)
    return resolved


def _require_generated_output_dir(path: Path) -> None:
    if not is_generated_output_path(path):
        raise ValueError("output_dir must be under a generated output root such as runs/")


def _resolve_analyst_prompt(
    *,
    prompt: str | None,
    prompt_file: Path | None,
    watch_only: bool,
) -> str | None:
    if prompt_file is not None and prompt is not None:
        raise ValueError("use either --prompt or --prompt-file, not both")
    if prompt_file is not None:
        return prompt_file.expanduser().read_text(encoding="utf-8").strip()
    if prompt is not None:
        return prompt.strip()
    if watch_only:
        return None
    return None


def _run_curses(
    *,
    stdscr: Any,
    output_dir: Path | None,
    agent: str,
    analyst_prompt: str | None,
    case_id: str | None,
    runs_root: Path,
    source_root: str | None,
    watch_only: bool,
    refresh_seconds: float,
) -> int:
    import curses

    screen = stdscr
    screen.timeout(INPUT_TIMEOUT_MS)
    if hasattr(screen, "keypad"):
        screen.keypad(True)
    try:
        curses.curs_set(0)
    except Exception:
        pass
    theme = init_curses_theme(curses)
    key_backtab = getattr(curses, "KEY_BTAB", -999)

    process: subprocess.Popen[str] | None = None
    openclaw_status = "watch-only" if watch_only else "ready"
    launch_error: str | None = None
    final_refreshes = 0
    prompt_buffer = PromptInputBuffer()
    prompt_dirty = True
    submitted_prompt = analyst_prompt
    active_output_dir = output_dir if watch_only or submitted_prompt else None
    refresh_clock = RefreshClock(refresh_seconds)
    force_state_refresh = active_output_dir is not None
    last_state: ConsoleState | None = None
    needs_redraw = True
    completed_process_returncode: int | None = None
    focus = FocusState()

    while True:
        if active_output_dir is None:
            if prompt_dirty:
                _draw_prompt_entry(
                    screen,
                    prompt_input=prompt_buffer.text,
                    error=launch_error,
                    case_id=case_id,
                    runs_root=runs_root,
                    theme=theme,
                )
                prompt_dirty = False
            key = screen.getch()
            result = prompt_buffer.handle_key(
                key,
                backspace_keys=(curses.KEY_BACKSPACE, *KEY_BACKSPACE_VALUES),
            )
            if result.should_quit:
                return result.exit_code or 0
            if result.submitted_prompt is not None:
                submitted_prompt = result.submitted_prompt
                active_output_dir = output_dir or plan_output_dir(case_id, runs_root=runs_root)
                launch_error, process, openclaw_status = _launch_from_prompt(
                    output_dir=active_output_dir,
                    agent=agent,
                    analyst_prompt=submitted_prompt,
                    case_id=case_id,
                    runs_root=runs_root,
                    source_root=source_root,
                )
                force_state_refresh = True
                needs_redraw = True
                continue
            if result.changed:
                prompt_dirty = True
            continue

        wrapped_preview = (
            build_wrapped_prompt(submitted_prompt, active_output_dir, source_root)
            if submitted_prompt
            else None
        )
        now = time.monotonic()
        if last_state is None or refresh_clock.should_refresh(now, forced=force_state_refresh):
            state = read_console_state(active_output_dir, prompt=wrapped_preview)
            _mirror_visible_transcript(active_output_dir, state)
            if launch_error:
                state = _state_with_error(state, launch_error)
            last_state = state
            refresh_clock.mark_refreshed(now)
            force_state_refresh = False
            needs_redraw = True

        if needs_redraw and last_state is not None:
            _draw(
                screen,
                last_state,
                openclaw_status=openclaw_status,
                watch_only=watch_only,
                focus=focus,
                theme=theme,
            )
            needs_redraw = False

        key = screen.getch()
        if key == KEY_CTRL_C:
            return 130
        if key in (ord("q"), ord("Q")):
            if process is not None and process.poll() is None:
                if _confirm_quit(screen):
                    process.terminate()
                    return 0
            else:
                return 0
        if key in (ord("r"), ord("R")):
            force_state_refresh = True
            continue
        if key in (KEY_TAB, curses.KEY_RIGHT):
            focus_next(focus)
            needs_redraw = True
            continue
        if key in (key_backtab, curses.KEY_LEFT):
            focus_previous(focus)
            needs_redraw = True
            continue
        if key in (curses.KEY_DOWN, ord("j"), ord("J")):
            scroll_focused_panel(focus, 1)
            needs_redraw = True
            continue
        if key in (curses.KEY_UP, ord("k"), ord("K")):
            scroll_focused_panel(focus, -1)
            needs_redraw = True
            continue
        if key == curses.KEY_NPAGE:
            scroll_focused_panel(focus, PAGE_SCROLL_LINES)
            needs_redraw = True
            continue
        if key == curses.KEY_PPAGE:
            scroll_focused_panel(focus, -PAGE_SCROLL_LINES)
            needs_redraw = True
            continue
        if key == curses.KEY_HOME:
            set_focused_scroll(focus, 0)
            needs_redraw = True
            continue
        if key == curses.KEY_END:
            set_focused_scroll(focus, END_SCROLL_SENTINEL)
            needs_redraw = True
            continue
        if key in (KEY_ENTER, KEY_CARRIAGE_RETURN) and process is None and not watch_only:
            if submitted_prompt is not None:
                launch_error, process, openclaw_status = _launch_from_prompt(
                    output_dir=active_output_dir,
                    agent=agent,
                    analyst_prompt=submitted_prompt,
                    case_id=case_id,
                    runs_root=runs_root,
                    source_root=source_root,
                )
                force_state_refresh = True
                needs_redraw = True
                continue

        if process is not None and completed_process_returncode is None:
            returncode = process.poll()
            if returncode is not None:
                completed_process_returncode = returncode
                openclaw_status = f"exited rc={returncode}"
                complete_active_run(
                    runs_root=runs_root,
                    pid=int(process.pid),
                    returncode=returncode,
                )
                if returncode != 0:
                    launch_error = f"OpenClaw exited rc={returncode}"
                force_state_refresh = True
                needs_redraw = True
                continue

        if (
            completed_process_returncode == 0
            and last_state is not None
            and (last_state.job_status in TERMINAL_JOB_STATUSES or last_state.job_status is None)
        ):
            final_refreshes += 1
            if final_refreshes >= 3:
                return 0


def _launch_from_prompt(
    *,
    output_dir: Path,
    agent: str,
    analyst_prompt: str,
    case_id: str | None,
    runs_root: Path,
    source_root: str | None,
) -> tuple[str | None, subprocess.Popen[str] | None, str]:
    try:
        ensure_no_active_run(runs_root)
        output_dir.mkdir(parents=True, exist_ok=True)
        wrapped_prompt = build_wrapped_prompt(analyst_prompt, output_dir, source_root)
        write_run_context(
            output_dir=output_dir,
            case_id=case_id,
            agent=agent,
            runs_root=runs_root,
            source_root=source_root,
            analyst_prompt=analyst_prompt,
            wrapped_prompt=wrapped_prompt,
        )
        process = launch_openclaw(
            agent,
            wrapped_prompt,
            output_dir / OPENCLAW_LOG_FILENAME,
        )
        write_active_run_lock(
            runs_root=runs_root,
            pid=int(process.pid),
            output_dir=output_dir,
            agent=agent,
        )
    except ActiveRunError as exc:
        active = exc.active_run
        return (
            "Active run already exists: "
            f"pid={active.get('pid')} output_dir={active.get('output_dir')}",
            None,
            "blocked",
        )
    except FileNotFoundError:
        return "OpenClaw executable not found in PATH.", None, "failed"
    except OSError as exc:
        return f"OpenClaw launch failed: {exc}", None, "failed"
    except ValueError as exc:
        return str(exc), None, "failed"
    return None, process, f"running pid={process.pid}"


def _state_with_error(state: ConsoleState, error: str) -> ConsoleState:
    return ConsoleState(
        output_dir=state.output_dir,
        run_dir=state.run_dir,
        prompt=state.prompt,
        job_status=state.job_status,
        returncode=state.returncode,
        validation_status=state.validation_status,
        finding_counts=state.finding_counts,
        case_question_counts=state.case_question_counts,
        normalized_events=state.normalized_events,
        rationale_events=state.rationale_events,
        policy_events=state.policy_events,
        raw_policy_event_count=state.raw_policy_event_count,
        progress_events=state.progress_events,
        self_correction_count=state.self_correction_count,
        self_correction_status=state.self_correction_status,
        latest_self_correction=state.latest_self_correction,
        latest_corrected_claim_status=state.latest_corrected_claim_status,
        final_summary=state.final_summary,
        claim_boundary=state.claim_boundary,
        openclaw_log_tail=state.openclaw_log_tail,
        errors=[*state.errors, error],
        required_outputs_present=state.required_outputs_present,
    )


def _draw_prompt_entry(
    screen: Any,
    *,
    prompt_input: str,
    error: str | None,
    case_id: str | None,
    runs_root: Path,
    theme: TuiTheme,
) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    width = max(width, 20)
    _add_line(screen, 0, 0, "Elenchos", width, theme.attr(STYLE_HEADER))
    _add_line(
        screen,
        1,
        0,
        f"runs: {runs_root} | case: {case_id or 'auto'}",
        width,
        theme.attr(STYLE_MUTED),
    )
    lines = [
        "Type a case request:",
        f"Elenchos> {prompt_input}",
        f"runs root: {runs_root}",
        f"case id: {case_id or 'auto'}",
    ]
    if error:
        lines.extend(["", f"warning: {error}"])
    rect = Rect(3, 0, max(3, height - 4), width)
    _draw_panel(
        screen,
        rect,
        PanelModel("prompt", "Analyst Request", lines),
        focused=True,
        scroll_offset=0,
        theme=theme,
    )
    _add_line(
        screen,
        height - 1,
        0,
        "Enter submit | Backspace edit | q quit",
        width,
        theme.attr(STYLE_FOOTER),
    )
    screen.refresh()


def _draw(
    screen: Any,
    state: ConsoleState,
    *,
    openclaw_status: str,
    watch_only: bool,
    focus: FocusState,
    theme: TuiTheme,
) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    width = max(width, 20)
    layout = choose_layout(width, height)
    sync_focus_state(focus, layout)
    model = build_tui_model(
        state,
        openclaw_status=openclaw_status,
        watch_only=watch_only,
        width=width,
    )
    _draw_header(screen, model, width, theme)
    panel_by_id = {panel.panel_id: panel for panel in model.panels}
    for placement in layout.panels:
        panel = panel_by_id.get(placement.panel_id)
        if panel is None:
            continue
        _draw_panel(
            screen,
            placement.rect,
            panel,
            focused=focus.focused_panel_id == panel.panel_id,
            scroll_offset=focus.offset(panel.panel_id),
            theme=theme,
        )

    footer = model.footer
    if not watch_only and openclaw_status == "ready":
        footer = "Enter start | " + footer
    _add_line(screen, height - 1, 0, footer, width, theme.attr(STYLE_FOOTER))
    screen.refresh()


def _draw_header(screen: Any, model: Any, width: int, theme: TuiTheme) -> None:
    x = 0
    title = f" {model.header} "
    _add_line(screen, 0, x, title, width, theme.attr(STYLE_HEADER))
    x += len(title)
    for badge in model.header_badges:
        text = f" {badge.text} "
        if x >= width - 1:
            break
        _add_line(screen, 0, x, text, max(1, width - x), theme.badge_attr(badge.value))
        x += len(text) + 1
    _add_line(
        screen,
        1,
        0,
        f"output: {model.output_path}",
        width,
        theme.attr(STYLE_MUTED),
    )


def _confirm_quit(screen: Any) -> bool:
    height, width = screen.getmaxyx()
    _add_line(
        screen,
        height - 1,
        0,
        "OpenClaw is still running. Press y to terminate OpenClaw, any other key to continue.",
        width,
    )
    screen.timeout(-1)
    key = screen.getch()
    screen.timeout(INPUT_TIMEOUT_MS)
    return key in (ord("y"), ord("Y"))


def _draw_panel(
    screen: Any,
    rect: Rect,
    panel: PanelModel,
    *,
    focused: bool,
    scroll_offset: int,
    theme: TuiTheme,
) -> None:
    if rect.y >= screen.getmaxyx()[0] - 1:
        return
    actual_height = max(1, min(rect.height, screen.getmaxyx()[0] - rect.y - 1))
    width = max(1, min(rect.width, screen.getmaxyx()[1] - rect.x))
    if actual_height < 2 or width < 4:
        return
    border_attr = theme.attr(STYLE_ACTIVE_BORDER if focused else STYLE_INACTIVE_BORDER)
    title_attr = theme.attr(STYLE_ACCENT if focused else STYLE_MUTED)
    borders = theme.borders
    right = rect.x + width - 1
    bottom = rect.y + actual_height - 1
    title = f" {panel.title} "
    title_limit = max(0, width - 4)
    title = title[:title_limit]
    top = (
        borders.top_left
        + borders.horizontal * max(0, width - 2)
        + borders.top_right
    )
    bottom_line = (
        borders.bottom_left
        + borders.horizontal * max(0, width - 2)
        + borders.bottom_right
    )
    _add_line(screen, rect.y, rect.x, top, width, border_attr)
    _add_line(screen, rect.y, rect.x + 2, title, max(1, width - 4), title_attr)
    for row in range(rect.y + 1, bottom):
        _add_line(screen, row, rect.x, borders.vertical, 1, border_attr)
        if right < screen.getmaxyx()[1]:
            _add_line(screen, row, right, borders.vertical, 1, border_attr)
    _add_line(screen, bottom, rect.x, bottom_line, width, border_attr)
    content_width = max(1, width - 4)
    content_height = max(0, actual_height - 2)
    window = render_panel_model(
        panel,
        content_width=content_width,
        content_height=content_height,
        scroll_offset=scroll_offset,
    )
    for index, line in enumerate(window.lines, start=1):
        _add_line(screen, rect.y + index, rect.x + 2, line, content_width)


def _add_line(screen: Any, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
    safe_text = text[: max(0, width)]
    try:
        screen.addnstr(y, x, safe_text, len(safe_text), attr)
    except Exception:
        return


def _state_body_lines(state: ConsoleState, *, watch_only: bool) -> list[str]:
    return state_body_lines(state, watch_only=watch_only)


def _self_correction_line(state: ConsoleState) -> str:
    for line in state_body_lines(state, watch_only=True):
        if line.startswith("OBSERVED:") or line.startswith("NONE:"):
            return line
    return "NONE: no self-correction artifact events observed."


def _status_badges(state: ConsoleState, *, openclaw_status: str) -> list[str]:
    return [
        badge.text for badge in build_tui_model(
            state,
            openclaw_status=openclaw_status,
            watch_only=True,
            width=120,
        ).header_badges
    ]


def _format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def _mirror_visible_transcript(output_dir: Path, state: ConsoleState) -> None:
    resolved = output_dir.resolve()
    if is_relative_to(resolved, MOUNTED_EVIDENCE_ROOT) or not is_generated_output_path(resolved):
        return
    path = resolved / TRANSCRIPT_FILENAME
    lines = ["# Elenchos Case Console Transcript", ""]
    for event in [*state.rationale_events, *state.policy_events]:
        timestamp = f"{event.timestamp_utc} " if event.timestamp_utc else ""
        lines.append(f"- {timestamp}{event.message}")
    if len(lines) <= 2:
        return
    content = "\n".join(_dedupe_lines(lines)) + "\n"
    if path.exists() and path.read_text(encoding="utf-8", errors="ignore") == content:
        return
    path.write_text(content, encoding="utf-8")


def _dedupe_lines(lines: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if line.startswith("- ") and line in seen:
            continue
        if line.startswith("- "):
            seen.add(line)
        output.append(line)
    return output


def terminal_columns() -> int:
    return shutil.get_terminal_size((100, 24)).columns
