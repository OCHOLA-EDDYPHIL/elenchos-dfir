from __future__ import annotations

import shutil
import subprocess
import textwrap
import time
from pathlib import Path
from typing import Any

from elenchos.policy.paths import (
    MOUNTED_EVIDENCE_ROOT,
    is_generated_output_path,
    is_relative_to,
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
    ConsoleEvent,
    ConsoleState,
    read_console_state,
    render_text_snapshot,
)

TERMINAL_JOB_STATUSES = {
    "completed",
    "completed_unknown_exit",
    "failed",
    "rejected",
    "not_found",
}
TRANSCRIPT_FILENAME = "case_console_transcript.md"


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
    refresh_seconds: float = 1.0,
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
    screen.nodelay(True)
    curses.curs_set(0)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)

    process: subprocess.Popen[str] | None = None
    openclaw_status = "watch-only" if watch_only else "ready"
    launch_error: str | None = None
    final_refreshes = 0
    prompt_input = ""
    submitted_prompt = analyst_prompt
    active_output_dir = output_dir if watch_only or submitted_prompt else None

    while True:
        if active_output_dir is None:
            _draw_prompt_entry(
                screen,
                prompt_input=prompt_input,
                error=launch_error,
                case_id=case_id,
                runs_root=runs_root,
            )
            state = None
        else:
            wrapped_preview = (
                build_wrapped_prompt(submitted_prompt, active_output_dir, source_root)
                if submitted_prompt
                else None
            )
            state = read_console_state(active_output_dir, prompt=wrapped_preview)
            _mirror_visible_transcript(active_output_dir, state)
            if launch_error:
                state = _state_with_error(state, launch_error)
            _draw(screen, state, openclaw_status=openclaw_status, watch_only=watch_only)

        key = screen.getch()
        if key == 3:
            return 130
        if active_output_dir is None:
            if key in (ord("q"), ord("Q")) and not prompt_input:
                return 0
            if key in (ord("\n"), 10, 13):
                if prompt_input.strip():
                    submitted_prompt = prompt_input.strip()
                    active_output_dir = output_dir or plan_output_dir(case_id, runs_root=runs_root)
                    launch_error, process, openclaw_status = _launch_from_prompt(
                        output_dir=active_output_dir,
                        agent=agent,
                        analyst_prompt=submitted_prompt,
                        case_id=case_id,
                        runs_root=runs_root,
                        source_root=source_root,
                    )
                continue
            if key in (curses.KEY_BACKSPACE, 127, 8):
                prompt_input = prompt_input[:-1]
                continue
            if 32 <= key <= 126:
                prompt_input += chr(key)
            time.sleep(max(refresh_seconds, 0.1))
            continue

        if key in (ord("q"), ord("Q")):
            if process is not None and process.poll() is None:
                if _confirm_quit(screen):
                    process.terminate()
                    return 0
            else:
                return 0
        if key in (ord("\n"), 10, 13) and process is None and not watch_only:
            if submitted_prompt is not None:
                launch_error, process, openclaw_status = _launch_from_prompt(
                    output_dir=active_output_dir,
                    agent=agent,
                    analyst_prompt=submitted_prompt,
                    case_id=case_id,
                    runs_root=runs_root,
                    source_root=source_root,
                )

        if process is not None:
            returncode = process.poll()
            if returncode is not None:
                openclaw_status = f"exited rc={returncode}"
                complete_active_run(
                    runs_root=runs_root,
                    pid=int(process.pid),
                    returncode=returncode,
                )
                if returncode != 0:
                    launch_error = f"OpenClaw exited rc={returncode}"
                elif state is not None and (
                    state.job_status in TERMINAL_JOB_STATUSES or state.job_status is None
                ):
                    final_refreshes += 1
                    if final_refreshes >= 3:
                        return 0
        time.sleep(max(refresh_seconds, 0.1))


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
        progress_events=state.progress_events,
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
) -> None:
    import curses

    screen.erase()
    height, width = screen.getmaxyx()
    width = max(width, 20)
    lines = [
        "Elenchos Case Console",
        "",
        "Type a case request. Example:",
        '"Triage the ROCBA case and tell me what happened."',
        "",
        f"runs root: {runs_root}",
        f"case id: {case_id or 'auto'}",
        "",
        f"Elenchos> {prompt_input}",
    ]
    if error:
        lines.extend(["", f"warning: {error}"])
    for index, line in enumerate(lines[: max(0, height - 2)]):
        attr = curses.A_BOLD if index == 0 else 0
        _add_line(screen, index, 0, line, width, attr)
    _add_line(screen, height - 1, 0, "Enter submit | Backspace edit | q quit", width, curses.A_DIM)
    screen.refresh()


def _draw(
    screen: Any,
    state: ConsoleState,
    *,
    openclaw_status: str,
    watch_only: bool,
) -> None:
    import curses

    screen.erase()
    height, width = screen.getmaxyx()
    width = max(width, 20)
    header = (
        "Elenchos Case Console | "
        f"OpenClaw: {openclaw_status} | "
        f"job: {state.job_status or 'pending'} | "
        f"validation: {state.validation_status or 'pending'}"
    )
    _add_line(screen, 0, 0, header, width, curses.A_BOLD)
    _add_line(screen, 1, 0, f"path: {state.output_dir}", width)

    y = 3
    panel_height = max(4, (height - 6) // 5)
    y = _panel(
        screen,
        y,
        0,
        panel_height,
        width,
        "Prompt",
        _wrapped_lines(
            state.prompt or "Watch-only mode. No prompt will be launched.",
            width - 4,
        )[:2],
    )
    y = _panel(
        screen,
        y,
        0,
        panel_height,
        width,
        "Live rationale",
        _event_lines(state.rationale_events, limit=max(1, panel_height - 3)),
    )
    y = _panel(
        screen,
        y,
        0,
        panel_height,
        width,
        "Policy gate",
        _event_lines(state.policy_events, limit=max(1, panel_height - 3)),
    )
    status_lines = [
        f"findings: {_format_counts(state.finding_counts) or 'none'}",
        f"case questions: {_format_counts(state.case_question_counts) or 'none'}",
        "normalized events: "
        f"{state.normalized_events if state.normalized_events is not None else 'pending'}",
        "required outputs: "
        + ", ".join(
            f"{name}={'yes' if present else 'no'}"
            for name, present in sorted(state.required_outputs_present.items())
        ),
    ]
    y = _panel(screen, y, 0, panel_height, width, "Run status", status_lines)
    summary_lines = _wrapped_lines(
        state.final_summary or "Pending generated Elenchos summary.",
        width - 4,
    )
    summary_lines.extend(_wrapped_lines(f"Claim boundary: {state.claim_boundary}", width - 4))
    if state.errors:
        summary_lines.append(f"warnings: {len(state.errors)}")
    if state.openclaw_log_tail:
        summary_lines.append("OpenClaw log tail:")
        summary_lines.extend(state.openclaw_log_tail[-3:])
    _panel(screen, y, 0, max(4, height - y - 2), width, "Final summary", summary_lines)

    footer = "q quit | r refresh"
    if not watch_only and openclaw_status == "ready":
        footer = "Enter start | " + footer
    _add_line(screen, height - 1, 0, footer, width, curses.A_DIM)
    screen.refresh()


def _confirm_quit(screen: Any) -> bool:
    height, width = screen.getmaxyx()
    _add_line(
        screen,
        height - 1,
        0,
        "OpenClaw is still running. Press y to terminate OpenClaw, any other key to continue.",
        width,
    )
    screen.nodelay(False)
    key = screen.getch()
    screen.nodelay(True)
    return key in (ord("y"), ord("Y"))


def _panel(
    screen: Any,
    y: int,
    x: int,
    height: int,
    width: int,
    title: str,
    lines: list[str],
) -> int:
    if y >= screen.getmaxyx()[0] - 2:
        return y
    actual_height = max(3, min(height, screen.getmaxyx()[0] - y - 1))
    right = x + width - 1
    bottom = y + actual_height - 1
    if width >= 4 and actual_height >= 3:
        _add_line(screen, y, x, "+" + "-" * (width - 2) + "+", width)
        _add_line(screen, y, x + 2, f" {title} ", max(1, width - 4))
        for row in range(y + 1, bottom):
            _add_line(screen, row, x, "|", width)
            if right < screen.getmaxyx()[1]:
                _add_line(screen, row, right, "|", 1)
        _add_line(screen, bottom, x, "+" + "-" * (width - 2) + "+", width)
    for index, line in enumerate(lines[: max(0, actual_height - 2)], start=1):
        _add_line(screen, y + index, x + 2, line, max(1, width - 4))
    return y + actual_height


def _add_line(screen: Any, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
    try:
        screen.addnstr(y, x, text, max(0, width - 1), attr)
    except Exception:
        return


def _event_lines(events: list[ConsoleEvent], *, limit: int) -> list[str]:
    if not events:
        return ["pending"]
    return [event.message for event in events[-limit:]]


def _wrapped_lines(text: str, width: int) -> list[str]:
    return textwrap.wrap(text, width=max(width, 20)) or [""]


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
