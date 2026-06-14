from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_AGENT = "main"
ACTIVE_RUN_FILENAME = ".elenchos-active-run.json"
OPENCLAW_LOG_FILENAME = "openclaw-console.log"


class ActiveRunError(RuntimeError):
    def __init__(self, active_run: dict[str, Any]) -> None:
        self.active_run = active_run
        output_dir = active_run.get("output_dir", "unknown")
        pid = active_run.get("pid", "unknown")
        super().__init__(
            "active Elenchos console run already exists: "
            f"pid={pid} output_dir={output_dir}"
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_wrapped_prompt(
    analyst_prompt: str,
    output_dir: Path,
    source_root: str | None = None,
) -> str:
    prompt = analyst_prompt.strip()
    if not prompt:
        raise ValueError("analyst_prompt must be non-empty")
    source_sentence = (
        f" Use the evidence source at {source_root}."
        if source_root is not None and source_root.strip()
        else ""
    )
    return (
        "Analyst request:\n"
        f"{prompt}\n\n"
        "Elenchos runtime constraints:\n"
        f"- Use this exact Elenchos output directory: {output_dir}.\n"
        "- Write generated outputs only under that directory.\n"
        "- Use only bounded Elenchos tools.\n"
        "- Keep raw evidence read-only.\n"
        "- Use the prepared_manifest_path produced by prepare_case when starting "
        "deterministic triage.\n"
        "- Show live [model-rationale] and [policy] progress through Elenchos "
        "generated artifacts.\n"
        "- Do not claim confirmed theft, exfiltration, memory findings, malware, "
        "attribution, or final compromise unless deterministic Elenchos outputs "
        "support the claim and validation passes.\n"
        "- Final response should include supported findings, unsupported gaps, "
        "claim boundary, and trace paths."
        f"{source_sentence}"
    )


def build_default_prompt(source_root: str, output_dir: Path) -> str:
    return build_wrapped_prompt(
        "Triage the case with Elenchos.",
        output_dir=output_dir,
        source_root=source_root,
    )


def build_openclaw_command(agent: str, prompt: str) -> list[str]:
    if not agent:
        raise ValueError("agent must be a non-empty string")
    if not prompt:
        raise ValueError("prompt must be a non-empty string")
    return ["openclaw", "agent", "--agent", agent, "--message", prompt]


def launch_openclaw(agent: str, prompt: str, log_path: Path) -> subprocess.Popen[str]:
    command = build_openclaw_command(agent, prompt)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("a", encoding="utf-8")
    try:
        return subprocess.Popen(
            command,
            text=True,
            stdout=handle,
            stderr=subprocess.STDOUT,
            shell=False,
        )
    finally:
        handle.close()


def plan_output_dir(case_id: str | None, runs_root: Path = Path("runs")) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = _slugify(case_id or "case")
    return runs_root.expanduser().resolve() / f"{slug}-{timestamp}"


def make_output_dir(case_id: str | None, runs_root: Path = Path("runs")) -> Path:
    output_dir = plan_output_dir(case_id, runs_root=runs_root)
    output_dir.mkdir(parents=True, exist_ok=False)
    return output_dir


def write_run_context(
    *,
    output_dir: Path,
    case_id: str | None,
    agent: str,
    runs_root: Path,
    source_root: str | None,
    analyst_prompt: str,
    wrapped_prompt: str,
) -> dict[str, object]:
    context: dict[str, object] = {
        "created_at_utc": utc_now(),
        "case_id": case_id,
        "agent": agent,
        "output_dir": str(output_dir),
        "runs_root": str(runs_root),
        "source_root": source_root,
        "analyst_prompt": analyst_prompt,
        "wrapped_prompt": wrapped_prompt,
        "policy_boundary": (
            "TUI text and model rationale are operational display only, not forensic "
            "evidence. Deterministic Elenchos outputs remain the forensic authority."
        ),
        "openclaw_command_shape": [
            "openclaw",
            "agent",
            "--agent",
            agent,
            "--message",
            "<prompt>",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "run_context.json").write_text(
        json.dumps(context, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return context


def active_run_lock_path(runs_root: Path = Path("runs")) -> Path:
    return runs_root.expanduser().resolve() / ACTIVE_RUN_FILENAME


def process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_active_run_lock(runs_root: Path = Path("runs")) -> dict[str, Any] | None:
    path = active_run_lock_path(runs_root)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def ensure_no_active_run(runs_root: Path = Path("runs")) -> None:
    lock = read_active_run_lock(runs_root)
    if lock is None:
        return
    pid = lock.get("pid")
    status = lock.get("status")
    if isinstance(pid, int) and status == "running" and process_is_alive(pid):
        raise ActiveRunError(lock)
    mark_active_run_stale(runs_root, lock)


def write_active_run_lock(
    *,
    runs_root: Path,
    pid: int,
    output_dir: Path,
    agent: str,
) -> dict[str, object]:
    lock = {
        "pid": pid,
        "output_dir": str(output_dir),
        "agent": agent,
        "started_at_utc": utc_now(),
        "status": "running",
    }
    path = active_run_lock_path(runs_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return lock


def mark_active_run_stale(
    runs_root: Path,
    lock: dict[str, Any] | None = None,
) -> dict[str, object] | None:
    existing = lock or read_active_run_lock(runs_root)
    if existing is None:
        return None
    updated = dict(existing)
    updated["status"] = "stale"
    updated["updated_at_utc"] = utc_now()
    path = active_run_lock_path(runs_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return updated


def complete_active_run(
    *,
    runs_root: Path,
    pid: int,
    returncode: int,
) -> dict[str, object] | None:
    lock = read_active_run_lock(runs_root)
    if lock is None or lock.get("pid") != pid:
        return None
    updated = dict(lock)
    updated["status"] = "completed" if returncode == 0 else "failed"
    updated["returncode"] = returncode
    updated["completed_at_utc"] = utc_now()
    path = active_run_lock_path(runs_root)
    path.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return updated


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-._")
    return slug or "case"
