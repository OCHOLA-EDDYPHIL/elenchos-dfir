from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_AGENT = "main"


def build_default_prompt(source_root: str, output_dir: Path) -> str:
    return (
        "Triage the case with Elenchos using the evidence source at "
        f"{source_root}. Use only bounded Elenchos tools. Use this exact "
        f"Elenchos output directory: {output_dir}. Keep raw evidence read-only. "
        "Use the prepared_manifest_path produced by prepare_case when starting "
        "the run. Show live rationale and policy-gate progress through Elenchos "
        "generated artifacts. Do not claim confirmed theft, exfiltration, memory "
        "findings, malware, attribution, or final compromise unless deterministic "
        "Elenchos outputs support the claim and validation passes. Final output "
        "should include supported findings, unsupported gaps, claim boundary, "
        "and trace paths."
    )


def build_openclaw_command(agent: str, prompt: str) -> list[str]:
    if not agent:
        raise ValueError("agent must be a non-empty string")
    if not prompt:
        raise ValueError("prompt must be a non-empty string")
    return ["openclaw", "agent", "--agent", agent, prompt]


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


def make_output_dir(case_id: str | None, runs_root: Path = Path("runs")) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = _slugify(case_id or "case")
    output_dir = runs_root.expanduser().resolve() / f"{slug}-{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=False)
    return output_dir


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-._")
    return slug or "case"
