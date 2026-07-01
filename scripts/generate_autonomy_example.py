#!/usr/bin/env python3
"""Regenerate the committed sanitized autonomy example bundle.

Runs the Replay-driven autonomy loop over the synthetic ``autonomy_demo`` fixture
(no model, no network, no real evidence) and writes a sanitized copy of the run
bundle under ``docs/examples/autonomy-runs/case-autonomy-demo/``. Paths are redacted
with the same ``$REPO_ROOT`` / ``$RUN_DIR`` / ``$HOME`` convention used by
``docs/submission/log-excerpts``.

Usage:  PYTHONPATH=src python scripts/generate_autonomy_example.py
"""

from __future__ import annotations

import tempfile
from itertools import count
from pathlib import Path

from elenchos.autonomy import AutonomySupervisor
from elenchos.autonomy.providers import ReplayDecisionProvider

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIR = REPO_ROOT / "docs" / "examples" / "autonomy-runs" / "case-autonomy-demo"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "positive_control" / "autonomy_demo.json"
DECISIONS = EXAMPLE_DIR / "decisions.jsonl"
CASE_ID = "case_positive-control"

BUNDLE_FILES = (
    "autonomy_decisions.jsonl",
    "state_observations.jsonl",
    "plan_revisions.jsonl",
    "tool_executions.jsonl",
    "self_correction_events.json",
    "trace_map.json",
    "findings.json",
    "report.md",
    "policy_decisions.jsonl",
)


def _fixed_clock():
    counter = count()
    base = "2026-06-20T12:00:"

    def _clock() -> str:
        seconds = next(counter) % 60
        return f"{base}{seconds:02d}Z"

    return _clock


def _sanitize(text: str, run_dir: Path) -> str:
    replacements = [
        (str(run_dir.resolve()), "$RUN_DIR"),
        (str(REPO_ROOT.resolve()), "$REPO_ROOT"),
        (str(Path.home()), "$HOME"),
    ]
    for needle, token in replacements:
        text = text.replace(needle, token)
    return text


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "runs" / "autonomy-demo"
        supervisor = AutonomySupervisor(
            case_id=CASE_ID,
            output_dir=output_dir,
            provider=ReplayDecisionProvider.from_jsonl(DECISIONS),
            fixture_path=FIXTURE,
            max_iterations=10,
            clock=_fixed_clock(),
        )
        result = supervisor.run()
        agent_run_dir = Path(result.agent_run_dir)

        EXAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        written = []
        for name in BUNDLE_FILES:
            source = agent_run_dir / name
            if not source.exists():
                continue
            sanitized = _sanitize(source.read_text(encoding="utf-8"), output_dir)
            (EXAMPLE_DIR / name).write_text(sanitized, encoding="utf-8")
            written.append(name)

    print(f"verification_status={result.verification_status}")
    print(f"plan_revisions={result.plan_revision_count}")
    print(f"self_correction_events={result.self_correction_count}")
    print(
        "trace_all_supported_resolved="
        f"{result.trace_map and result.trace_map.get('all_supported_claims_resolved')}"
    )
    print(f"written={','.join(written)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
