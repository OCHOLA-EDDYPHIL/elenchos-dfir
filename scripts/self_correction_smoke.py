from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    fixture = repo_root / "tests" / "fixtures" / "positive_control" / "unsupported_claim.json"
    with tempfile.TemporaryDirectory(prefix="elenchos-self-correction-") as tmp:
        output_dir = Path(tmp) / "runs" / "case_self-correction-control" / "agent-run"
        command = [
            sys.executable,
            "-m",
            "elenchos",
            "agent",
            "run-fixture",
            "--case-id",
            "case_self-correction-control",
            "--fixture",
            str(fixture),
            "--output-dir",
            str(output_dir),
            "--max-iterations",
            "7",
        ]
        completed = subprocess.run(
            command,
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            print(completed.stdout, end="")
            print(completed.stderr, end="", file=sys.stderr)
            return completed.returncode

        agent_run = json.loads((output_dir / "agent_run.json").read_text(encoding="utf-8"))
        findings = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
        corrections = agent_run.get("corrections", [])
        statuses = [
            row.get("status")
            for row in findings.get("findings", [])
            if isinstance(row, dict)
        ]
        if not corrections:
            print("self-correction smoke failed: no corrections recorded", file=sys.stderr)
            return 1
        if "needs_review" not in statuses:
            print("self-correction smoke failed: no finding was downgraded", file=sys.stderr)
            return 1

        print(f"self_correction_output={output_dir}")
        print(f"self_correction_count={len(corrections)}")
        print(f"finding_statuses={','.join(str(status) for status in statuses)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
