from __future__ import annotations

import json
from pathlib import Path
from typing import IO

from elenchos.integrations import job_runner


class FakePopen:
    pid = 4242

    def __init__(
        self,
        argv: list[str],
        *,
        cwd: Path,
        text: bool,
        stdout: IO[str],
        stderr: IO[str],
        shell: bool,
    ) -> None:
        assert isinstance(argv, list)
        assert shell is False
        assert text is True
        assert cwd.is_dir()
        stdout.write("started\n")
        stderr.write("")
        self.argv = argv
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode


def _write_case_prep(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "case_id": "case",
        "source_root": str(path.parent.parent / "evidence"),
        "sources": [{"local_path": str(path.parent.parent / "evidence" / "source.E01")}],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_start_case_run_writes_job_and_rejects_duplicate(tmp_path: Path):
    job_runner.POPEN_REGISTRY.clear()
    case_prep = tmp_path / "runs" / "case" / "case-prep" / "case_prep.json"
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_case_prep(case_prep)

    first = job_runner.start_case_run(
        {"artifact_manifest": str(case_prep), "output_dir": str(output_dir)},
        popen_factory=FakePopen,
    )
    second = job_runner.start_case_run(
        {"artifact_manifest": str(case_prep), "output_dir": str(output_dir)},
        popen_factory=FakePopen,
    )

    assert first["status"] == "started"
    assert (output_dir / "run_job.json").is_file()
    assert second["status"] == "rejected"


def test_poll_and_finish_read_generated_job_state(tmp_path: Path):
    job_runner.POPEN_REGISTRY.clear()
    case_prep = tmp_path / "runs" / "case" / "case-prep" / "case_prep.json"
    output_dir = tmp_path / "runs" / "case" / "agent-run"
    _write_case_prep(case_prep)
    started = job_runner.start_case_run(
        {"artifact_manifest": str(case_prep), "output_dir": str(output_dir)},
        popen_factory=FakePopen,
    )
    process = job_runner.POPEN_REGISTRY[str(started["job_id"])]
    assert isinstance(process, FakePopen)

    running = job_runner.poll_case_run({"output_dir": str(output_dir)})
    process.returncode = 0
    completed = job_runner.finish_case_run({"output_dir": str(output_dir)})

    assert running["status"] == "running"
    assert completed["status"] == "completed"
    assert completed["progress_event_count"] == 1
