from __future__ import annotations

import json
from pathlib import Path
from typing import IO

from elenchos.integrations import job_runner
from elenchos.integrations.job_state import _linux_process_state


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
    artifact_path = path.parent / "extracted" / "mft" / "$MFT"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(b"mft")
    payload = {
        "case_id": "case",
        "coverage_gaps": [],
        "prepared_artifacts": [
            {
                "artifact_id": "prep_mft",
                "artifact_type": "mft",
                "parser_eligible": True,
                "path": "extracted/mft/$MFT",
                "source_id": "src1",
                "status": "available",
            }
        ],
        "source_root": str(path.parent.parent / "evidence"),
        "sources": [
            {
                "analysis_scope": "primary",
                "display_name": "source.E01",
                "kind": "ewf_e01",
                "local_path": str(path.parent.parent / "evidence" / "source.E01"),
                "role": "disk_image",
                "source_id": "src1",
                "status": "available",
            }
        ],
        "warnings": [],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_linux_process_state_reads_proc_stat(tmp_path: Path):
    proc_stat = tmp_path / "123" / "stat"
    proc_stat.parent.mkdir()
    proc_stat.write_text("123 (python worker) Z 1 2 3\n", encoding="utf-8")

    assert _linux_process_state(123, tmp_path) == "Z"


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
    assert first["prepared_manifest_path"].endswith("case_prep.json")
    assert (output_dir / "run_job.json").is_file()
    job = json.loads((output_dir / "run_job.json").read_text(encoding="utf-8"))
    assert job["prepared_manifest_path"].endswith("case_prep.json")
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


def test_start_case_run_passes_prepared_manifest_path_into_argv(tmp_path: Path):
    job_runner.POPEN_REGISTRY.clear()
    case_prep = tmp_path / "runs" / "case" / "prep" / "case_prep.json"
    output_dir = tmp_path / "runs" / "case" / "run"
    seen: list[list[str]] = []
    _write_case_prep(case_prep)

    class RecordingPopen(FakePopen):
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            seen.append(argv)
            super().__init__(argv, **kwargs)  # type: ignore[arg-type]

    job_runner.start_case_run(
        {"prepared_manifest_path": str(case_prep), "output_dir": str(output_dir)},
        popen_factory=RecordingPopen,
    )

    argv = seen[0]
    assert argv[argv.index("--artifact-manifest") + 1] == str(case_prep.resolve())


def test_start_case_run_rejects_run_integrity_manifest_before_launch(tmp_path: Path):
    called = False
    bad_manifest = tmp_path / "runs" / "case" / "run" / "run_integrity_manifest.json"
    bad_manifest.parent.mkdir(parents=True)
    bad_manifest.write_text("{}\n", encoding="utf-8")

    def fail_if_called(*args: object, **kwargs: object) -> FakePopen:
        nonlocal called
        called = True
        return FakePopen(*args, **kwargs)  # type: ignore[arg-type]

    try:
        job_runner.start_case_run(
            {"prepared_manifest_path": str(bad_manifest), "output_dir": str(bad_manifest.parent)},
            popen_factory=fail_if_called,
        )
    except ValueError as exc:
        assert "not a prepared case manifest" in str(exc)
    else:
        raise AssertionError("start_case_run should have rejected the wrong manifest")

    assert called is False


def test_start_case_run_rejects_unsupported_manifest_before_launch(tmp_path: Path):
    called = False
    case_prep = tmp_path / "runs" / "case" / "prep" / "case_prep.json"
    case_prep.parent.mkdir(parents=True)
    case_prep.write_text(
        json.dumps(
            {
                "case_id": "case",
                "coverage_gaps": [],
                "prepared_artifacts": [],
                "sources": [
                    {
                        "analysis_scope": "primary",
                        "display_name": "source.E01",
                        "kind": "ewf_e01",
                        "role": "disk_image",
                        "source_id": "src1",
                        "status": "available",
                    }
                ],
                "warnings": [],
            }
        ),
        encoding="utf-8",
    )

    def fail_if_called(*args: object, **kwargs: object) -> FakePopen:
        nonlocal called
        called = True
        return FakePopen(*args, **kwargs)  # type: ignore[arg-type]

    try:
        job_runner.start_case_run(
            {
                "prepared_manifest_path": str(case_prep),
                "output_dir": str(case_prep.parent.parent / "run"),
            },
            popen_factory=fail_if_called,
        )
    except ValueError as exc:
        assert "contains no supported prepared artifacts" in str(exc)
    else:
        raise AssertionError("start_case_run should have rejected unsupported manifest")

    assert called is False
