from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from elenchos.evidence.manifest import EvidenceArtifact
from elenchos.parser.config import ParserCommandConfig, ParserToolCommand
from elenchos.parser.mft import (
    DEFAULT_MFTECMD_CSV_NAME,
    PARSER_NAME,
    parse_mft,
    parse_mft_artifact,
)
from elenchos.runner.tool_result import ToolResult

FIXTURE_DIR = Path("tests/fixtures/parser_outputs/mft")


def make_mft(tmp_path: Path) -> Path:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    mft_path = evidence_root / "$MFT"
    mft_path.write_bytes(b"synthetic mft placeholder, not real evidence\n")
    return mft_path


def make_config(executable: str = "MFTECmd-test") -> ParserCommandConfig:
    return ParserCommandConfig(
        {
            "mftecmd": ParserToolCommand(
                parser_name="mftecmd",
                executable=executable,
            )
        }
    )


def fake_runner_success(captured: dict[str, object]):
    def runner(command, **kwargs):
        captured["command"] = tuple(command)
        captured["kwargs"] = dict(kwargs)

        output_dir = Path(command[command.index("--csv") + 1])
        csv_name = command[command.index("--csvf") + 1]
        shutil.copyfile(FIXTURE_DIR / "mftecmd_valid.csv", output_dir / csv_name)

        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("synthetic stdout\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")

        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=0,
            duration_ms=12,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            stdout_sha256=None,
            stderr_sha256=None,
            status="success",
        )

    return runner


def fake_runner_failed_without_csv(captured: dict[str, object]):
    def runner(command, **kwargs):
        captured["command"] = tuple(command)
        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("synthetic failure\n", encoding="utf-8")
        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=7,
            duration_ms=15,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            stdout_sha256=None,
            stderr_sha256=None,
            status="failed",
        )

    return runner


def fake_runner_failed_with_csv(captured: dict[str, object]):
    def runner(command, **kwargs):
        captured["command"] = tuple(command)
        output_dir = Path(command[command.index("--csv") + 1])
        csv_name = command[command.index("--csvf") + 1]
        shutil.copyfile(FIXTURE_DIR / "mftecmd_valid.csv", output_dir / csv_name)

        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("synthetic failure\n", encoding="utf-8")
        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=7,
            duration_ms=15,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            stdout_sha256=None,
            stderr_sha256=None,
            status="failed",
        )

    return runner


def fake_runner_success_malformed_csv(captured: dict[str, object]):
    def runner(command, **kwargs):
        captured["command"] = tuple(command)
        output_dir = Path(command[command.index("--csv") + 1])
        csv_name = command[command.index("--csvf") + 1]
        shutil.copyfile(FIXTURE_DIR / "mftecmd_malformed.csv", output_dir / csv_name)

        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("synthetic stdout\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=0,
            duration_ms=12,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            stdout_sha256=None,
            stderr_sha256=None,
            status="success",
        )

    return runner


def test_parse_mft_builds_expected_argv_and_success_result(tmp_path):
    captured: dict[str, object] = {}
    mft_path = make_mft(tmp_path)
    runs_root = tmp_path / "runs"

    result = parse_mft(
        case_id="case-001",
        artifact_id="EV-MFT-0001",
        mft_path=mft_path,
        runs_root=runs_root,
        evidence_root=mft_path.parent,
        command_config=make_config(),
        runner=fake_runner_success(captured),
    )

    output_dir = runs_root / "case-001" / "parser_outputs" / "EV-MFT-0001" / "mftecmd"
    command = captured["command"]
    assert command == (
        "MFTECmd-test",
        "-f",
        str(mft_path),
        "--csv",
        str(output_dir.resolve()),
        "--csvf",
        DEFAULT_MFTECMD_CSV_NAME,
    )
    assert isinstance(result.command, tuple)
    assert result.parser_name == PARSER_NAME
    assert result.status == "success"
    assert result.output_dir == str(output_dir.resolve())
    assert str(output_dir / DEFAULT_MFTECMD_CSV_NAME) in result.output_files
    assert str((runs_root / "case-001" / "logs").resolve()) in result.metadata["stdout_path"]
    assert result.output_hashes
    assert len(result.events) == 4


def test_parse_mft_returns_failed_when_runner_fails_without_csv(tmp_path):
    captured: dict[str, object] = {}
    mft_path = make_mft(tmp_path)

    result = parse_mft(
        case_id="case-001",
        artifact_id="EV-MFT-0001",
        mft_path=mft_path,
        runs_root=tmp_path / "runs",
        evidence_root=mft_path.parent,
        command_config=make_config(),
        runner=fake_runner_failed_without_csv(captured),
    )

    assert result.status == "failed"
    assert result.events == []
    assert result.errors
    assert any("exit_code=7" in error for error in result.errors)
    assert any(path.endswith("_stderr.log") for path in result.output_files)
    assert any(path.endswith("_stderr.log") for path in result.output_hashes)


def test_parse_mft_returns_partial_success_when_runner_fails_with_csv(tmp_path):
    captured: dict[str, object] = {}
    mft_path = make_mft(tmp_path)

    result = parse_mft(
        case_id="case-001",
        artifact_id="EV-MFT-0001",
        mft_path=mft_path,
        runs_root=tmp_path / "runs",
        evidence_root=mft_path.parent,
        command_config=make_config(),
        runner=fake_runner_failed_with_csv(captured),
    )

    assert result.status == "partial_success"
    assert result.events
    assert result.warnings
    assert result.errors


def test_parse_mft_returns_partial_success_for_malformed_csv(tmp_path):
    captured: dict[str, object] = {}
    mft_path = make_mft(tmp_path)

    result = parse_mft(
        case_id="case-001",
        artifact_id="EV-MFT-0001",
        mft_path=mft_path,
        runs_root=tmp_path / "runs",
        evidence_root=mft_path.parent,
        command_config=make_config(),
        runner=fake_runner_success_malformed_csv(captured),
    )

    assert result.status == "partial_success"
    assert result.events
    assert result.warnings
    assert any("invalid timestamp" in warning for warning in result.warnings)
    assert any(event.status == "malformed" for event in result.events)


def test_parse_mft_returns_skipped_when_command_missing(tmp_path):
    mft_path = make_mft(tmp_path)
    config = ParserCommandConfig({})

    result = parse_mft(
        case_id="case-001",
        artifact_id="EV-MFT-0001",
        mft_path=mft_path,
        runs_root=tmp_path / "runs",
        evidence_root=mft_path.parent,
        command_config=config,
        runner=fake_runner_success({}),
    )

    assert result.status == "skipped"
    assert result.command is None
    assert any("MFTECmd command is not available" in error for error in result.errors)


def test_parse_mft_rejects_missing_input(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_mft(
            case_id="case-001",
            artifact_id="EV-MFT-0001",
            mft_path=tmp_path / "missing-$MFT",
            runs_root=tmp_path / "runs",
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_mft_rejects_directory_input(tmp_path):
    mft_dir = tmp_path / "evidence"
    mft_dir.mkdir()

    with pytest.raises(ValueError, match="must be a file"):
        parse_mft(
            case_id="case-001",
            artifact_id="EV-MFT-0001",
            mft_path=mft_dir,
            runs_root=tmp_path / "runs",
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_mft_rejects_outputs_inside_evidence_root(tmp_path):
    mft_path = make_mft(tmp_path)

    with pytest.raises(ValueError, match="inside evidence root"):
        parse_mft(
            case_id="case-001",
            artifact_id="EV-MFT-0001",
            mft_path=mft_path,
            runs_root=mft_path.parent / "runs",
            evidence_root=mft_path.parent,
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_mft_artifact_accepts_mft_and_rejects_non_mft(tmp_path):
    mft_path = make_mft(tmp_path)
    artifact = EvidenceArtifact(
        artifact_id="EV-MFT-0001",
        path=str(mft_path),
        relative_path="$MFT",
        size_bytes=mft_path.stat().st_size,
        sha256="a" * 64,
        artifact_type="mft",
        discovered_at_utc="2026-01-01T00:00:00Z",
    )

    result = parse_mft_artifact(
        case_id="case-001",
        artifact=artifact,
        runs_root=tmp_path / "runs",
        evidence_root=mft_path.parent,
        command_config=make_config(),
        runner=fake_runner_success({}),
    )
    assert result.status == "success"

    bad_artifact = EvidenceArtifact(
        artifact_id="EV-REG-0001",
        path=str(mft_path),
        relative_path="SOFTWARE",
        size_bytes=mft_path.stat().st_size,
        sha256="b" * 64,
        artifact_type="registry",
        discovered_at_utc="2026-01-01T00:00:00Z",
    )
    with pytest.raises(ValueError, match="expected artifact_type=mft"):
        parse_mft_artifact(
            case_id="case-001",
            artifact=bad_artifact,
            runs_root=tmp_path / "runs2",
            evidence_root=mft_path.parent,
            command_config=make_config(),
            runner=fake_runner_success({}),
        )
