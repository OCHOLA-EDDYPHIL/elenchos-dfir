from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from siftguard.evidence.manifest import EvidenceArtifact
from siftguard.parser.amcache import (
    DEFAULT_AMCACHE_CSV_NAME,
    PARSER_NAME,
    parse_amcache,
    parse_amcache_artifact,
)
from siftguard.parser.config import ParserCommandConfig, ParserToolCommand
from siftguard.runner.tool_result import ToolResult

FIXTURE_DIR = Path("tests/fixtures/parser_outputs/amcache")


def make_amcache(tmp_path: Path) -> Path:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    amcache_path = evidence_root / "Amcache.hve"
    amcache_path.write_bytes(b"synthetic amcache placeholder, not real evidence\n")
    return amcache_path


def make_config(executable: str = "AmcacheParser-test") -> ParserCommandConfig:
    return ParserCommandConfig(
        {
            "amcacheparser": ParserToolCommand(
                parser_name="amcacheparser",
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
        shutil.copyfile(FIXTURE_DIR / "amcacheparser_valid.csv", output_dir / csv_name)

        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("synthetic stdout\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")

        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=0,
            duration_ms=13,
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
            exit_code=9,
            duration_ms=17,
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
        shutil.copyfile(FIXTURE_DIR / "amcacheparser_valid.csv", output_dir / csv_name)

        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("synthetic failure\n", encoding="utf-8")
        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=9,
            duration_ms=17,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            stdout_sha256=None,
            stderr_sha256=None,
            status="failed",
        )

    return runner


def test_parse_amcache_builds_expected_argv_and_success_result(tmp_path):
    captured: dict[str, object] = {}
    amcache_path = make_amcache(tmp_path)
    runs_root = tmp_path / "runs"

    result = parse_amcache(
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
        amcache_path=amcache_path,
        runs_root=runs_root,
        evidence_root=amcache_path.parent,
        command_config=make_config(),
        runner=fake_runner_success(captured),
    )

    output_dir = (
        runs_root / "case-001" / "parser_outputs" / "EV-AMCACHE-0001" / "amcacheparser"
    )
    command = captured["command"]
    assert command == (
        "AmcacheParser-test",
        "-f",
        str(amcache_path),
        "--csv",
        str(output_dir.resolve()),
        "--csvf",
        DEFAULT_AMCACHE_CSV_NAME,
    )
    assert isinstance(result.command, tuple)
    assert result.parser_name == PARSER_NAME
    assert result.artifact_type == "amcache"
    assert result.status == "success"
    assert result.output_dir == str(output_dir.resolve())
    assert str(output_dir / DEFAULT_AMCACHE_CSV_NAME) in result.output_files
    assert any(
        str((runs_root / "case-001" / "logs").resolve()) in path
        for path in result.output_files
    )
    assert result.output_hashes
    assert len(result.events) == 1
    assert result.events[0].event_type == "amcache_execution"


def test_parse_amcache_returns_failed_when_runner_fails_without_csv(tmp_path):
    captured: dict[str, object] = {}
    amcache_path = make_amcache(tmp_path)

    result = parse_amcache(
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
        amcache_path=amcache_path,
        runs_root=tmp_path / "runs",
        evidence_root=amcache_path.parent,
        command_config=make_config(),
        runner=fake_runner_failed_without_csv(captured),
    )

    assert result.status == "failed"
    assert result.events == []
    assert result.errors
    assert any(path.endswith("_stderr.log") for path in result.output_files)


def test_parse_amcache_returns_partial_success_when_runner_fails_with_csv(tmp_path):
    captured: dict[str, object] = {}
    amcache_path = make_amcache(tmp_path)

    result = parse_amcache(
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
        amcache_path=amcache_path,
        runs_root=tmp_path / "runs",
        evidence_root=amcache_path.parent,
        command_config=make_config(),
        runner=fake_runner_failed_with_csv(captured),
    )

    assert result.status == "partial_success"
    assert result.events
    assert result.warnings
    assert result.errors


def test_parse_amcache_returns_skipped_when_command_missing(tmp_path):
    amcache_path = make_amcache(tmp_path)
    config = ParserCommandConfig({})

    result = parse_amcache(
        case_id="case-001",
        artifact_id="EV-AMCACHE-0001",
        amcache_path=amcache_path,
        runs_root=tmp_path / "runs",
        evidence_root=amcache_path.parent,
        command_config=config,
        runner=fake_runner_success({}),
    )

    assert result.status == "skipped"
    assert result.command is None
    assert result.errors


def test_parse_amcache_rejects_missing_input(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_amcache(
            case_id="case-001",
            artifact_id="EV-AMCACHE-0001",
            amcache_path=tmp_path / "missing-amcache",
            runs_root=tmp_path / "runs",
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_amcache_rejects_directory_input(tmp_path):
    amcache_dir = tmp_path / "evidence"
    amcache_dir.mkdir()

    with pytest.raises(ValueError, match="must be a file"):
        parse_amcache(
            case_id="case-001",
            artifact_id="EV-AMCACHE-0001",
            amcache_path=amcache_dir,
            runs_root=tmp_path / "runs",
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_amcache_rejects_outputs_inside_evidence_root(tmp_path):
    amcache_path = make_amcache(tmp_path)

    with pytest.raises(ValueError, match="inside evidence root"):
        parse_amcache(
            case_id="case-001",
            artifact_id="EV-AMCACHE-0001",
            amcache_path=amcache_path,
            runs_root=amcache_path.parent / "runs",
            evidence_root=amcache_path.parent,
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_amcache_artifact_accepts_amcache_and_rejects_other_types(tmp_path):
    amcache_path = make_amcache(tmp_path)
    artifact = EvidenceArtifact(
        artifact_id="EV-AMCACHE-0001",
        path=str(amcache_path),
        relative_path="Amcache.hve",
        size_bytes=amcache_path.stat().st_size,
        sha256="a" * 64,
        artifact_type="amcache",
        discovered_at_utc="2026-01-01T00:00:00Z",
    )

    result = parse_amcache_artifact(
        case_id="case-001",
        artifact=artifact,
        runs_root=tmp_path / "runs",
        evidence_root=amcache_path.parent,
        command_config=make_config(),
        runner=fake_runner_success({}),
    )
    assert result.status == "success"

    bad_artifact = EvidenceArtifact(
        artifact_id="EV-REG-0001",
        path=str(amcache_path),
        relative_path="NTUSER.DAT",
        size_bytes=amcache_path.stat().st_size,
        sha256="b" * 64,
        artifact_type="registry_hive",
        discovered_at_utc="2026-01-01T00:00:00Z",
    )
    with pytest.raises(ValueError, match="expected artifact_type=amcache"):
        parse_amcache_artifact(
            case_id="case-001",
            artifact=bad_artifact,
            runs_root=tmp_path / "runs2",
            evidence_root=amcache_path.parent,
            command_config=make_config(),
            runner=fake_runner_success({}),
        )
