from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from siftguard.evidence.manifest import EvidenceArtifact
from siftguard.parser.config import ParserCommandConfig, ParserToolCommand
from siftguard.parser.registry_runkeys import (
    NTUSER_RUN_CSV_NAME,
    NTUSER_RUNONCE_CSV_NAME,
    PARSER_NAME,
    SOFTWARE_RUN_CSV_NAME,
    SOFTWARE_RUNONCE_CSV_NAME,
    parse_registry_runkeys,
    parse_registry_runkeys_artifact,
)
from siftguard.runner.tool_result import ToolResult

FIXTURE_DIR = Path("tests/fixtures/parser_outputs/registry")


def make_hive(tmp_path: Path, name: str = "NTUSER.DAT") -> Path:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(exist_ok=True)
    hive_path = evidence_root / name
    hive_path.write_bytes(b"synthetic registry hive placeholder, not real evidence\n")
    return hive_path


def make_config(executable: str = "RECmd-test") -> ParserCommandConfig:
    return ParserCommandConfig(
        {
            "recmd": ParserToolCommand(
                parser_name="recmd",
                executable=executable,
            )
        }
    )


def fake_runner_success(captured: dict[str, object]):
    def runner(command, **kwargs):
        commands = captured.setdefault("commands", [])
        assert isinstance(commands, list)
        commands.append(tuple(command))

        output_dir = Path(command[command.index("--csv") + 1])
        csv_name = command[command.index("--csvf") + 1]
        shutil.copyfile(FIXTURE_DIR / "recmd_runkeys_valid.csv", output_dir / csv_name)

        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("synthetic stdout\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")

        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=0,
            duration_ms=11,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            stdout_sha256=None,
            stderr_sha256=None,
            status="success",
        )

    return runner


def fake_runner_failed_without_csv(captured: dict[str, object]):
    def runner(command, **kwargs):
        commands = captured.setdefault("commands", [])
        assert isinstance(commands, list)
        commands.append(tuple(command))

        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("synthetic failure\n", encoding="utf-8")
        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=8,
            duration_ms=14,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            stdout_sha256=None,
            stderr_sha256=None,
            status="failed",
        )

    return runner


def fake_runner_failed_with_csv(captured: dict[str, object]):
    def runner(command, **kwargs):
        commands = captured.setdefault("commands", [])
        assert isinstance(commands, list)
        commands.append(tuple(command))

        output_dir = Path(command[command.index("--csv") + 1])
        csv_name = command[command.index("--csvf") + 1]
        shutil.copyfile(FIXTURE_DIR / "recmd_runkeys_valid.csv", output_dir / csv_name)

        stdout_path = kwargs["stdout_path"]
        stderr_path = kwargs["stderr_path"]
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("synthetic failure\n", encoding="utf-8")
        return ToolResult(
            command=list(command),
            cwd=None,
            exit_code=8,
            duration_ms=14,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            stdout_sha256=None,
            stderr_sha256=None,
            status="failed",
        )

    return runner


def test_parse_registry_runkeys_builds_ntuser_argv_and_success_result(tmp_path):
    captured: dict[str, object] = {}
    hive_path = make_hive(tmp_path, "NTUSER.DAT")
    runs_root = tmp_path / "runs"

    result = parse_registry_runkeys(
        case_id="case-001",
        artifact_id="EV-REG-0001",
        hive_path=hive_path,
        runs_root=runs_root,
        evidence_root=hive_path.parent,
        command_config=make_config(),
        runner=fake_runner_success(captured),
    )

    output_dir = runs_root / "case-001" / "parser_outputs" / "EV-REG-0001" / "recmd"
    commands = captured["commands"]
    assert commands == [
        (
            "RECmd-test",
            "-f",
            str(hive_path),
            "--kn",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "--csv",
            str(output_dir.resolve()),
            "--csvf",
            NTUSER_RUN_CSV_NAME,
            "--nl",
        ),
        (
            "RECmd-test",
            "-f",
            str(hive_path),
            "--kn",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "--csv",
            str(output_dir.resolve()),
            "--csvf",
            NTUSER_RUNONCE_CSV_NAME,
            "--nl",
        ),
    ]
    assert isinstance(result.command, tuple)
    assert result.command == commands[0]
    assert result.parser_name == PARSER_NAME
    assert result.artifact_type == "registry"
    assert result.status == "success"
    assert result.output_dir == str(output_dir.resolve())
    assert str(output_dir / NTUSER_RUN_CSV_NAME) in result.output_files
    assert str(output_dir / NTUSER_RUNONCE_CSV_NAME) in result.output_files
    assert any(
        str((runs_root / "case-001" / "logs").resolve()) in path
        for path in result.output_files
    )
    assert result.metadata["command_count"] == 2
    assert result.metadata["successful_command_count"] == 2
    assert result.output_hashes
    assert len(result.events) == 4
    assert {event.event_type for event in result.events} == {"registry_run_key"}


def test_parse_registry_runkeys_builds_software_targets(tmp_path):
    captured: dict[str, object] = {}
    hive_path = make_hive(tmp_path, "SOFTWARE")
    runs_root = tmp_path / "runs"

    result = parse_registry_runkeys(
        case_id="case-001",
        artifact_id="EV-REG-0002",
        hive_path=hive_path,
        runs_root=runs_root,
        evidence_root=hive_path.parent,
        command_config=make_config(),
        runner=fake_runner_success(captured),
    )

    output_dir = runs_root / "case-001" / "parser_outputs" / "EV-REG-0002" / "recmd"
    commands = captured["commands"]
    assert commands[0] == (
        "RECmd-test",
        "-f",
        str(hive_path),
        "--kn",
        r"Microsoft\Windows\CurrentVersion\Run",
        "--csv",
        str(output_dir.resolve()),
        "--csvf",
        SOFTWARE_RUN_CSV_NAME,
        "--nl",
    )
    assert commands[1][commands[1].index("--csvf") + 1] == SOFTWARE_RUNONCE_CSV_NAME
    assert result.status == "success"


def test_parse_registry_runkeys_returns_failed_when_runner_fails_without_csv(tmp_path):
    captured: dict[str, object] = {}
    hive_path = make_hive(tmp_path)

    result = parse_registry_runkeys(
        case_id="case-001",
        artifact_id="EV-REG-0001",
        hive_path=hive_path,
        runs_root=tmp_path / "runs",
        evidence_root=hive_path.parent,
        command_config=make_config(),
        runner=fake_runner_failed_without_csv(captured),
    )

    assert result.status == "failed"
    assert result.events == []
    assert result.errors
    assert result.metadata["failed_command_count"] == 2
    assert any(path.endswith("_stderr.log") for path in result.output_files)


def test_parse_registry_runkeys_returns_partial_success_when_runner_fails_with_csv(tmp_path):
    captured: dict[str, object] = {}
    hive_path = make_hive(tmp_path)

    result = parse_registry_runkeys(
        case_id="case-001",
        artifact_id="EV-REG-0001",
        hive_path=hive_path,
        runs_root=tmp_path / "runs",
        evidence_root=hive_path.parent,
        command_config=make_config(),
        runner=fake_runner_failed_with_csv(captured),
    )

    assert result.status == "partial_success"
    assert result.events
    assert result.warnings
    assert result.errors
    assert result.metadata["failed_command_count"] == 2


def test_parse_registry_runkeys_returns_skipped_when_command_missing(tmp_path):
    hive_path = make_hive(tmp_path)
    config = ParserCommandConfig({})

    result = parse_registry_runkeys(
        case_id="case-001",
        artifact_id="EV-REG-0001",
        hive_path=hive_path,
        runs_root=tmp_path / "runs",
        evidence_root=hive_path.parent,
        command_config=config,
        runner=fake_runner_success({}),
    )

    assert result.status == "skipped"
    assert result.command is None
    assert result.errors


def test_parse_registry_runkeys_returns_skipped_for_unsupported_hive(tmp_path):
    hive_path = make_hive(tmp_path, "SYSTEM")

    result = parse_registry_runkeys(
        case_id="case-001",
        artifact_id="EV-REG-0001",
        hive_path=hive_path,
        runs_root=tmp_path / "runs",
        evidence_root=hive_path.parent,
        command_config=make_config(),
        runner=fake_runner_success({}),
    )

    assert result.status == "skipped"
    assert result.command is None
    assert result.errors


def test_parse_registry_runkeys_rejects_missing_input(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_registry_runkeys(
            case_id="case-001",
            artifact_id="EV-REG-0001",
            hive_path=tmp_path / "missing-hive",
            runs_root=tmp_path / "runs",
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_registry_runkeys_rejects_directory_input(tmp_path):
    hive_dir = tmp_path / "evidence"
    hive_dir.mkdir()

    with pytest.raises(ValueError, match="must be a file"):
        parse_registry_runkeys(
            case_id="case-001",
            artifact_id="EV-REG-0001",
            hive_path=hive_dir,
            runs_root=tmp_path / "runs",
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_registry_runkeys_rejects_outputs_inside_evidence_root(tmp_path):
    hive_path = make_hive(tmp_path)

    with pytest.raises(ValueError, match="inside evidence root"):
        parse_registry_runkeys(
            case_id="case-001",
            artifact_id="EV-REG-0001",
            hive_path=hive_path,
            runs_root=hive_path.parent / "runs",
            evidence_root=hive_path.parent,
            command_config=make_config(),
            runner=fake_runner_success({}),
        )


def test_parse_registry_runkeys_artifact_accepts_registry_hive_and_rejects_other_types(
    tmp_path,
):
    hive_path = make_hive(tmp_path)
    artifact = EvidenceArtifact(
        artifact_id="EV-REG-0001",
        path=str(hive_path),
        relative_path="NTUSER.DAT",
        size_bytes=hive_path.stat().st_size,
        sha256="a" * 64,
        artifact_type="registry_hive",
        discovered_at_utc="2026-01-01T00:00:00Z",
    )

    result = parse_registry_runkeys_artifact(
        case_id="case-001",
        artifact=artifact,
        runs_root=tmp_path / "runs",
        evidence_root=hive_path.parent,
        command_config=make_config(),
        runner=fake_runner_success({}),
    )
    assert result.status == "success"
    assert result.artifact_type == "registry"

    bad_artifact = EvidenceArtifact(
        artifact_id="EV-MFT-0001",
        path=str(hive_path),
        relative_path="$MFT",
        size_bytes=hive_path.stat().st_size,
        sha256="b" * 64,
        artifact_type="mft",
        discovered_at_utc="2026-01-01T00:00:00Z",
    )
    with pytest.raises(ValueError, match="expected artifact_type"):
        parse_registry_runkeys_artifact(
            case_id="case-001",
            artifact=bad_artifact,
            runs_root=tmp_path / "runs2",
            evidence_root=hive_path.parent,
            command_config=make_config(),
            runner=fake_runner_success({}),
        )
