from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from siftguard.agent.models import AgentRun, AgentRunStatus
from siftguard.agent.runner import run_agent_workflow
from siftguard.audit.execution_ledger import read_events
from siftguard.cli import main
from siftguard.evidence.manifest import EvidenceArtifact, EvidenceManifest, write_manifest

CASE_ID = "CASE-SYN-001"
SYNTHETIC_PATH = "C:\\Users\\Alice\\AppData\\Local\\Temp\\example-a.exe"
SYNTHETIC_HASH = "a" * 64
FIXED_TIME = "2026-01-01T00:00:00Z"


def fixed_clock() -> str:
    return FIXED_TIME


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact(case_dir: Path, path: Path, artifact_type: str, artifact_id: str) -> EvidenceArtifact:
    return EvidenceArtifact(
        artifact_id=artifact_id,
        path=str(path.resolve()),
        relative_path=path.relative_to(case_dir).as_posix(),
        size_bytes=path.stat().st_size,
        sha256=_sha256(path),
        artifact_type=artifact_type,
        discovered_at_utc=FIXED_TIME,
    )


def write_synthetic_manifest(tmp_path: Path) -> tuple[Path, Path, list[Path]]:
    case_dir = tmp_path / "synthetic-parser-inputs"
    case_dir.mkdir()

    mft_csv = case_dir / "mftecmd.csv"
    mft_csv.write_text(
        "\n".join(
            [
                "FullPath,FileName,Created0x10,SHA256,EntryNumber",
                f"{SYNTHETIC_PATH},example-a.exe,2026-01-01 00:00:01,{SYNTHETIC_HASH},1842",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    amcache_csv = case_dir / "amcache.csv"
    amcache_csv.write_text(
        "\n".join(
            [
                "FilePath,ProgramName,LastModifiedTimeUtc,SHA256",
                f"{SYNTHETIC_PATH},example-a.exe,2026-01-01 00:00:02,{SYNTHETIC_HASH}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    runkeys_csv = case_dir / "runkeys.csv"
    runkeys_csv.write_text(
        "\n".join(
            [
                "Hive,KeyPath,ValueName,ValueData,LastWriteTime",
                (
                    "NTUSER.DAT,"
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run,"
                    f"Example,{SYNTHETIC_PATH},2026-01-01 00:00:03"
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    artifacts = [
        _artifact(case_dir, mft_csv, "mftecmd_csv", "EV-SYN-MFT-001"),
        _artifact(case_dir, amcache_csv, "amcacheparser_csv", "EV-SYN-AMCACHE-001"),
        _artifact(case_dir, runkeys_csv, "recmd_runkeys_csv", "EV-SYN-REG-001"),
    ]
    manifest = EvidenceManifest(
        case_id=CASE_ID,
        generated_at_utc=FIXED_TIME,
        case_root=str(case_dir.resolve()),
        artifact_count=len(artifacts),
        artifacts=artifacts,
    )
    manifest_path = tmp_path / "manifest.json"
    write_manifest(manifest, manifest_path)
    return manifest_path, case_dir, [mft_csv, amcache_csv, runkeys_csv]


def test_agent_runner_completes_successful_synthetic_run(tmp_path: Path):
    manifest_path, _case_dir, source_files = write_synthetic_manifest(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID
    source_payloads = {path: path.read_bytes() for path in source_files}

    run = run_agent_workflow(
        case_id=CASE_ID,
        manifest_path=manifest_path,
        output_dir=output_dir,
        max_iterations=6,
        clock=fixed_clock,
    )

    assert run.status is AgentRunStatus.NEEDS_REVIEW
    assert [step.phase.value for step in run.steps] == [
        "inventory",
        "parse",
        "correlate",
        "validate",
        "report",
        "verify",
    ]
    assert [step.status.value for step in run.steps] == [
        "completed",
        "completed",
        "completed",
        "completed",
        "completed",
        "skipped",
    ]
    assert run.max_iterations == 6
    assert run.state.completed_steps == [
        "step_inventory",
        "step_parse",
        "step_correlate",
        "step_validate",
        "step_report",
    ]
    assert run.state.attempts == {
        "step_inventory": 1,
        "step_parse": 1,
        "step_correlate": 1,
        "step_validate": 1,
        "step_report": 1,
        "step_verify": 1,
    }
    assert "Output verification checks are deferred to issue #65." in run.warnings

    for filename in (
        "agent_run.json",
        "audit.jsonl",
        "normalized_events.json",
        "subject_timelines.json",
        "findings.json",
        "report.md",
    ):
        assert (output_dir / filename).is_file()

    normalized = json.loads((output_dir / "normalized_events.json").read_text(encoding="utf-8"))
    timelines = json.loads((output_dir / "subject_timelines.json").read_text(encoding="utf-8"))
    findings = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    agent_run = json.loads((output_dir / "agent_run.json").read_text(encoding="utf-8"))

    assert normalized["event_count"] == 4
    assert timelines["timeline_count"] == 1
    assert findings["finding_count"] == 1
    assert agent_run["status"] == "needs_review"
    assert AgentRun.from_dict(agent_run).to_dict() == agent_run
    assert "command" not in json.dumps(agent_run).lower()
    assert all((output_dir / ref).exists() for ref in agent_run["output_refs"].values())
    assert {path: path.read_bytes() for path in source_files} == source_payloads


def test_agent_runner_writes_agent_audit_events(tmp_path: Path):
    manifest_path, _case_dir, _source_files = write_synthetic_manifest(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID

    run_agent_workflow(
        case_id=CASE_ID,
        manifest_path=manifest_path,
        output_dir=output_dir,
        max_iterations=6,
        clock=fixed_clock,
    )

    events = read_events(output_dir / "audit.jsonl")
    assert [event["action"] for event in events] == [
        "agent_run_started",
        "agent_step_started",
        "agent_step_completed",
        "agent_step_started",
        "agent_step_completed",
        "agent_step_started",
        "agent_step_completed",
        "agent_step_started",
        "agent_step_completed",
        "agent_step_started",
        "agent_step_completed",
        "agent_step_started",
        "agent_step_completed",
        "agent_run_completed",
    ]
    assert [event["phase"] for event in events if event["action"] == "agent_step_started"] == [
        "inventory",
        "parse",
        "correlate",
        "validate",
        "report",
        "verify",
    ]
    assert events[-2]["status"] == "skipped"
    assert events[-1]["status"] == "needs_review"


def test_agent_runner_stops_cleanly_when_max_iterations_is_reached(tmp_path: Path):
    manifest_path, _case_dir, _source_files = write_synthetic_manifest(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID

    run = run_agent_workflow(
        case_id=CASE_ID,
        manifest_path=manifest_path,
        output_dir=output_dir,
        max_iterations=2,
        clock=fixed_clock,
    )

    assert run.status is AgentRunStatus.FAILED
    assert [step.phase.value for step in run.steps] == ["inventory", "parse"]
    assert run.errors == ["max_iterations=2 reached before phase correlate"]
    assert (output_dir / "agent_run.json").is_file()
    assert (output_dir / "audit.jsonl").is_file()
    assert not (output_dir / "subject_timelines.json").exists()
    assert read_events(output_dir / "audit.jsonl")[-1]["action"] == "agent_run_failed"


def test_agent_runner_rejects_output_dir_inside_manifest_case_root(tmp_path: Path):
    manifest_path, case_dir, _source_files = write_synthetic_manifest(tmp_path)

    with pytest.raises(ValueError, match="case_root"):
        run_agent_workflow(
            case_id=CASE_ID,
            manifest_path=manifest_path,
            output_dir=case_dir / "runs" / CASE_ID,
            max_iterations=6,
            clock=fixed_clock,
        )


def test_agent_cli_run_succeeds_with_synthetic_manifest(tmp_path: Path, capsys):
    manifest_path, _case_dir, _source_files = write_synthetic_manifest(tmp_path)
    output_dir = tmp_path / "runs" / CASE_ID

    exit_code = main(
        [
            "agent",
            "run",
            "--case-id",
            CASE_ID,
            "--manifest",
            str(manifest_path),
            "--output-dir",
            str(output_dir),
            "--max-iterations",
            "6",
        ]
    )

    assert exit_code == 0
    assert (output_dir / "agent_run.json").is_file()
    assert (output_dir / "audit.jsonl").is_file()
    out = capsys.readouterr().out
    assert "status=needs_review" in out
    assert f"agent_run={(output_dir / 'agent_run.json').resolve()}" in out


def test_agent_cli_run_fails_clearly_for_missing_manifest(tmp_path: Path, capsys):
    exit_code = main(
        [
            "agent",
            "run",
            "--case-id",
            CASE_ID,
            "--manifest",
            str(tmp_path / "missing-manifest.json"),
            "--output-dir",
            str(tmp_path / "runs" / CASE_ID),
            "--max-iterations",
            "6",
        ]
    )

    assert exit_code == 1
    assert "manifest does not exist" in capsys.readouterr().err


def test_agent_cli_help_does_not_expose_shell_execution_options(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["agent", "run", "--help"])

    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out.lower()
    assert "--manifest" in help_text
    assert "--output-dir" in help_text
    for forbidden in ("--shell", "--command", "--cmd", "--argv", "--executable"):
        assert forbidden not in help_text
