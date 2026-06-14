from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from elenchos.correlation.event_schema import ParserEvent
from elenchos.parser.result import ParserResult


def load_validation_script() -> ModuleType:
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "validate_sift_parsers.py"
    spec = importlib.util.spec_from_file_location("validate_sift_parsers", script_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


validation_script = load_validation_script()


def make_event(
    *,
    case_id: str,
    artifact_id: str,
    artifact_type: str,
    parser_name: str,
    source_tool: str,
) -> ParserEvent:
    event_type = {
        "mftecmd": "file_record",
        "recmd": "registry_run_key",
        "amcacheparser": "amcache_execution",
    }[parser_name]
    return ParserEvent(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        parser_name=parser_name,
        source_tool=source_tool,
        event_type=event_type,
        evidence_refs=[artifact_id],
        status="normalized",
    )


def make_result(
    *,
    case_id: str,
    artifact_id: str,
    artifact_type: str,
    parser_name: str,
    source_tool: str,
    status: str = "success",
    runs_root: Path,
) -> ParserResult:
    output_dir = runs_root / case_id / "parser_outputs" / artifact_id / parser_name
    output_file = output_dir / "parser-output.csv"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file.write_text("synthetic validation output\n", encoding="utf-8")
    return ParserResult(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        parser_name=parser_name,
        source_tool=source_tool,
        status=status,
        output_dir=str(output_dir),
        output_files=[str(output_file)],
        events=[
            make_event(
                case_id=case_id,
                artifact_id=artifact_id,
                artifact_type=artifact_type,
                parser_name=parser_name,
                source_tool=source_tool,
            )
        ],
        warnings=["parser warning"] if status == "partial_success" else [],
    )


def fixed_tool_info() -> dict[str, dict[str, object]]:
    return {
        "MFTECmd": {
            "available": True,
            "path": "on PATH",
            "version": "MFTECmd 1",
            "version_exit_code": 0,
        },
        "RECmd": {
            "available": True,
            "path": "on PATH",
            "version": "RECmd 1",
            "version_exit_code": 0,
        },
        "AmcacheParser": {
            "available": True,
            "path": "on PATH",
            "version": "AmcacheParser 1",
            "version_exit_code": 0,
        },
    }


def test_arg_parser_accepts_expected_args_and_defaults(tmp_path):
    defaults = {
        "evidence_root": tmp_path / "evidence",
        "mft_path": tmp_path / "evidence" / "$MFT",
        "registry_hive_paths": [tmp_path / "evidence" / "NTUSER.DAT"],
        "amcache_path": tmp_path / "evidence" / "Amcache.hve",
    }

    args = validation_script.parse_args(
        [
            "--case-id",
            "CASE-PARSER-VALIDATION",
            "--runs-root",
            str(tmp_path / "runs"),
            "--timeout-seconds",
            "30",
        ],
        defaults,
    )

    assert args.case_id == "CASE-PARSER-VALIDATION"
    assert args.evidence_root == defaults["evidence_root"]
    assert args.mft_path == defaults["mft_path"]
    assert args.registry_hive_path == defaults["registry_hive_paths"]
    assert args.amcache_path == defaults["amcache_path"]
    assert args.timeout_seconds == 30


def test_summary_sanitization_uses_runs_relative_paths_and_basenames(tmp_path):
    runs_root = tmp_path / "runs"
    result = make_result(
        case_id="CASE-PARSER-VALIDATION",
        artifact_id="EV-MFT-VALIDATION",
        artifact_type="mft",
        parser_name="mftecmd",
        source_tool="MFTECmd",
        runs_root=runs_root,
    )

    row = validation_script.summarize_parser_result(
        result,
        runs_root=runs_root,
        audit_ledger_path=runs_root / "CASE-PARSER-VALIDATION" / "audit.jsonl",
    )

    assert row["output_dir"] == (
        "runs/CASE-PARSER-VALIDATION/parser_outputs/EV-MFT-VALIDATION/mftecmd"
    )
    assert row["output_file_basenames"] == ["parser-output.csv"]
    assert str(tmp_path) not in json.dumps(row)


def test_summary_output_path_must_resolve_under_runs_root(tmp_path):
    runs_root = tmp_path / "runs"
    evidence_root = tmp_path / "evidence"
    runs_root.mkdir()
    evidence_root.mkdir()

    resolved = validation_script.resolve_summary_out(
        Path("CASE-PARSER-VALIDATION/summary.json"),
        runs_root,
        evidence_root,
        "CASE-PARSER-VALIDATION",
    )

    assert resolved == (runs_root / "CASE-PARSER-VALIDATION" / "summary.json").resolve()


def test_summary_output_path_rejects_evidence_root(tmp_path):
    evidence_root = tmp_path / "evidence"
    runs_root = evidence_root / "runs"
    runs_root.mkdir(parents=True)

    with pytest.raises(ValueError, match="inside evidence root"):
        validation_script.resolve_summary_out(
            Path("summary.json"),
            runs_root,
            evidence_root,
            "CASE-PARSER-VALIDATION",
        )


def test_summary_output_path_must_stay_under_case_directory(tmp_path):
    runs_root = tmp_path / "runs"
    evidence_root = tmp_path / "evidence"
    runs_root.mkdir()
    evidence_root.mkdir()

    with pytest.raises(ValueError, match="runs/<case_id>"):
        validation_script.resolve_summary_out(
            Path("other-case/summary.json"),
            runs_root,
            evidence_root,
            "CASE-PARSER-VALIDATION",
        )


def test_run_validation_rejects_runs_root_inside_evidence_root(tmp_path):
    evidence_root = tmp_path / "evidence"
    runs_root = evidence_root / "runs"
    evidence_root.mkdir()
    args = validation_script.parse_args(
        [
            "--case-id",
            "CASE-PARSER-VALIDATION",
            "--runs-root",
            str(runs_root),
            "--evidence-root",
            str(evidence_root),
        ]
    )

    with pytest.raises(ValueError, match="runs_root must not be inside evidence_root"):
        validation_script.run_validation(args)


def test_missing_all_artifact_paths_writes_failure_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(validation_script, "collect_tool_info", fixed_tool_info)
    evidence_root = tmp_path / "evidence"
    runs_root = tmp_path / "runs"
    evidence_root.mkdir()
    args = validation_script.parse_args(
        [
            "--case-id",
            "CASE-PARSER-VALIDATION",
            "--runs-root",
            str(runs_root),
            "--evidence-root",
            str(evidence_root),
        ]
    )

    summary, summary_path, exit_code = validation_script.run_validation(args)

    assert exit_code == 1
    assert summary["validations"] == []
    assert summary["errors"] == ["no parser artifact paths supplied"]
    assert summary_path.is_file()


def test_fake_parser_results_produce_success_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(validation_script, "collect_tool_info", fixed_tool_info)
    evidence_root = tmp_path / "evidence"
    runs_root = tmp_path / "runs"
    evidence_root.mkdir()
    mft_path = evidence_root / "$MFT"
    hive_path = evidence_root / "NTUSER.DAT"
    amcache_path = evidence_root / "Amcache.hve"
    for path in (mft_path, hive_path, amcache_path):
        path.write_text("synthetic placeholder\n", encoding="utf-8")

    def append_audit(ledger_path: Path, tool_name: str) -> None:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"event_id": tool_name}) + "\n")

    def fake_parse_mft(**kwargs):
        append_audit(kwargs["ledger_path"], "mftecmd")
        return make_result(
            case_id=kwargs["case_id"],
            artifact_id=kwargs["artifact_id"],
            artifact_type="mft",
            parser_name="mftecmd",
            source_tool="MFTECmd",
            runs_root=kwargs["runs_root"],
        )

    def fake_parse_registry_runkeys(**kwargs):
        append_audit(kwargs["ledger_path"], "recmd")
        return make_result(
            case_id=kwargs["case_id"],
            artifact_id=kwargs["artifact_id"],
            artifact_type="registry",
            parser_name="recmd",
            source_tool="RECmd",
            runs_root=kwargs["runs_root"],
        )

    def fake_parse_amcache(**kwargs):
        append_audit(kwargs["ledger_path"], "amcacheparser")
        return make_result(
            case_id=kwargs["case_id"],
            artifact_id=kwargs["artifact_id"],
            artifact_type="amcache",
            parser_name="amcacheparser",
            source_tool="AmcacheParser",
            runs_root=kwargs["runs_root"],
        )

    monkeypatch.setattr(validation_script, "parse_mft", fake_parse_mft)
    monkeypatch.setattr(validation_script, "parse_registry_runkeys", fake_parse_registry_runkeys)
    monkeypatch.setattr(validation_script, "parse_amcache", fake_parse_amcache)

    args = validation_script.parse_args(
        [
            "--case-id",
            "CASE-PARSER-VALIDATION",
            "--runs-root",
            str(runs_root),
            "--evidence-root",
            str(evidence_root),
            "--mft-path",
            str(mft_path),
            "--registry-hive-path",
            str(hive_path),
            "--amcache-path",
            str(amcache_path),
        ]
    )

    summary, summary_path, exit_code = validation_script.run_validation(args)

    assert exit_code == 0
    assert summary["audit"]["entry_count"] == 3
    assert [row["parser_name"] for row in summary["validations"]] == [
        "mftecmd",
        "recmd",
        "amcacheparser",
    ]
    assert all(row["event_count"] == 1 for row in summary["validations"])
    assert summary_path.is_file()


def test_partial_or_failed_eventful_summary_exits_two(monkeypatch, tmp_path):
    monkeypatch.setattr(validation_script, "collect_tool_info", fixed_tool_info)
    evidence_root = tmp_path / "evidence"
    runs_root = tmp_path / "runs"
    evidence_root.mkdir()
    mft_path = evidence_root / "$MFT"
    mft_path.write_text("synthetic placeholder\n", encoding="utf-8")

    def fake_parse_mft(**kwargs):
        return make_result(
            case_id=kwargs["case_id"],
            artifact_id=kwargs["artifact_id"],
            artifact_type="mft",
            parser_name="mftecmd",
            source_tool="MFTECmd",
            status="partial_success",
            runs_root=kwargs["runs_root"],
        )

    monkeypatch.setattr(validation_script, "parse_mft", fake_parse_mft)
    args = validation_script.parse_args(
        [
            "--case-id",
            "CASE-PARSER-VALIDATION",
            "--runs-root",
            str(runs_root),
            "--evidence-root",
            str(evidence_root),
            "--mft-path",
            str(mft_path),
        ]
    )

    summary, _, exit_code = validation_script.run_validation(args)

    assert exit_code == 2
    assert summary["validations"][0]["status"] == "partial_success"


def test_generated_summary_omits_private_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(validation_script, "collect_tool_info", fixed_tool_info)
    evidence_root = tmp_path / "private-evidence-root"
    runs_root = tmp_path / "private-runs-root"
    evidence_root.mkdir()
    mft_path = evidence_root / "$MFT"
    mft_path.write_text("synthetic placeholder\n", encoding="utf-8")

    def fake_parse_mft(**kwargs):
        return make_result(
            case_id=kwargs["case_id"],
            artifact_id=kwargs["artifact_id"],
            artifact_type="mft",
            parser_name="mftecmd",
            source_tool="MFTECmd",
            runs_root=kwargs["runs_root"],
        )

    monkeypatch.setattr(validation_script, "parse_mft", fake_parse_mft)
    args = validation_script.parse_args(
        [
            "--case-id",
            "CASE-PARSER-VALIDATION",
            "--runs-root",
            str(runs_root),
            "--evidence-root",
            str(evidence_root),
            "--mft-path",
            str(mft_path),
        ]
    )

    _, summary_path, _ = validation_script.run_validation(args)
    summary_text = summary_path.read_text(encoding="utf-8")

    assert str(evidence_root) not in summary_text
    assert str(runs_root) not in summary_text
    assert str(tmp_path) not in summary_text
