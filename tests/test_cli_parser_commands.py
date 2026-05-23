from __future__ import annotations

import json

import pytest

from siftguard.cli import main
from siftguard.parser.result import ParserResult


def make_result(
    *,
    status: str = "success",
    artifact_type: str = "mft",
    parser_name: str = "mftecmd",
    source_tool: str = "MFTECmd",
) -> ParserResult:
    return ParserResult(
        case_id="case-001",
        artifact_id="EV-0001",
        artifact_type=artifact_type,
        parser_name=parser_name,
        source_tool=source_tool,
        status=status,
    )


def test_cli_help_exits_zero_and_keeps_existing_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "hash" in out
    assert "inventory" in out
    assert "audit-read" in out
    assert "parse-mft" in out
    assert "parse-registry-runkeys" in out
    assert "parse-amcache" in out


def test_parse_mft_calls_wrapper_and_prints_json(monkeypatch, tmp_path, capsys):
    from siftguard.parser import mft

    captured: dict[str, object] = {}

    def fake_parse_mft(**kwargs):
        captured.update(kwargs)
        return make_result()

    monkeypatch.setattr(mft, "parse_mft", fake_parse_mft)

    exit_code = main(
        [
            "parse-mft",
            "--case-id",
            "case-001",
            "--artifact-id",
            "EV-MFT-0001",
            "--mft-path",
            str(tmp_path / "evidence" / "mft-placeholder"),
            "--runs-root",
            str(tmp_path / "runs"),
        ]
    )

    assert exit_code == 0
    assert captured["case_id"] == "case-001"
    assert captured["artifact_id"] == "EV-MFT-0001"
    assert captured["mft_path"] == tmp_path / "evidence" / "mft-placeholder"
    assert captured["runs_root"] == tmp_path / "runs"
    payload = json.loads(capsys.readouterr().out)
    assert payload["parser_name"] == "mftecmd"
    assert payload["status"] == "success"


def test_parse_registry_runkeys_calls_wrapper(monkeypatch, tmp_path, capsys):
    from siftguard.parser import registry_runkeys

    captured: dict[str, object] = {}

    def fake_parse_registry_runkeys(**kwargs):
        captured.update(kwargs)
        return make_result(
            artifact_type="registry",
            parser_name="recmd",
            source_tool="RECmd",
        )

    monkeypatch.setattr(registry_runkeys, "parse_registry_runkeys", fake_parse_registry_runkeys)

    exit_code = main(
        [
            "parse-registry-runkeys",
            "--case-id",
            "case-001",
            "--artifact-id",
            "EV-REG-0001",
            "--hive-path",
            str(tmp_path / "evidence" / "NTUSER-placeholder"),
            "--runs-root",
            str(tmp_path / "runs"),
            "--artifact-type",
            "registry_hive",
        ]
    )

    assert exit_code == 0
    assert captured["hive_path"] == tmp_path / "evidence" / "NTUSER-placeholder"
    assert captured["artifact_type"] == "registry_hive"
    payload = json.loads(capsys.readouterr().out)
    assert payload["parser_name"] == "recmd"
    assert payload["status"] == "success"


def test_parse_amcache_calls_wrapper(monkeypatch, tmp_path, capsys):
    from siftguard.parser import amcache

    captured: dict[str, object] = {}

    def fake_parse_amcache(**kwargs):
        captured.update(kwargs)
        return make_result(
            artifact_type="amcache",
            parser_name="amcacheparser",
            source_tool="AmcacheParser",
        )

    monkeypatch.setattr(amcache, "parse_amcache", fake_parse_amcache)

    exit_code = main(
        [
            "parse-amcache",
            "--case-id",
            "case-001",
            "--artifact-id",
            "EV-AMCACHE-0001",
            "--amcache-path",
            str(tmp_path / "evidence" / "Amcache-placeholder"),
            "--runs-root",
            str(tmp_path / "runs"),
        ]
    )

    assert exit_code == 0
    assert captured["amcache_path"] == tmp_path / "evidence" / "Amcache-placeholder"
    payload = json.loads(capsys.readouterr().out)
    assert payload["parser_name"] == "amcacheparser"
    assert payload["status"] == "success"


def test_parse_command_json_out_writes_under_runs_root(monkeypatch, tmp_path, capsys):
    from siftguard.parser import mft

    monkeypatch.setattr(mft, "parse_mft", lambda **_: make_result())

    runs_root = tmp_path / "runs"
    exit_code = main(
        [
            "parse-mft",
            "--case-id",
            "case-001",
            "--artifact-id",
            "EV-MFT-0001",
            "--mft-path",
            str(tmp_path / "evidence" / "mft-placeholder"),
            "--runs-root",
            str(runs_root),
            "--json-out",
            "parser-results/result.json",
        ]
    )

    expected_path = runs_root / "parser-results" / "result.json"
    assert exit_code == 0
    assert expected_path.is_file()
    payload = json.loads(expected_path.read_text(encoding="utf-8"))
    assert payload["parser_name"] == "mftecmd"
    assert payload["status"] == "success"
    out = capsys.readouterr().out
    assert "status=success" in out
    assert f"result={expected_path.resolve()}" in out


def test_parse_command_json_out_rejects_path_outside_runs_root(monkeypatch, tmp_path, capsys):
    from siftguard.parser import mft

    monkeypatch.setattr(mft, "parse_mft", lambda **_: make_result())

    exit_code = main(
        [
            "parse-mft",
            "--case-id",
            "case-001",
            "--artifact-id",
            "EV-MFT-0001",
            "--mft-path",
            str(tmp_path / "evidence" / "mft-placeholder"),
            "--runs-root",
            str(tmp_path / "runs"),
            "--json-out",
            "../outside.json",
        ]
    )

    assert exit_code == 1
    assert "outside base" in capsys.readouterr().err


def test_parse_command_json_out_rejects_evidence_root(monkeypatch, tmp_path, capsys):
    from siftguard.parser import mft

    monkeypatch.setattr(mft, "parse_mft", lambda **_: make_result())
    evidence_root = tmp_path / "evidence"

    exit_code = main(
        [
            "parse-mft",
            "--case-id",
            "case-001",
            "--artifact-id",
            "EV-MFT-0001",
            "--mft-path",
            str(evidence_root / "mft-placeholder"),
            "--runs-root",
            str(evidence_root / "runs"),
            "--evidence-root",
            str(evidence_root),
            "--json-out",
            "result.json",
        ]
    )

    assert exit_code == 1
    assert "inside evidence root" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("status", "expected_exit_code"),
    [
        ("success", 0),
        ("partial_success", 2),
        ("skipped", 3),
        ("failed", 1),
    ],
)
def test_parse_command_exit_codes(monkeypatch, tmp_path, capsys, status, expected_exit_code):
    from siftguard.parser import amcache

    monkeypatch.setattr(
        amcache,
        "parse_amcache",
        lambda **_: make_result(
            status=status,
            artifact_type="amcache",
            parser_name="amcacheparser",
            source_tool="AmcacheParser",
        ),
    )

    exit_code = main(
        [
            "parse-amcache",
            "--case-id",
            "case-001",
            "--artifact-id",
            "EV-AMCACHE-0001",
            "--amcache-path",
            str(tmp_path / "evidence" / "Amcache-placeholder"),
            "--runs-root",
            str(tmp_path / "runs"),
        ]
    )

    assert exit_code == expected_exit_code
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == status


def test_parser_cli_help_does_not_expose_arbitrary_execution_options(capsys):
    help_texts: list[str] = []
    for command in ("parse-mft", "parse-registry-runkeys", "parse-amcache"):
        with pytest.raises(SystemExit) as exc:
            main([command, "--help"])
        assert exc.value.code == 0
        help_texts.append(capsys.readouterr().out)

    combined_help = "\n".join(help_texts)
    for forbidden in ("--command", "--cmd", "--shell", "--executable"):
        assert forbidden not in combined_help
    for forbidden in ("--bn", "--sync", "--batch-file"):
        assert forbidden not in combined_help
