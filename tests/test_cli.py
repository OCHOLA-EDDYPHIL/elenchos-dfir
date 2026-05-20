from __future__ import annotations

import hashlib

import pytest

from siftguard.audit.execution_ledger import append_event
from siftguard.cli import main


def test_cli_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    out = capsys.readouterr().out
    assert "siftguard" in out


def test_cli_hash(tmp_path, capsys):
    target = tmp_path / "file.bin"
    payload = b"abc"
    target.write_bytes(payload)

    exit_code = main(["hash", str(target)])
    assert exit_code == 0
    assert hashlib.sha256(payload).hexdigest() in capsys.readouterr().out


def test_cli_inventory_and_audit_read(tmp_path, capsys):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "$MFT").write_text("mft", encoding="utf-8")
    (case_dir / "SOFTWARE").write_text("hive", encoding="utf-8")

    manifest_path = tmp_path / "manifest.json"
    exit_code = main(["inventory", str(case_dir), "--manifest-out", str(manifest_path)])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "case_id=" in output
    assert "artifact_count=2" in output
    assert f"manifest={manifest_path}" in output

    ledger = tmp_path / "ledger.jsonl"
    append_event(
        ledger,
        {"event_id": "evt_000001", "status": "success", "tool_name": "x", "exit_code": 0},
    )

    exit_code = main(["audit-read", str(ledger)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "events=1" in out
    assert "evt_000001" in out
