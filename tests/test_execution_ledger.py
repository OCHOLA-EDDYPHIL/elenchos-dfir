from __future__ import annotations

import pytest

from elenchos.audit.execution_ledger import (
    append_event,
    make_audit_event,
    make_event_id,
    read_events,
    utc_now,
)


def test_append_and_read_one_event(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    event = make_audit_event(
        event_id=make_event_id(1),
        timestamp_utc=utc_now(),
        case_id="case1",
        tool_name="tool",
        command=["python", "--version"],
        cwd=None,
        exit_code=0,
        duration_ms=1,
        stdout_path=None,
        stderr_path=None,
        stdout_sha256=None,
        stderr_sha256=None,
        status="success",
    )
    append_event(ledger, event)

    rows = read_events(ledger)
    assert len(rows) == 1
    assert rows[0]["event_id"] == "evt_000001"


def test_append_multiple_preserves_order(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    append_event(ledger, {"event_id": "evt_000001", "status": "success"})
    append_event(ledger, {"event_id": "evt_000002", "status": "failed"})
    rows = read_events(ledger)
    assert [row["event_id"] for row in rows] == ["evt_000001", "evt_000002"]


def test_parent_directory_auto_created(tmp_path):
    ledger = tmp_path / "nested" / "ledger.jsonl"
    append_event(ledger, {"event_id": "evt_000001", "status": "success"})
    assert ledger.exists()


def test_malformed_jsonl_raises(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text('{"ok":1}\nnot-json\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Malformed JSONL at line 2"):
        read_events(ledger)


def test_make_event_id_format():
    assert make_event_id(1) == "evt_000001"
    assert make_event_id(42) == "evt_000042"


def test_make_audit_event_validates_status():
    with pytest.raises(ValueError, match="invalid audit status"):
        make_audit_event(
            event_id="evt_000001",
            timestamp_utc=utc_now(),
            case_id="case",
            tool_name="tool",
            command=["python", "--version"],
            cwd=None,
            exit_code=0,
            duration_ms=1,
            stdout_path=None,
            stderr_path=None,
            stdout_sha256=None,
            stderr_sha256=None,
            status="unknown",
        )
