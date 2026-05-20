from __future__ import annotations

from siftguard.audit.execution_ledger import append_event, read_events


def test_append_and_read_events(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    append_event(ledger, {"event_id": "evt-000001", "event_type": "x"})
    append_event(ledger, {"event_id": "evt-000002", "event_type": "y"})

    rows = read_events(ledger)
    assert len(rows) == 2
    assert rows[0]["event_id"] == "evt-000001"
    assert rows[1]["event_id"] == "evt-000002"
