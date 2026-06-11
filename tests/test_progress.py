from __future__ import annotations

import json
from pathlib import Path

import pytest

from siftguard.progress import (
    append_progress_event,
    make_progress_event,
    read_progress_events,
)

CASE_ID = "CASE-PROGRESS-001"
FIXED_TIME = "2026-01-01T00:00:00Z"


def test_progress_event_jsonl_schema(tmp_path: Path):
    progress_path = tmp_path / "runs" / CASE_ID / "progress.jsonl"

    append_progress_event(
        progress_path,
        case_id=CASE_ID,
        phase="normalize/select",
        status="completed",
        message="normalize/select completed with 3 selected event(s)",
        timestamp=FIXED_TIME,
    )

    payload = json.loads(progress_path.read_text(encoding="utf-8"))
    assert set(payload) == {"timestamp", "case_id", "phase", "status", "message"}
    assert payload == {
        "timestamp": FIXED_TIME,
        "case_id": CASE_ID,
        "phase": "normalize/select",
        "status": "completed",
        "message": "normalize/select completed with 3 selected event(s)",
    }
    assert read_progress_events(progress_path)[0].to_dict() == payload


def test_progress_rejects_invalid_phase():
    with pytest.raises(ValueError, match="invalid progress phase"):
        make_progress_event(
            case_id=CASE_ID,
            phase="parse_everything",
            status="completed",
            message="completed",
            timestamp=FIXED_TIME,
        )


@pytest.mark.parametrize(
    "message",
    [
        "hash sha256:" + ("a" * 64),
        "api_key present",
        '{"raw":"row"}',
        "a,b,c,d",
    ],
)
def test_progress_rejects_unsafe_messages(message: str):
    with pytest.raises(ValueError):
        make_progress_event(
            case_id=CASE_ID,
            phase="report",
            status="completed",
            message=message,
            timestamp=FIXED_TIME,
        )


def test_read_progress_rejects_malformed_rows(tmp_path: Path):
    progress_path = tmp_path / "progress.jsonl"
    progress_path.write_text("[]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not an object"):
        read_progress_events(progress_path)
