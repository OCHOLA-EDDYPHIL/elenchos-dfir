from __future__ import annotations

import json
from pathlib import Path

from elenchos.integrations.rationale_trace import (
    append_jsonl,
    load_json_file,
    next_sequence_id,
    safe_read_json,
)


def test_append_jsonl_writes_compact_utf8_record(tmp_path: Path):
    path = tmp_path / "runs" / "case" / "agent-run" / "model_rationale.jsonl"

    append_jsonl(path, {"rationale_id": "rationale_000001", "phase": "validation"})

    assert path.read_text(encoding="utf-8") == (
        '{"phase":"validation","rationale_id":"rationale_000001"}\n'
    )


def test_next_sequence_id_reads_existing_jsonl_records(tmp_path: Path):
    path = tmp_path / "runs" / "case" / "agent-run" / "policy_decisions.jsonl"
    append_jsonl(path, {"policy_decision_id": "policy_000001"})
    append_jsonl(path, {"policy_decision_id": "policy_000004"})

    assert next_sequence_id("policy", path) == "policy_000005"


def test_load_and_safe_read_json(tmp_path: Path):
    path = tmp_path / "runs" / "case" / "agent-run" / "state.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"status": "ok"}), encoding="utf-8")

    assert load_json_file(path) == {"status": "ok"}
    assert safe_read_json(path) == {"status": "ok"}
    assert safe_read_json(path.with_name("missing.json")) is None
