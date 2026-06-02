from __future__ import annotations

import json
from pathlib import Path

import pytest

from siftguard.agent.casebook import CASEBOOK_YAML_REJECTION, load_casebook

CASE_ID = "rocba-standard"


def test_committed_rocba_casebook_loads_successfully():
    casebook = load_casebook(
        Path("docs/casebooks/rocba-standard.json"),
        case_id=CASE_ID,
    )

    assert casebook.case_id == CASE_ID
    assert casebook.display_name == "ROCBA Standard Forensic Case"
    assert {fact.id for fact in casebook.case_facts} >= {
        "fred_system",
        "reported_break_in",
        "targeted_system",
    }
    assert casebook.triage_profile.keywords == ("SRL",)
    assert ".docx" in casebook.triage_profile.file_extensions
    assert {question.id for question in casebook.case_questions} >= {
        "q_when_activity",
        "q_what_was_stolen",
        "q_memory",
    }
    assert casebook.analysis_windows[0].id == "absence_window"


def test_yaml_casebook_is_rejected(tmp_path: Path):
    path = tmp_path / "casebook.yaml"
    path.write_text("case_id: rocba-standard\n", encoding="utf-8")

    with pytest.raises(ValueError, match=CASEBOOK_YAML_REJECTION):
        load_casebook(path, case_id=CASE_ID)


def test_casebook_case_id_mismatch_fails_clearly(tmp_path: Path):
    source = json.loads(Path("docs/casebooks/rocba-standard.json").read_text(encoding="utf-8"))
    source["case_id"] = "other-case"
    path = tmp_path / "casebook.json"
    path.write_text(json.dumps(source), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match case_id"):
        load_casebook(path, case_id=CASE_ID)
