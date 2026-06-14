from __future__ import annotations

import json
from pathlib import Path

import pytest

from elenchos.agent.casebook import CASEBOOK_YAML_REJECTION, load_casebook

CASE_ID = "rocba-standard"
GENERIC_CASE_ID = "generic-windows-disk-triage"
GENERIC_CASEBOOK_PATH = Path("docs/casebooks/generic-windows-disk-triage.json")
ROCBA_QUESTION_IDS = {
    "q_what_was_stolen",
    "q_where_transferred",
    "q_how_stolen",
    "q_memory",
}


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
    assert casebook.claim_boundaries[0].claim_area == "theft/exfiltration"
    assert casebook.claim_boundaries[0].question_ids == (
        "q_what_was_stolen",
        "q_where_transferred",
        "q_how_stolen",
    )
    assert casebook.claim_boundaries[0].related_question_ids == ("q_memory",)
    assert casebook.reusable_template is False


def test_committed_generic_windows_disk_triage_casebook_loads_as_reusable_template():
    casebook = load_casebook(
        GENERIC_CASEBOOK_PATH,
        case_id="storyless-image-001",
    )

    assert casebook.case_id == GENERIC_CASE_ID
    assert casebook.display_name == "Generic Windows Disk Triage"
    assert casebook.reusable_template is True
    assert casebook.claim_boundaries == ()
    assert not (ROCBA_QUESTION_IDS & {question.id for question in casebook.case_questions})
    assert {question.id for question in casebook.case_questions} >= {
        "q_supported_artifact_families",
        "q_mft_timeline_activity",
        "q_registry_runonce_entries",
        "q_amcache_program_presence",
        "q_ntuser_user_activity",
        "q_findings_requiring_review",
        "q_outside_current_scope",
    }


def test_generic_windows_disk_triage_casebook_text_is_conservative():
    payload = json.loads(GENERIC_CASEBOOK_PATH.read_text(encoding="utf-8"))
    text = json.dumps(payload, sort_keys=True).casefold()

    forbidden = (
        "theft",
        "exfiltration",
        "apt",
        "attribution",
        "confirmed compromise",
    )
    assert not any(term in text for term in forbidden)


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


def test_normal_casebook_does_not_allow_reusable_template_mismatch(tmp_path: Path):
    source = json.loads(Path("docs/casebooks/rocba-standard.json").read_text(encoding="utf-8"))
    assert source.get("reusable_template") is not True
    path = tmp_path / "casebook.json"
    path.write_text(json.dumps(source), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match case_id"):
        load_casebook(path, case_id="storyless-image-001")


def test_casebook_reusable_template_must_be_boolean(tmp_path: Path):
    source = json.loads(GENERIC_CASEBOOK_PATH.read_text(encoding="utf-8"))
    source["reusable_template"] = "true"
    path = tmp_path / "casebook.json"
    path.write_text(json.dumps(source), encoding="utf-8")

    with pytest.raises(ValueError, match="reusable_template must be a boolean"):
        load_casebook(path, case_id="storyless-image-001")


def test_casebook_claim_boundary_rejects_unknown_question_id(tmp_path: Path):
    source = json.loads(Path("docs/casebooks/rocba-standard.json").read_text(encoding="utf-8"))
    source["claim_boundaries"][0]["question_ids"] = ["q_missing"]
    path = tmp_path / "casebook.json"
    path.write_text(json.dumps(source), encoding="utf-8")

    with pytest.raises(ValueError, match="references unknown case question"):
        load_casebook(path, case_id=CASE_ID)
