from __future__ import annotations

import json
from pathlib import Path

import pytest

from siftguard.audit.execution_ledger import read_events
from siftguard.case_prep.extractors import SUPPORTED_TARGETS, FixtureExtractor
from siftguard.case_prep.prepare import prepare_case
from siftguard.case_prep.source_discovery import (
    discover_source_root,
    read_source_manifest,
    write_source_manifest,
)
from siftguard.cli import main

CASE_ID = "rocba-standard"
FIXED_TIME = "2026-01-01T00:00:00Z"


def fixed_clock() -> str:
    return FIXED_TIME


def write_sources(root: Path) -> None:
    (root / "memory").mkdir(parents=True)
    (root / "rocba-cdrive.e01").write_bytes(b"fake ewf")
    (root / "memory" / "Rocba-Memory.raw").write_bytes(b"fake memory")
    (root / "ROCBA-BACKGROUND.pptx").write_bytes(b"fake pptx")


def write_fixture_artifacts(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True)
    files = {
        "mft": root / "MFT.fixture",
        "software": root / "SOFTWARE.fixture",
        "ntuser": root / "NTUSER.fixture",
        "amcache": root / "Amcache.fixture",
    }
    for target_id, path in files.items():
        path.write_bytes(f"fixture-{target_id}".encode("utf-8"))
    return files


def source_manifest_path(tmp_path: Path, manifest) -> Path:
    path = tmp_path / ".local" / "cases" / CASE_ID / "source-manifest.json"
    write_source_manifest(manifest, path, include_local_paths=True)
    return path


def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "runs" / CASE_ID / "case-prep"


def test_source_root_discovery_detects_disk_memory_and_pptx(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)

    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    by_name = {source.display_name: source for source in manifest.sources}

    assert by_name["rocba-cdrive.e01"].role == "disk_image"
    assert by_name["rocba-cdrive.e01"].kind == "ewf_e01"
    assert by_name["Rocba-Memory.raw"].role == "memory_image"
    assert by_name["Rocba-Memory.raw"].status == "staged_not_analyzed"
    assert by_name["ROCBA-BACKGROUND.pptx"].role == "case_background"


def test_source_root_prepare_writes_json_source_manifest(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest_out = tmp_path / ".local" / "cases" / CASE_ID / "source-manifest.json"

    result = prepare_case(
        case_id=CASE_ID,
        source_root=source_root,
        source_manifest_out=manifest_out,
        output_dir=output_dir(tmp_path),
        extractor=FixtureExtractor({}),
        clock=fixed_clock,
    )

    assert manifest_out.is_file()
    payload = json.loads(manifest_out.read_text(encoding="utf-8"))
    assert payload["case_id"] == CASE_ID
    assert payload["source_count"] == 3
    assert result.source_manifest_path.is_file()
    sanitized = json.loads(result.source_manifest_path.read_text(encoding="utf-8"))
    assert "source_root" not in sanitized
    assert "local_path" not in json.dumps(sanitized)


def test_source_manifest_input_mode_works(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    manifest_path = source_manifest_path(tmp_path, manifest)
    fixture_files = write_fixture_artifacts(tmp_path / "fixtures")

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=manifest_path,
        output_dir=output_dir(tmp_path),
        extractor=FixtureExtractor(fixture_files),
        clock=fixed_clock,
    )

    assert result.manifest.status == "completed"
    assert len(result.manifest.prepared_artifacts) == 4
    assert (result.output_dir / "case_prep.json").is_file()


def test_source_root_and_source_manifest_conflict_handling(tmp_path: Path, capsys):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    manifest_path = source_manifest_path(tmp_path, manifest)

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "case",
                "prepare",
                "--case-id",
                CASE_ID,
                "--source-root",
                str(source_root),
                "--source-manifest",
                str(manifest_path),
                "--output-dir",
                str(output_dir(tmp_path)),
            ]
        )

    assert exc.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_output_dir_outside_allowed_roots_is_rejected(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)

    with pytest.raises(ValueError, match="ignored generated output path"):
        prepare_case(
            case_id=CASE_ID,
            source_manifest_path=source_manifest_path(tmp_path, manifest),
            output_dir=tmp_path / "case-prep",
            extractor=FixtureExtractor({}),
            clock=fixed_clock,
        )


def test_output_dir_under_mnt_evidence_is_rejected(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)

    with pytest.raises(ValueError, match="evidence root"):
        prepare_case(
            case_id=CASE_ID,
            source_manifest_path=source_manifest_path(tmp_path, manifest),
            output_dir=Path("/mnt/evidence/runs/rocba-standard/case-prep"),
            extractor=FixtureExtractor({}),
            clock=fixed_clock,
        )


def test_output_dir_under_source_root_is_rejected(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)

    with pytest.raises(ValueError, match="source root"):
        prepare_case(
            case_id=CASE_ID,
            source_root=source_root,
            source_manifest_out=tmp_path / ".local" / "cases" / CASE_ID / "source-manifest.json",
            output_dir=source_root / "runs" / CASE_ID,
            extractor=FixtureExtractor({}),
            clock=fixed_clock,
        )


def test_memory_image_is_inventoried_but_out_of_scope(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)

    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    memory = next(source for source in manifest.sources if source.role == "memory_image")

    assert memory.status == "staged_not_analyzed"
    assert memory.analysis_scope == "out_of_scope_for_final_submission"


def test_disk_first_amcache_target_is_represented():
    amcache_target = next(target for target in SUPPORTED_TARGETS if target.target_id == "amcache")

    assert amcache_target.candidate_paths == ("Windows/AppCompat/Programs/Amcache.hve",)


def test_missing_amcache_becomes_coverage_gap(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    fixtures = write_fixture_artifacts(tmp_path / "fixtures")
    fixtures.pop("amcache")

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=source_manifest_path(tmp_path, manifest),
        output_dir=output_dir(tmp_path),
        extractor=FixtureExtractor(fixtures),
        clock=fixed_clock,
    )

    gaps = [gap for gap in result.manifest.coverage_gaps if gap.artifact_type == "amcache_hive"]
    assert len(gaps) == 1
    assert gaps[0].reason == "not_found"
    assert "Windows/AppCompat/Programs/Amcache.hve" in gaps[0].recommended_next_step


def test_missing_ntuser_becomes_coverage_gap(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    fixtures = write_fixture_artifacts(tmp_path / "fixtures")
    fixtures.pop("ntuser")

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=source_manifest_path(tmp_path, manifest),
        output_dir=output_dir(tmp_path),
        extractor=FixtureExtractor(fixtures),
        clock=fixed_clock,
    )

    ntuser_gaps = [
        gap
        for gap in result.manifest.coverage_gaps
        if gap.artifact_type == "registry_hive" and "NTUSER" in gap.impact
    ]
    assert len(ntuser_gaps) == 1
    assert ntuser_gaps[0].reason == "not_found"


def test_successful_fixture_extraction_writes_case_prep_json(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    fixtures = write_fixture_artifacts(tmp_path / "fixtures")

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=source_manifest_path(tmp_path, manifest),
        output_dir=output_dir(tmp_path),
        extractor=FixtureExtractor(fixtures),
        clock=fixed_clock,
    )
    payload = json.loads(result.case_prep_path.read_text(encoding="utf-8"))

    assert payload["case_id"] == CASE_ID
    assert payload["status"] == "completed"
    assert len(payload["prepared_artifacts"]) == 4
    assert {artifact["status"] for artifact in payload["prepared_artifacts"]} == {"available"}
    assert all(artifact["sha256"] for artifact in payload["prepared_artifacts"])


def test_extraction_audit_jsonl_is_written(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=source_manifest_path(tmp_path, manifest),
        output_dir=output_dir(tmp_path),
        extractor=FixtureExtractor({}),
        clock=fixed_clock,
    )

    events = read_events(result.extraction_audit_path)
    assert [event["event_type"] for event in events][0] == "case_prepare_started"
    assert [event["event_type"] for event in events][-1] == "case_prepare_completed"
    assert any(event["event_type"] == "artifact_prepared" for event in events)


def test_case_prepare_help_has_no_arbitrary_shell_interface(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["case", "prepare", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "--source-root" in help_text
    assert "--source-manifest" in help_text
    assert "Memory" in help_text
    assert "sources are inventoried only" in help_text
    assert "Generated outputs go under ignored run paths" in help_text
    for forbidden in ("--command", "--shell", "--executable"):
        assert forbidden not in help_text


def test_runtime_output_uses_source_ids_for_provenance(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    fixtures = write_fixture_artifacts(tmp_path / "fixtures")

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=source_manifest_path(tmp_path, manifest),
        output_dir=output_dir(tmp_path),
        extractor=FixtureExtractor(fixtures),
        clock=fixed_clock,
    )
    payload = json.loads(result.case_prep_path.read_text(encoding="utf-8"))
    source_ids = {source["source_id"] for source in payload["sources"]}

    assert source_ids
    assert all(artifact["source_id"] in source_ids for artifact in payload["prepared_artifacts"])
    assert all(
        artifact["source_role"] == "disk_image"
        for artifact in payload["prepared_artifacts"]
    )
    assert "/mnt/evidence" not in json.dumps(payload)
    assert ".local/" not in json.dumps(payload)


def test_yaml_source_manifest_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="YAML source manifests are not supported"):
        read_source_manifest(tmp_path / "source-manifest.yaml")
