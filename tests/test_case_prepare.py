from __future__ import annotations

import json
from pathlib import Path

import pytest

from siftguard.audit.execution_ledger import read_events
from siftguard.case_prep.extractors import (
    SUPPORTED_TARGETS,
    FixtureExtractor,
    _profile_ntuser_targets,
    _target_matches,
)
from siftguard.case_prep.models import ArtifactTarget, ExtractionOutcome
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


def profile_ntuser_target(profile_id: str) -> ArtifactTarget:
    return ArtifactTarget(
        target_id=f"ntuser_{profile_id.replace('-', '_')}",
        artifact_type="registry_hive",
        display_name="NTUSER.DAT",
        output_path=f"extracted/registry/profiles/{profile_id}/NTUSER.DAT",
        candidate_paths=("Users/*/NTUSER.DAT",),
        registry_hive_type="ntuser",
        profile_id=profile_id,
        profile_display_name=profile_id,
        sanitized_profile_hint=profile_id,
        source_candidate_ref=f"Users/{profile_id}/NTUSER.DAT",
    )


class MultiProfileFixtureExtractor:
    def __init__(self, *, failed_profile_ids: set[str] | None = None) -> None:
        self.failed_profile_ids = failed_profile_ids or set()

    def extract(self, context) -> list[ExtractionOutcome]:
        outcomes: list[ExtractionOutcome] = []
        for target_id, relative_path in (
            ("mft", "extracted/mft/$MFT"),
            ("software", "extracted/registry/SOFTWARE"),
            ("amcache", "extracted/amcache/Amcache.hve"),
        ):
            target = next(item for item in SUPPORTED_TARGETS if item.target_id == target_id)
            output_path = context.output_dir / relative_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(f"fixture-{target_id}".encode("utf-8"))
            outcomes.append(
                ExtractionOutcome(
                    target=target,
                    status="available",
                    extraction_method="fixture_copy",
                )
            )
        for profile_id in ("profile-0001", "profile-0002"):
            target = profile_ntuser_target(profile_id)
            if profile_id in self.failed_profile_ids:
                outcomes.append(
                    ExtractionOutcome(
                        target=target,
                        status="extraction_failed",
                        extraction_method=f"fixture_copy:{target.source_candidate_ref}",
                        reason="extraction_failed",
                        warnings=[f"fixture extraction failed for {profile_id}"],
                    )
                )
                continue
            output_path = context.output_dir / target.output_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(f"fixture-{profile_id}".encode("utf-8"))
            outcomes.append(
                ExtractionOutcome(
                    target=target,
                    status="available",
                    extraction_method=f"fixture_copy:{target.source_candidate_ref}",
                )
            )
        return outcomes


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


def test_amcache_transaction_log_candidates_are_discovered():
    matches = _target_matches(
        [
            ("10", "Windows/AppCompat/Programs/Amcache.hve"),
            ("11", "Windows/AppCompat/Programs/Amcache.hve.LOG1"),
            ("12", "Windows/AppCompat/Programs/Amcache.hve.LOG2"),
        ]
    )

    assert matches["amcache"] == ("10", "Windows/AppCompat/Programs/Amcache.hve")
    assert matches["amcache_log1"] == (
        "11",
        "Windows/AppCompat/Programs/Amcache.hve.LOG1",
    )
    assert matches["amcache_log2"] == (
        "12",
        "Windows/AppCompat/Programs/Amcache.hve.LOG2",
    )


def test_case_prepare_stages_amcache_transaction_log_sidecars(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)
    fixtures = write_fixture_artifacts(tmp_path / "fixtures")
    fixtures["amcache_log1"] = tmp_path / "fixtures" / "Amcache.hve.LOG1"
    fixtures["amcache_log2"] = tmp_path / "fixtures" / "Amcache.hve.LOG2"
    fixtures["amcache_log1"].write_bytes(b"synthetic-log1")
    fixtures["amcache_log2"].write_bytes(b"synthetic-log2")

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=source_manifest_path(tmp_path, manifest),
        output_dir=output_dir(tmp_path),
        extractor=FixtureExtractor(fixtures),
        clock=fixed_clock,
    )
    payload = json.loads(result.case_prep_path.read_text(encoding="utf-8"))
    amcache = next(
        artifact
        for artifact in payload["prepared_artifacts"]
        if artifact["artifact_type"] == "amcache_hive"
    )

    assert {sidecar["display_name"] for sidecar in amcache["sidecars"]} == {
        "Amcache.hve.LOG1",
        "Amcache.hve.LOG2",
    }
    assert {sidecar["status"] for sidecar in amcache["sidecars"]} == {"available"}
    assert all(sidecar["sha256"] for sidecar in amcache["sidecars"])
    assert all(sidecar["hash_status"] == "computed" for sidecar in amcache["sidecars"])
    assert (result.output_dir / "extracted/amcache/Amcache.hve.LOG1").is_file()
    assert (result.output_dir / "extracted/amcache/Amcache.hve.LOG2").is_file()


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
        if gap.artifact_type == "ntuser_hive" and "NTUSER" in gap.impact
    ]
    assert len(ntuser_gaps) == 1
    assert ntuser_gaps[0].reason == "not_found"


def test_profile_ntuser_candidate_discovery_uses_sanitized_targets():
    targets = _profile_ntuser_targets(
        [
            ("11", "Users/Alpha/NTUSER.DAT"),
            ("12", "Users/Alpha/AppData/Roaming/NTUSER.DAT"),
            ("13", "Users/Beta/NTUSER.DAT"),
            ("14", "Windows/System32/config/NTUSER.DAT"),
        ]
    )

    assert [target.profile_id for target, _inode, _path in targets] == [
        "profile-0001",
        "profile-0002",
    ]
    assert [target.output_path for target, _inode, _path in targets] == [
        "extracted/registry/profiles/profile-0001/NTUSER.DAT",
        "extracted/registry/profiles/profile-0002/NTUSER.DAT",
    ]
    assert all(
        "Alpha" not in target.output_path
        and "Beta" not in target.output_path
        and "Alpha" not in (target.source_candidate_ref or "")
        and "Beta" not in (target.source_candidate_ref or "")
        for target, _inode, _path in targets
    )


def test_case_prepare_stages_multiple_profile_ntuser_hives(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=source_manifest_path(tmp_path, manifest),
        output_dir=output_dir(tmp_path),
        extractor=MultiProfileFixtureExtractor(),
        clock=fixed_clock,
    )
    payload = json.loads(result.case_prep_path.read_text(encoding="utf-8"))
    ntuser_artifacts = [
        artifact
        for artifact in payload["prepared_artifacts"]
        if artifact.get("registry_hive_type") == "ntuser"
    ]

    assert len(ntuser_artifacts) == 2
    assert {artifact["profile_id"] for artifact in ntuser_artifacts} == {
        "profile-0001",
        "profile-0002",
    }
    assert {artifact["status"] for artifact in ntuser_artifacts} == {"available"}
    assert all(artifact["parser_eligible"] is True for artifact in ntuser_artifacts)
    assert {
        artifact["path"] for artifact in ntuser_artifacts
    } == {
        "extracted/registry/profiles/profile-0001/NTUSER.DAT",
        "extracted/registry/profiles/profile-0002/NTUSER.DAT",
    }
    assert all("Alpha" not in json.dumps(artifact) for artifact in ntuser_artifacts)
    assert all("Beta" not in json.dumps(artifact) for artifact in ntuser_artifacts)


def test_profile_ntuser_extraction_failure_is_gap_not_blocking(tmp_path: Path):
    source_root = tmp_path / "evidence" / "rocba"
    write_sources(source_root)
    manifest = discover_source_root(case_id=CASE_ID, source_root=source_root, clock=fixed_clock)

    result = prepare_case(
        case_id=CASE_ID,
        source_manifest_path=source_manifest_path(tmp_path, manifest),
        output_dir=output_dir(tmp_path),
        extractor=MultiProfileFixtureExtractor(failed_profile_ids={"profile-0002"}),
        clock=fixed_clock,
    )

    artifacts = result.manifest.prepared_artifacts
    by_profile = {
        artifact.profile_id: artifact
        for artifact in artifacts
        if artifact.registry_hive_type == "ntuser"
    }
    assert by_profile["profile-0001"].status == "available"
    assert by_profile["profile-0002"].status == "extraction_failed"
    assert by_profile["profile-0002"].parser_eligible is False
    gaps = [
        gap
        for gap in result.manifest.coverage_gaps
        if gap.profile_id == "profile-0002"
    ]
    assert len(gaps) == 1
    assert gaps[0].artifact_type == "ntuser_hive"
    assert gaps[0].reason == "extraction_failed"


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
