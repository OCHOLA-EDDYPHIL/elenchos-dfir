from __future__ import annotations

from pathlib import Path

from siftguard.evidence.inventory import classify_artifact
from siftguard.evidence.manifest import (
    artifact_id_for,
    build_manifest,
    read_manifest,
    write_manifest,
)


def test_artifact_id_deterministic():
    rel = "nested/$MFT"
    sha256 = "a" * 64
    first = artifact_id_for(rel, sha256)
    second = artifact_id_for(rel, sha256)
    assert first == second
    assert first.startswith("artifact_")
    assert len(first) == len("artifact_") + 16


def test_classify_artifact_expected_cases():
    cases = {
        "$MFT": "mft",
        "MFT": "mft",
        "Amcache.hve": "amcache",
        "SYSTEM": "registry_hive",
        "SOFTWARE": "registry_hive",
        "SECURITY": "registry_hive",
        "SAM": "registry_hive",
        "NTUSER.DAT": "registry_hive",
        "USRCLASS.DAT": "registry_hive",
        "Security.evtx": "evtx",
        "disk.E01": "disk_image",
        "disk.Ex01": "disk_image",
        "disk.dd": "disk_image",
        "disk.raw": "disk_image",
        "disk.img": "disk_image",
        "mem.mem": "memory_image",
        "mem.vmem": "memory_image",
        "mem.dmp": "memory_image",
        "something.bin": "unknown",
    }
    for name, expected in cases.items():
        assert classify_artifact(Path(name)) == expected


def test_build_manifest_roundtrip_and_sorting(tmp_path):
    case_dir = tmp_path / "case"
    nested = case_dir / "nested"
    nested.mkdir(parents=True)

    (nested / "z.txt").write_text("z", encoding="utf-8")
    (case_dir / "$MFT").write_text("mft", encoding="utf-8")
    (case_dir / "Amcache.hve").write_text("ac", encoding="utf-8")

    manifest = build_manifest(case_dir, case_id="case_demo_001")
    assert manifest.case_id == "case_demo_001"
    assert manifest.case_root == str(case_dir.resolve())
    assert manifest.artifact_count == len(manifest.artifacts)
    assert manifest.generated_at_utc.endswith("Z")

    rel_paths = [artifact.relative_path for artifact in manifest.artifacts]
    assert rel_paths == sorted(rel_paths)

    manifest_path = tmp_path / "manifest.json"
    write_manifest(manifest, manifest_path)
    loaded = read_manifest(manifest_path)

    assert loaded.case_id == manifest.case_id
    assert loaded.case_root == manifest.case_root
    assert loaded.artifact_count == manifest.artifact_count
    assert [a.relative_path for a in loaded.artifacts] == rel_paths


def test_manifest_accepts_optional_source_image_fields(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    artifact_path = case_dir / "$MFT"
    artifact_path.write_text("mft", encoding="utf-8")

    manifest = build_manifest(case_dir, case_id="case_demo_001")
    manifest.artifacts[0].source_image_id = "primary"
    manifest.artifacts[0].source_image_label = "primary-base-dc-cdrive"
    manifest_path = tmp_path / "manifest.json"
    write_manifest(manifest, manifest_path)

    loaded = read_manifest(manifest_path)

    assert loaded.artifacts[0].source_image_id == "primary"
    assert loaded.artifacts[0].source_image_label == "primary-base-dc-cdrive"
