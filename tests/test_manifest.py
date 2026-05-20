from __future__ import annotations

from siftguard.evidence.manifest import artifact_id_for, build_manifest


def test_build_manifest_records_expected_fields(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    artifact = case_dir / "$MFT"
    artifact.write_text("abc", encoding="utf-8")

    manifest = build_manifest(case_dir)
    assert manifest.case_dir == str(case_dir.resolve())
    assert len(manifest.artifacts) == 1

    entry = manifest.artifacts[0]
    assert entry.relative_path == "$MFT"
    assert entry.size_bytes == 3
    assert len(entry.sha256) == 64
    assert entry.artifact_id == artifact_id_for(entry.relative_path, entry.sha256)
