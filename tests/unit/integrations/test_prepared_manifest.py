from __future__ import annotations

import json
from pathlib import Path

import pytest

from elenchos.integrations.prepared_manifest import (
    resolve_prepared_manifest_path,
    validate_prepared_manifest_for_run,
)


def _write_case_prep(path: Path, *, supported: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    prepared_artifacts = []
    if supported:
        artifact = path.parent / "extracted" / "mft" / "$MFT"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b"mft")
        prepared_artifacts.append(
            {
                "artifact_id": "prep_mft",
                "artifact_type": "mft",
                "parser_eligible": True,
                "path": "extracted/mft/$MFT",
                "source_id": "src1",
                "status": "available",
            }
        )
    path.write_text(
        json.dumps(
            {
                "case_id": "case",
                "coverage_gaps": [],
                "prepared_artifacts": prepared_artifacts,
                "sources": [
                    {
                        "analysis_scope": "primary",
                        "display_name": "source.E01",
                        "kind": "ewf_e01",
                        "role": "disk_image",
                        "source_id": "src1",
                        "status": "available",
                    }
                ],
                "warnings": [],
            }
        ),
        encoding="utf-8",
    )


def test_resolve_prepared_manifest_finds_prep_default(tmp_path: Path):
    output_dir = tmp_path / "runs" / "case" / "run"
    case_prep = tmp_path / "runs" / "case" / "prep" / "case_prep.json"
    _write_case_prep(case_prep)

    assert resolve_prepared_manifest_path(output_dir=output_dir) == case_prep.resolve()


def test_validate_prepared_manifest_accepts_supported_case_prep(tmp_path: Path):
    case_prep = tmp_path / "runs" / "case" / "prep" / "case_prep.json"
    _write_case_prep(case_prep)

    result = validate_prepared_manifest_for_run(case_prep)

    assert result.case_id == "case"
    assert result.supported_artifact_count == 1
    assert result.readable_artifact_count == 1


def test_validate_prepared_manifest_rejects_integrity_manifest(tmp_path: Path):
    bad = tmp_path / "runs" / "case" / "run" / "run_integrity_manifest.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a prepared case manifest"):
        validate_prepared_manifest_for_run(bad)


def test_validate_prepared_manifest_rejects_unsupported_only_manifest(tmp_path: Path):
    case_prep = tmp_path / "runs" / "case" / "prep" / "case_prep.json"
    _write_case_prep(case_prep, supported=False)

    with pytest.raises(ValueError, match="contains no supported prepared artifacts"):
        validate_prepared_manifest_for_run(case_prep)
