from __future__ import annotations

from pathlib import Path

import pytest

from siftguard.parser.paths import (
    build_parser_logs_dir,
    build_parser_normalized_dir,
    build_parser_output_dir,
    ensure_parser_output_dir,
)


def test_parser_output_path_convention(tmp_path):
    runs_root = tmp_path / "runs"

    output_dir = build_parser_output_dir(
        runs_root,
        "case-001",
        "EV-MFT-0001",
        "mftecmd",
    )

    assert output_dir == (
        runs_root / "case-001" / "parser_outputs" / "EV-MFT-0001" / "mftecmd"
    ).resolve()
    assert not output_dir.exists()


def test_ensure_parser_output_dir_creates_directory(tmp_path):
    output_dir = ensure_parser_output_dir(
        tmp_path / "runs",
        "case-001",
        "EV-REG-0001",
        "recmd",
    )

    assert output_dir.is_dir()


def test_parser_logs_and_normalized_dirs(tmp_path):
    runs_root = tmp_path / "runs"

    assert build_parser_logs_dir(runs_root, "case-001") == (
        runs_root / "case-001" / "logs"
    ).resolve()
    assert build_parser_normalized_dir(runs_root, "case-001") == (
        runs_root / "case-001" / "normalized"
    ).resolve()


@pytest.mark.parametrize(
    "bad_value",
    [
        "../case",
        "case/evil",
        r"case\evil",
        "EV-MFT-0001/../../x",
        "/tmp/case",
        "",
        "case;rm -rf",
        "case|cat",
        "case$HOME",
        "case\x00id",
    ],
)
def test_parser_output_path_rejects_unsafe_identifiers(tmp_path, bad_value):
    with pytest.raises((TypeError, ValueError)):
        build_parser_output_dir(tmp_path / "runs", bad_value, "EV-MFT-0001", "mftecmd")


def test_parser_output_path_rejects_evidence_root(tmp_path):
    evidence_root = tmp_path / "cases"
    runs_root = evidence_root / "runs"

    with pytest.raises(ValueError, match="inside evidence root"):
        build_parser_output_dir(
            runs_root,
            "case-001",
            "EV-MFT-0001",
            "mftecmd",
            evidence_root=evidence_root,
        )


def test_parser_output_path_accepts_path_object_runs_root(tmp_path):
    output_dir = build_parser_output_dir(
        Path(tmp_path / "runs"),
        "case-001",
        "EV-AMCACHE-0001",
        "amcacheparser",
    )

    assert output_dir.name == "amcacheparser"
