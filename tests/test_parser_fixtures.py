from __future__ import annotations

import csv
from pathlib import Path

FIXTURE_ROOT = Path("tests/fixtures/parser_outputs")


def test_parser_fixture_readme_exists():
    readme = FIXTURE_ROOT / "README.md"

    assert readme.is_file()
    text = readme.read_text(encoding="utf-8").lower()
    assert "synthetic" in text
    assert "not real evidence" in text


def test_synthetic_fixture_directories_exist():
    for name in ("mft", "registry", "amcache"):
        assert (FIXTURE_ROOT / name).is_dir()


def test_synthetic_fixture_files_exist_and_are_consumable():
    expected_files = [
        FIXTURE_ROOT / "mft" / "mftecmd_valid.csv",
        FIXTURE_ROOT / "mft" / "mftecmd_malformed.csv",
        FIXTURE_ROOT / "registry" / "recmd_runkeys_valid.csv",
        FIXTURE_ROOT / "registry" / "recmd_runkeys_malformed.csv",
        FIXTURE_ROOT / "amcache" / "amcacheparser_valid.csv",
        FIXTURE_ROOT / "amcache" / "amcacheparser_malformed.csv",
    ]

    for fixture in expected_files:
        assert fixture.is_file()
        with fixture.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        assert rows, f"{fixture} should contain at least one synthetic data row"


def test_synthetic_fixture_files_do_not_contain_private_markers():
    forbidden_markers = [
        "/home/",
        "private-host",
        "private-user",
    ]

    for fixture in FIXTURE_ROOT.rglob("*"):
        if fixture.is_file():
            text = fixture.read_text(encoding="utf-8").lower()
            for marker in forbidden_markers:
                assert marker not in text
