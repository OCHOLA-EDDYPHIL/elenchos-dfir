from __future__ import annotations

import json
from pathlib import Path

from siftguard.cli import main

CASE_ID = "CASE-SYN-001"
SYNTHETIC_PATH = "C:/Users/Alice/AppData/Local/Temp/example-a.exe"


def synthetic_input(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "case_id": CASE_ID,
                "events": [
                    {
                        "event_type": "drop",
                        "timestamp": "2026-01-01T00:00:01Z",
                        "subject": SYNTHETIC_PATH,
                        "source": "mft",
                        "path": SYNTHETIC_PATH,
                        "basename": "example-a.exe",
                        "details": {"detail": "synthetic MFT file creation"},
                        "evidence_refs": [
                            {
                                "evidence_id": "EV-SYN-MFT-001",
                                "parser": "mftecmd",
                                "source": "$MFT",
                                "raw_record_ref": "csv:mft.csv:1842",
                                "description": "Synthetic MFT row reference.",
                            }
                        ],
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_cli_correlate_succeeds_with_synthetic_normalized_events(tmp_path: Path, capsys):
    input_path = tmp_path / "normalized-events.json"
    output_dir = tmp_path / "runs" / CASE_ID
    synthetic_input(input_path)

    exit_code = main(
        [
            "correlate",
            "--case-id",
            CASE_ID,
            "--input",
            str(input_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0
    assert (output_dir / "subject_timelines.json").is_file()
    assert (output_dir / "findings.json").is_file()
    assert (output_dir / "report.md").is_file()
    assert (output_dir / "audit.jsonl").is_file()
    out = capsys.readouterr().out
    assert f"output_dir={output_dir.resolve()}" in out
    assert "timelines=1" in out
    assert "findings=0" in out
    assert f"report_path={(output_dir / 'report.md').resolve()}" in out
    assert "# Case Report" not in out


def test_cli_correlate_fails_clearly_for_missing_input(tmp_path: Path, capsys):
    exit_code = main(
        [
            "correlate",
            "--case-id",
            CASE_ID,
            "--input",
            str(tmp_path / "missing-normalized-events.json"),
            "--output-dir",
            str(tmp_path / "runs" / CASE_ID),
        ]
    )

    assert exit_code == 1
    assert "normalized input JSON does not exist" in capsys.readouterr().err


def test_cli_correlate_help_does_not_expose_raw_evidence_or_execution_options(capsys):
    try:
        main(["correlate", "--help"])
    except SystemExit as exc:
        assert exc.code == 0

    help_text = capsys.readouterr().out.lower()
    assert "--input" in help_text
    assert "--output-dir" in help_text
    for forbidden in ("raw-evidence", "upload", "--shell", "--command", "--executable"):
        assert forbidden not in help_text
