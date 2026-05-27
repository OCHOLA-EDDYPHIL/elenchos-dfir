from __future__ import annotations

import csv
import re
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from siftguard.correlation.event_schema import JSON_SCALAR, ParserEvent, RawRecordRef
from siftguard.evidence.hashing import sha256_file
from siftguard.evidence.manifest import EvidenceArtifact
from siftguard.parser.config import ParserCommandConfig, resolve_parser_command
from siftguard.parser.paths import (
    build_parser_logs_dir,
    ensure_parser_output_dir,
)
from siftguard.parser.result import ParserResult
from siftguard.runner.subprocess_runner import run_command
from siftguard.runner.tool_result import ToolResult

PARSER_NAME = "mftecmd"
SOURCE_TOOL = "MFTECmd"
EXPECTED_ARTIFACT_TYPE = "mft"
DEFAULT_MFTECMD_CSV_NAME = "mftecmd.csv"
EVENT_LIMIT_WARNING_PREFIX = "max_events="

Runner = Callable[..., ToolResult]

_ABSENT_TIMESTAMPS = {"", "n/a", "na", "none", "null", "0"}
_SHA256_RE = re.compile(r"^(?:sha256:)?([a-fA-F0-9]{64})$")

_TIMESTAMP_COLUMNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("file_created", ("Created0x10", "Created", "CreatedUtc")),
    ("file_modified", ("Modified0x10", "LastModified0x10", "Modified", "LastModifiedUtc")),
    ("file_accessed", ("Accessed0x10", "LastAccess0x10", "Accessed", "LastAccessUtc")),
)


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _require_non_empty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")


def _validate_max_events(max_events: int | None) -> int | None:
    if max_events is None:
        return None
    if not isinstance(max_events, int) or max_events < 1:
        raise ValueError("max_events must be a positive integer when provided")
    return max_events


def _row_get(row: dict[str, str], *names: str) -> str | None:
    lower_map = {key.lower(): key for key in row}
    for name in names:
        actual_key = lower_map.get(name.lower())
        if actual_key is None:
            continue
        value = row.get(actual_key)
        if value is not None and value.strip():
            return value.strip()
    return None


def _row_path(row: dict[str, str]) -> str | None:
    direct = _row_get(row, "FullPath", "FilePath", "Path")
    if direct is not None:
        return direct

    parent = _row_get(row, "ParentPath")
    filename = _row_get(row, "FileName")
    if parent and filename:
        separator = "\\" if "\\" in parent else "/"
        stripped_parent = parent.rstrip("/\\")
        return f"{stripped_parent}{separator}{filename}"
    return filename


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    return int(value)


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"true", "1", "yes", "y"}:
        return True
    if lowered in {"false", "0", "no", "n"}:
        return False
    raise ValueError(f"invalid bool value: {value}")


def _metadata_for_row(
    row: dict[str, str],
    row_number: int,
    warnings: list[str],
) -> tuple[dict[str, JSON_SCALAR], bool]:
    metadata: dict[str, JSON_SCALAR] = {}
    malformed = False

    for column, key in (
        ("EntryNumber", "entry_number"),
        ("SequenceNumber", "sequence_number"),
        ("ParentEntryNumber", "parent_entry_number"),
        ("FileSize", "file_size"),
    ):
        raw_value = _row_get(row, column)
        if raw_value is None:
            continue
        try:
            metadata[key] = _parse_int(raw_value)
        except ValueError:
            warnings.append(f"row {row_number}: invalid integer in {column}")
            malformed = True

    for column, key in (("InUse", "in_use"), ("IsDirectory", "is_directory")):
        raw_value = _row_get(row, column)
        if raw_value is None:
            continue
        try:
            metadata[key] = _parse_bool(raw_value)
        except ValueError:
            warnings.append(f"row {row_number}: invalid boolean in {column}")
            malformed = True

    return metadata, malformed


def _normalize_sha256(value: str | None, row_number: int, warnings: list[str]) -> str | None:
    if value is None:
        return None

    match = _SHA256_RE.match(value.strip())
    if match is None:
        warnings.append(f"row {row_number}: invalid SHA256 value")
        return None
    return match.group(1).lower()


def _normalize_timestamp(value: str) -> str | None:
    text = value.strip()
    lowered = text.lower()
    if lowered in _ABSENT_TIMESTAMPS or lowered.startswith("0001-01-01"):
        return None

    if text.endswith("Z"):
        parse_text = text[:-1] + "+00:00"
    else:
        parse_text = text.replace(" ", "T", 1)
        if "." in parse_text:
            prefix, suffix = parse_text.split(".", 1)
            fraction = suffix
            timezone_suffix = ""
            for marker in ("+", "-"):
                if marker in suffix:
                    fraction, timezone_suffix = suffix.split(marker, 1)
                    timezone_suffix = marker + timezone_suffix
                    break
            parse_text = f"{prefix}.{fraction[:6]}{timezone_suffix}"

    parsed = datetime.fromisoformat(parse_text)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _timestamp_value(row: dict[str, str], columns: Sequence[str]) -> tuple[str, str] | None:
    for column in columns:
        value = _row_get(row, column)
        if value is not None:
            return column, value
    return None


def _event(
    *,
    case_id: str,
    artifact_id: str,
    event_type: str,
    path: str,
    subject: str,
    row_number: int,
    csv_path: Path,
    entry_number: str | None,
    sha256: str | None,
    metadata: dict[str, JSON_SCALAR],
    status: str,
    timestamp_utc: str | None = None,
    timestamp_description: str | None = None,
) -> ParserEvent:
    return ParserEvent(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=EXPECTED_ARTIFACT_TYPE,
        parser_name=PARSER_NAME,
        source_tool=SOURCE_TOOL,
        event_type=event_type,
        timestamp_utc=timestamp_utc,
        timestamp_description=timestamp_description,
        subject=subject,
        path=path,
        sha256=sha256,
        evidence_refs=[artifact_id],
        raw_record_ref=RawRecordRef(
            source_path=str(csv_path),
            row_number=row_number,
            record_id=entry_number,
        ),
        status=status,
        confidence="tool_reported",
        metadata=metadata,
    )


def normalize_mftecmd_csv(
    *,
    csv_path: Path,
    case_id: str,
    artifact_id: str,
    max_events: int | None = None,
) -> tuple[list[ParserEvent], list[str], list[str]]:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")
    max_events = _validate_max_events(max_events)

    events: list[ParserEvent] = []
    warnings: list[str] = []
    errors: list[str] = []
    limit_reached = False

    if not csv_path.exists():
        return [], [], [f"MFTECmd CSV does not exist: {csv_path}"]
    if csv_path.is_dir():
        return [], [], [f"MFTECmd CSV path is a directory: {csv_path}"]

    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return [], [], [f"MFTECmd CSV has no header row: {csv_path}"]

        row_count = 0
        for row_number, row in enumerate(reader, start=2):
            if max_events is not None and len(events) >= max_events:
                limit_reached = True
                break

            row_count += 1
            row_warnings_before = len(warnings)
            path = _row_path(row)
            if path is None:
                errors.append(f"row {row_number}: missing file path or file name")
                continue

            filename = _row_get(row, "FileName")
            subject = filename or path
            entry_number = _row_get(row, "EntryNumber")
            metadata, malformed_metadata = _metadata_for_row(row, row_number, warnings)
            sha256 = _normalize_sha256(
                _row_get(row, "SHA256", "Hash", "FileHash"),
                row_number,
                warnings,
            )
            timestamp_events: list[ParserEvent] = []

            for event_type, columns in _TIMESTAMP_COLUMNS:
                timestamp_source = _timestamp_value(row, columns)
                if timestamp_source is None:
                    continue

                column_name, raw_timestamp = timestamp_source
                try:
                    timestamp_utc = _normalize_timestamp(raw_timestamp)
                except ValueError:
                    warnings.append(f"row {row_number}: invalid timestamp in {column_name}")
                    continue

                if timestamp_utc is None:
                    continue

                timestamp_events.append(
                    _event(
                        case_id=case_id,
                        artifact_id=artifact_id,
                        event_type=event_type,
                        path=path,
                        subject=subject,
                        row_number=row_number,
                        csv_path=csv_path,
                        entry_number=entry_number,
                        sha256=sha256,
                        metadata=dict(metadata),
                        status="normalized",
                        timestamp_utc=timestamp_utc,
                        timestamp_description=column_name,
                    )
                )

            file_record_status = (
                "malformed"
                if malformed_metadata or len(warnings) > row_warnings_before
                else "normalized"
            )
            row_events = [
                _event(
                    case_id=case_id,
                    artifact_id=artifact_id,
                    event_type="file_record",
                    path=path,
                    subject=subject,
                    row_number=row_number,
                    csv_path=csv_path,
                    entry_number=entry_number,
                    sha256=sha256,
                    metadata=metadata,
                    status=file_record_status,
                ),
                *timestamp_events,
            ]
            for event in row_events:
                if max_events is not None and len(events) >= max_events:
                    limit_reached = True
                    break
                events.append(event)
            if limit_reached:
                break

        if row_count == 0:
            errors.append(f"MFTECmd CSV has no data rows: {csv_path}")
        if limit_reached:
            warnings.append(
                f"{EVENT_LIMIT_WARNING_PREFIX}{max_events} reached; "
                "remaining MFTECmd rows were not normalized"
            )

    return events, warnings, errors


def _existing_file_hashes(paths: Sequence[Path]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in paths:
        if path.exists() and path.is_file():
            hashes[str(path)] = sha256_file(path)
    return hashes


def _existing_files(paths: Sequence[Path]) -> list[str]:
    return [str(path) for path in paths if path.exists() and path.is_file()]


def _tool_error(tool_result: ToolResult) -> str:
    return (
        f"MFTECmd failed with status={tool_result.status} "
        f"exit_code={tool_result.exit_code}"
    )


def parse_mft(
    *,
    case_id: str,
    artifact_id: str,
    mft_path: Path,
    runs_root: Path,
    evidence_root: Path | None = None,
    ledger_path: Path | None = None,
    command_config: ParserCommandConfig | None = None,
    timeout_seconds: int = 900,
    runner: Runner | None = None,
    artifact_type: str = EXPECTED_ARTIFACT_TYPE,
    max_events: int | None = None,
) -> ParserResult:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")
    max_events = _validate_max_events(max_events)
    if artifact_type != EXPECTED_ARTIFACT_TYPE:
        raise ValueError(f"expected artifact_type={EXPECTED_ARTIFACT_TYPE}, got {artifact_type}")

    resolved_mft_path = Path(mft_path)
    resolved_runs_root = Path(runs_root)
    if not resolved_mft_path.exists():
        raise FileNotFoundError(f"MFT input does not exist: {resolved_mft_path}")
    if resolved_mft_path.is_dir():
        raise ValueError(f"MFT input must be a file, not a directory: {resolved_mft_path}")

    try:
        command_base = resolve_parser_command(PARSER_NAME, command_config)
    except (KeyError, TypeError, ValueError) as exc:
        return ParserResult.missing_command(
            case_id=case_id,
            artifact_id=artifact_id,
            artifact_type=EXPECTED_ARTIFACT_TYPE,
            parser_name=PARSER_NAME,
            source_tool=SOURCE_TOOL,
            reason=f"MFTECmd command is not available: {exc}",
        )

    output_dir = ensure_parser_output_dir(
        resolved_runs_root,
        case_id,
        artifact_id,
        PARSER_NAME,
        evidence_root,
    )
    logs_dir = build_parser_logs_dir(resolved_runs_root, case_id, evidence_root)
    logs_dir.mkdir(parents=True, exist_ok=True)

    csv_path = output_dir / DEFAULT_MFTECMD_CSV_NAME
    stdout_path = logs_dir / f"{PARSER_NAME}_{artifact_id}_stdout.log"
    stderr_path = logs_dir / f"{PARSER_NAME}_{artifact_id}_stderr.log"
    command = (
        *command_base,
        "-f",
        str(resolved_mft_path),
        "--csv",
        str(output_dir),
        "--csvf",
        DEFAULT_MFTECMD_CSV_NAME,
    )

    started_at_utc = _utc_now_z()
    runner_fn = runner or run_command
    tool_result = runner_fn(
        command,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout_seconds=timeout_seconds,
        ledger_path=ledger_path,
        case_id=case_id,
        tool_name=PARSER_NAME,
        runs_root=resolved_runs_root,
        evidence_root=evidence_root,
    )
    ended_at_utc = _utc_now_z()

    candidate_files = (csv_path, stdout_path, stderr_path)
    output_files = _existing_files(candidate_files)
    output_hashes = _existing_file_hashes(candidate_files)
    warnings: list[str] = []
    errors: list[str] = []
    events: list[ParserEvent] = []

    tool_failed = tool_result.status != "success"
    if csv_path.exists():
        events, warnings, errors = normalize_mftecmd_csv(
            csv_path=csv_path,
            case_id=case_id,
            artifact_id=artifact_id,
            max_events=max_events,
        )
        if tool_failed:
            warnings.append("MFTECmd command failed but output CSV was present")
            errors.append(_tool_error(tool_result))
            status = "partial_success"
        elif errors or warnings:
            status = "partial_success" if events else "failed"
        else:
            status = "success"
    else:
        if tool_failed:
            errors.append(_tool_error(tool_result))
        else:
            errors.append(f"expected MFTECmd CSV was not created: {csv_path}")
        status = "failed"

    return ParserResult(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=EXPECTED_ARTIFACT_TYPE,
        parser_name=PARSER_NAME,
        source_tool=SOURCE_TOOL,
        status=status,
        command=command,
        output_dir=str(output_dir),
        output_files=output_files,
        output_hashes=output_hashes,
        events=events,
        warnings=warnings,
        errors=errors,
        started_at_utc=started_at_utc,
        ended_at_utc=ended_at_utc,
        duration_ms=getattr(tool_result, "duration_ms", None),
        metadata={
            "csv_name": DEFAULT_MFTECMD_CSV_NAME,
            "max_events": max_events,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "tool_exit_code": getattr(tool_result, "exit_code", None),
            "tool_status": getattr(tool_result, "status", None),
        },
    )


def parse_mft_artifact(
    *,
    case_id: str,
    artifact: EvidenceArtifact,
    runs_root: Path,
    evidence_root: Path | None = None,
    ledger_path: Path | None = None,
    command_config: ParserCommandConfig | None = None,
    timeout_seconds: int = 900,
    runner: Runner | None = None,
    max_events: int | None = None,
) -> ParserResult:
    if artifact.artifact_type != EXPECTED_ARTIFACT_TYPE:
        raise ValueError(
            f"expected artifact_type={EXPECTED_ARTIFACT_TYPE}, got {artifact.artifact_type}"
        )
    return parse_mft(
        case_id=case_id,
        artifact_id=artifact.artifact_id,
        mft_path=Path(artifact.path),
        runs_root=runs_root,
        evidence_root=evidence_root,
        ledger_path=ledger_path,
        command_config=command_config,
        timeout_seconds=timeout_seconds,
        runner=runner,
        artifact_type=artifact.artifact_type,
        max_events=max_events,
    )
