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
from siftguard.parser.paths import build_parser_logs_dir, ensure_parser_output_dir
from siftguard.parser.result import ParserResult
from siftguard.runner.subprocess_runner import run_command
from siftguard.runner.tool_result import ToolResult

PARSER_NAME = "amcacheparser"
SOURCE_TOOL = "AmcacheParser"
EXPECTED_ARTIFACT_TYPE = "amcache"
DEFAULT_AMCACHE_CSV_NAME = "amcache.csv"

Runner = Callable[..., ToolResult]

_ABSENT_TIMESTAMPS = {"", "n/a", "na", "none", "null", "0"}
_SHA1_RE = re.compile(r"^(?:sha1:)?([a-fA-F0-9]{40})$")
_SHA256_RE = re.compile(r"^(?:sha256:)?([a-fA-F0-9]{64})$")

_PATH_COLUMNS = ("FilePath", "FullPath", "Path", "ProgramPath", "FileName")
_SUBJECT_COLUMNS = ("ProgramName", "FileName")
_TIMESTAMP_COLUMNS = (
    "LastModifiedTimeUtc",
    "LastModifiedUtc",
    "ModifiedTimeUtc",
    "LinkDate",
    "CreatedUtc",
    "FirstRunTimeUtc",
)
_SHA256_COLUMNS = ("SHA256", "SHA-256", "Hash", "FileHash")
_SHA1_COLUMNS = ("SHA1", "SHA-1")


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _require_non_empty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")


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


def _row_value_with_column(row: dict[str, str], columns: Sequence[str]) -> tuple[str, str] | None:
    lower_map = {key.lower(): key for key in row}
    for column in columns:
        actual_key = lower_map.get(column.lower())
        if actual_key is None:
            continue
        value = row.get(actual_key)
        if value is not None and value.strip():
            return actual_key, value.strip()
    return None


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


def _normalize_hashes(
    row: dict[str, str],
    row_number: int,
    warnings: list[str],
) -> tuple[str | None, str | None, bool]:
    sha256: str | None = None
    sha1: str | None = None
    malformed = False

    for column in (*_SHA256_COLUMNS, *_SHA1_COLUMNS):
        value = _row_get(row, column)
        if value is None:
            continue

        sha256_match = _SHA256_RE.match(value)
        if sha256_match is not None:
            sha256 = sha256_match.group(1).lower()
            continue

        sha1_match = _SHA1_RE.match(value)
        if sha1_match is not None:
            sha1 = sha1_match.group(1).lower()
            continue

        warnings.append(f"row {row_number}: invalid hash value in {column}")
        malformed = True

    return sha256, sha1, malformed


def _metadata_for_row(
    row: dict[str, str],
    *,
    sha1: str | None,
    timestamp_column: str | None,
) -> dict[str, JSON_SCALAR]:
    metadata: dict[str, JSON_SCALAR] = {"parser": PARSER_NAME}
    for column, key in (
        ("ProgramName", "program_name"),
        ("FileName", "file_name"),
        ("Publisher", "publisher"),
        ("ProductName", "product_name"),
        ("Version", "version"),
    ):
        value = _row_get(row, column)
        if value is not None:
            metadata[key] = value
    if sha1 is not None:
        metadata["sha1"] = sha1
    if timestamp_column is not None:
        metadata["source_timestamp_column"] = timestamp_column
    return metadata


def _record_id(
    *,
    program_name: str | None,
    path: str | None,
    sha256: str | None,
    sha1: str | None,
) -> str | None:
    parts = [part for part in (program_name, path, sha256, sha1) if part]
    return "|".join(parts) if parts else None


def _amcache_event(
    *,
    case_id: str,
    artifact_id: str,
    csv_path: Path,
    row_number: int,
    subject: str,
    path: str | None,
    timestamp_utc: str | None,
    timestamp_column: str | None,
    sha256: str | None,
    sha1: str | None,
    status: str,
    metadata: dict[str, JSON_SCALAR],
) -> ParserEvent:
    program_name = metadata.get("program_name")
    return ParserEvent(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=EXPECTED_ARTIFACT_TYPE,
        parser_name=PARSER_NAME,
        source_tool=SOURCE_TOOL,
        event_type="amcache_execution",
        timestamp_utc=timestamp_utc,
        timestamp_description=timestamp_column if timestamp_utc is not None else None,
        subject=subject,
        path=path,
        sha256=sha256,
        evidence_refs=[artifact_id],
        raw_record_ref=RawRecordRef(
            source_path=str(csv_path),
            row_number=row_number,
            record_id=_record_id(
                program_name=program_name if isinstance(program_name, str) else None,
                path=path,
                sha256=sha256,
                sha1=sha1,
            ),
        ),
        status=status,
        confidence="tool_reported",
        metadata=metadata,
    )


def normalize_amcache_csv(
    *,
    csv_path: Path,
    case_id: str,
    artifact_id: str,
) -> tuple[list[ParserEvent], list[str], list[str]]:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")

    events: list[ParserEvent] = []
    warnings: list[str] = []
    errors: list[str] = []

    if not csv_path.exists():
        return [], [], [f"AmcacheParser CSV does not exist: {csv_path}"]
    if csv_path.is_dir():
        return [], [], [f"AmcacheParser CSV path is a directory: {csv_path}"]

    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return [], [], [f"AmcacheParser CSV has no header row: {csv_path}"]

        row_count = 0
        for row_number, row in enumerate(reader, start=2):
            row_count += 1
            row_warnings_before = len(warnings)
            path = _row_get(row, *_PATH_COLUMNS)
            subject = _row_get(row, *_SUBJECT_COLUMNS) or path
            if subject is None:
                errors.append(f"row {row_number}: missing Amcache row subject or path")
                continue

            timestamp_column: str | None = None
            timestamp_utc: str | None = None
            timestamp_value = _row_value_with_column(row, _TIMESTAMP_COLUMNS)
            if timestamp_value is not None:
                timestamp_column, raw_timestamp = timestamp_value
                try:
                    timestamp_utc = _normalize_timestamp(raw_timestamp)
                except ValueError:
                    warnings.append(f"row {row_number}: invalid timestamp in {timestamp_column}")

            sha256, sha1, malformed_hash = _normalize_hashes(row, row_number, warnings)
            metadata = _metadata_for_row(
                row,
                sha1=sha1,
                timestamp_column=timestamp_column if timestamp_utc is not None else None,
            )
            malformed = malformed_hash or len(warnings) > row_warnings_before or path is None
            if path is None:
                warnings.append(f"row {row_number}: missing FilePath")

            events.append(
                _amcache_event(
                    case_id=case_id,
                    artifact_id=artifact_id,
                    csv_path=csv_path,
                    row_number=row_number,
                    subject=subject,
                    path=path,
                    timestamp_utc=timestamp_utc,
                    timestamp_column=timestamp_column,
                    sha256=sha256,
                    sha1=sha1,
                    status="malformed" if malformed else "normalized",
                    metadata=metadata,
                )
            )

        if row_count == 0:
            errors.append(f"AmcacheParser CSV has no data rows: {csv_path}")

    return events, warnings, errors


def _existing_file_hashes(paths: Sequence[Path]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in paths:
        if path.exists() and path.is_file():
            hashes[str(path)] = sha256_file(path)
    return hashes


def _existing_files(paths: Sequence[Path]) -> list[str]:
    return [str(path) for path in paths if path.exists() and path.is_file()]


def _known_stdout_error(stdout_path: Path) -> str | None:
    if not stdout_path.exists() or stdout_path.is_dir():
        return None
    text = stdout_path.read_text(encoding="utf-8", errors="replace").lower()
    for phrase in (
        "file not found",
        "not found",
        "does not exist",
        "bad registry hive signature",
        "stack trace",
        "exception",
        "unable to process",
        "failed to process",
    ):
        if phrase in text:
            return phrase
    return None


def _tool_error(tool_result: ToolResult) -> str:
    return (
        f"AmcacheParser failed with status={tool_result.status} "
        f"exit_code={tool_result.exit_code}"
    )


def parse_amcache(
    *,
    case_id: str,
    artifact_id: str,
    amcache_path: Path,
    runs_root: Path,
    evidence_root: Path | None = None,
    ledger_path: Path | None = None,
    command_config: ParserCommandConfig | None = None,
    timeout_seconds: int = 900,
    runner: Runner | None = None,
    artifact_type: str = EXPECTED_ARTIFACT_TYPE,
) -> ParserResult:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")
    if artifact_type != EXPECTED_ARTIFACT_TYPE:
        raise ValueError(
            f"expected artifact_type={EXPECTED_ARTIFACT_TYPE}, got {artifact_type}"
        )

    resolved_amcache_path = Path(amcache_path)
    resolved_runs_root = Path(runs_root)
    if not resolved_amcache_path.exists():
        raise FileNotFoundError(f"Amcache input does not exist: {resolved_amcache_path}")
    if resolved_amcache_path.is_dir():
        raise ValueError(
            f"Amcache input must be a file, not a directory: {resolved_amcache_path}"
        )

    try:
        command_base = resolve_parser_command(PARSER_NAME, command_config)
    except (KeyError, TypeError, ValueError) as exc:
        return ParserResult.missing_command(
            case_id=case_id,
            artifact_id=artifact_id,
            artifact_type=EXPECTED_ARTIFACT_TYPE,
            parser_name=PARSER_NAME,
            source_tool=SOURCE_TOOL,
            reason=f"AmcacheParser command is not available: {exc}",
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

    csv_path = output_dir / DEFAULT_AMCACHE_CSV_NAME
    stdout_path = logs_dir / f"{PARSER_NAME}_{artifact_id}_stdout.log"
    stderr_path = logs_dir / f"{PARSER_NAME}_{artifact_id}_stderr.log"
    command = (
        *command_base,
        "-f",
        str(resolved_amcache_path),
        "--csv",
        str(output_dir),
        "--csvf",
        DEFAULT_AMCACHE_CSV_NAME,
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
    stdout_error = _known_stdout_error(stdout_path)
    if stdout_error is not None:
        tool_failed = True
        errors.append(f"AmcacheParser stdout reported: {stdout_error}")

    if csv_path.exists():
        events, warnings, normalize_errors = normalize_amcache_csv(
            csv_path=csv_path,
            case_id=case_id,
            artifact_id=artifact_id,
        )
        errors.extend(normalize_errors)
        if tool_failed:
            warnings.append("AmcacheParser command failed but output CSV was present")
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
            errors.append(f"expected AmcacheParser CSV was not created: {csv_path}")
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
            "csv_name": DEFAULT_AMCACHE_CSV_NAME,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "tool_exit_code": getattr(tool_result, "exit_code", None),
            "tool_status": getattr(tool_result, "status", None),
        },
    )


def parse_amcache_artifact(
    *,
    case_id: str,
    artifact: EvidenceArtifact,
    runs_root: Path,
    evidence_root: Path | None = None,
    ledger_path: Path | None = None,
    command_config: ParserCommandConfig | None = None,
    timeout_seconds: int = 900,
    runner: Runner | None = None,
) -> ParserResult:
    if artifact.artifact_type != EXPECTED_ARTIFACT_TYPE:
        raise ValueError(
            f"expected artifact_type={EXPECTED_ARTIFACT_TYPE}, got {artifact.artifact_type}"
        )
    return parse_amcache(
        case_id=case_id,
        artifact_id=artifact.artifact_id,
        amcache_path=Path(artifact.path),
        runs_root=runs_root,
        evidence_root=evidence_root,
        ledger_path=ledger_path,
        command_config=command_config,
        timeout_seconds=timeout_seconds,
        runner=runner,
        artifact_type=artifact.artifact_type,
    )
