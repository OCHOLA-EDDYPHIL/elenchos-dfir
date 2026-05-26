from __future__ import annotations

import csv
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
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

PARSER_NAME = "recmd"
SOURCE_TOOL = "RECmd"
OUTPUT_ARTIFACT_TYPE = "registry"
ACCEPTED_INPUT_ARTIFACT_TYPES = {"registry", "registry_hive"}

SOFTWARE_RUN_CSV_NAME = "software-run.csv"
SOFTWARE_RUNONCE_CSV_NAME = "software-runonce.csv"
NTUSER_RUN_CSV_NAME = "ntuser-run.csv"
NTUSER_RUNONCE_CSV_NAME = "ntuser-runonce.csv"

Runner = Callable[..., ToolResult]

_ABSENT_TIMESTAMPS = {"", "n/a", "na", "none", "null", "0"}


@dataclass(frozen=True, slots=True)
class RunKeyTarget:
    label: str
    key_path: str
    csv_name: str
    json_name: str


_SOFTWARE_TARGETS = (
    RunKeyTarget(
        label="software-run",
        key_path=r"Microsoft\Windows\CurrentVersion\Run",
        csv_name=SOFTWARE_RUN_CSV_NAME,
        json_name="Run.json",
    ),
    RunKeyTarget(
        label="software-runonce",
        key_path=r"Microsoft\Windows\CurrentVersion\RunOnce",
        csv_name=SOFTWARE_RUNONCE_CSV_NAME,
        json_name="RunOnce.json",
    ),
)

_NTUSER_TARGETS = (
    RunKeyTarget(
        label="ntuser-run",
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Run",
        csv_name=NTUSER_RUN_CSV_NAME,
        json_name="Run.json",
    ),
    RunKeyTarget(
        label="ntuser-runonce",
        key_path=r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        csv_name=NTUSER_RUNONCE_CSV_NAME,
        json_name="RunOnce.json",
    ),
)


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


def _record_id(hive: str | None, key_path: str | None, value_name: str | None) -> str | None:
    parts = [part for part in (hive, key_path, value_name) if part]
    return "|".join(parts) if parts else None


def _registry_event(
    *,
    case_id: str,
    artifact_id: str,
    csv_path: Path,
    row_number: int,
    hive: str | None,
    key_path: str | None,
    value_name: str | None,
    value_data: str | None,
    timestamp_utc: str | None,
    status: str,
    metadata: dict[str, JSON_SCALAR],
) -> ParserEvent:
    return ParserEvent(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=OUTPUT_ARTIFACT_TYPE,
        parser_name=PARSER_NAME,
        source_tool=SOURCE_TOOL,
        event_type="registry_run_key",
        timestamp_utc=timestamp_utc,
        timestamp_description="LastWriteTime" if timestamp_utc is not None else None,
        subject=value_name or key_path,
        key_path=key_path,
        value_name=value_name,
        value_data=value_data,
        evidence_refs=[artifact_id],
        raw_record_ref=RawRecordRef(
            source_path=str(csv_path),
            row_number=row_number,
            record_id=_record_id(hive, key_path, value_name),
        ),
        status=status,
        confidence="tool_reported",
        metadata=metadata,
    )


def _display_key_path(hive_path: Path, target: RunKeyTarget) -> str:
    if hive_path.name.lower() == "software":
        return f"HKLM\\Software\\{target.key_path}"
    return f"HKCU\\{target.key_path}"


def normalize_recmd_runkeys_csv(
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
        return [], [], [f"RECmd Run Key CSV does not exist: {csv_path}"]
    if csv_path.is_dir():
        return [], [], [f"RECmd Run Key CSV path is a directory: {csv_path}"]

    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return [], [], [f"RECmd Run Key CSV has no header row: {csv_path}"]

        row_count = 0
        for row_number, row in enumerate(reader, start=2):
            row_count += 1
            hive = _row_get(row, "Hive")
            key_path = _row_get(row, "KeyPath", "Key Path")
            value_name = _row_get(row, "ValueName", "Value Name")
            value_data = _row_get(row, "ValueData", "Value Data", "Data")

            if key_path is None and value_name is None and value_data is None:
                errors.append(f"row {row_number}: missing registry key and value context")
                continue

            malformed = False
            if key_path is None:
                warnings.append(f"row {row_number}: missing KeyPath")
                malformed = True

            timestamp_utc: str | None = None
            raw_timestamp = _row_get(row, "LastWriteTime", "LastWriteTimeUtc")
            if raw_timestamp is not None:
                try:
                    timestamp_utc = _normalize_timestamp(raw_timestamp)
                except ValueError:
                    warnings.append(f"row {row_number}: invalid timestamp in LastWriteTime")
                    malformed = True

            metadata: dict[str, JSON_SCALAR] = {
                "parser": PARSER_NAME,
                "value_data_present": value_data is not None,
            }
            if hive is not None:
                metadata["hive"] = hive

            events.append(
                _registry_event(
                    case_id=case_id,
                    artifact_id=artifact_id,
                    csv_path=csv_path,
                    row_number=row_number,
                    hive=hive,
                    key_path=key_path,
                    value_name=value_name,
                    value_data=value_data,
                    timestamp_utc=timestamp_utc,
                    status="malformed" if malformed else "normalized",
                    metadata=metadata,
                )
            )

        if row_count == 0:
            errors.append(f"RECmd Run Key CSV has no data rows: {csv_path}")

    return events, warnings, errors


def normalize_recmd_runkeys_json(
    *,
    json_path: Path,
    case_id: str,
    artifact_id: str,
    hive: str,
    key_path: str,
) -> tuple[list[ParserEvent], list[str], list[str]]:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")

    if not json_path.exists():
        return [], [], [f"RECmd Run Key JSON does not exist: {json_path}"]
    if json_path.is_dir():
        return [], [], [f"RECmd Run Key JSON path is a directory: {json_path}"]

    warnings: list[str] = []
    errors: list[str] = []
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        return [], [], [f"RECmd Run Key JSON is malformed: {json_path}: {exc}"]

    if not isinstance(payload, dict):
        return [], [], [f"RECmd Run Key JSON root is not an object: {json_path}"]

    values = payload.get("Values")
    if values in (None, []):
        return [], [], []
    if not isinstance(values, list):
        return [], [], [f"RECmd Run Key JSON Values field is not a list: {json_path}"]

    timestamp_utc: str | None = None
    raw_timestamp = payload.get("LastWriteTimestamp")
    timestamp_malformed = False
    if isinstance(raw_timestamp, str) and raw_timestamp.strip():
        try:
            timestamp_utc = _normalize_timestamp(raw_timestamp)
        except ValueError:
            warnings.append("json key: invalid timestamp in LastWriteTimestamp")
            timestamp_malformed = True

    events: list[ParserEvent] = []
    for value_index, item in enumerate(values, start=1):
        if not isinstance(item, dict):
            warnings.append(f"json value {value_index}: value record is not an object")
            continue

        value_name = item.get("ValueName")
        value_data = item.get("ValueData")
        normalized_value_name = value_name.strip() if isinstance(value_name, str) else None
        normalized_value_data = value_data.strip() if isinstance(value_data, str) else None
        if not normalized_value_name and not normalized_value_data:
            warnings.append(f"json value {value_index}: missing value context")
            continue

        metadata: dict[str, JSON_SCALAR] = {
            "hive": hive,
            "parser": PARSER_NAME,
            "source_format": "json",
            "value_data_present": normalized_value_data is not None,
        }
        value_type = item.get("ValueType")
        if isinstance(value_type, str) and value_type:
            metadata["value_type"] = value_type

        events.append(
            _registry_event(
                case_id=case_id,
                artifact_id=artifact_id,
                csv_path=json_path,
                row_number=value_index,
                hive=hive,
                key_path=key_path,
                value_name=normalized_value_name,
                value_data=normalized_value_data,
                timestamp_utc=timestamp_utc,
                status="malformed" if timestamp_malformed else "normalized",
                metadata=metadata,
            )
        )

    return events, warnings, errors


def _targets_for_hive(hive_path: Path) -> tuple[RunKeyTarget, ...]:
    name = hive_path.name.lower()
    if name == "software":
        return _SOFTWARE_TARGETS
    if name == "ntuser.dat":
        return _NTUSER_TARGETS
    return ()


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
        "does not exist",
        "bad registry hive signature",
        "unable to process",
        "failed to process",
    ):
        if phrase in text:
            return phrase
    return None


def _tool_error(tool_result: ToolResult, target: RunKeyTarget) -> str:
    return (
        f"RECmd target {target.label} failed with status={tool_result.status} "
        f"exit_code={tool_result.exit_code}"
    )


def _skipped_result(
    *,
    case_id: str,
    artifact_id: str,
    reason: str,
) -> ParserResult:
    return ParserResult(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=OUTPUT_ARTIFACT_TYPE,
        parser_name=PARSER_NAME,
        source_tool=SOURCE_TOOL,
        status="skipped",
        errors=[reason],
    )


def parse_registry_runkeys(
    *,
    case_id: str,
    artifact_id: str,
    hive_path: Path,
    runs_root: Path,
    evidence_root: Path | None = None,
    ledger_path: Path | None = None,
    command_config: ParserCommandConfig | None = None,
    timeout_seconds: int = 900,
    runner: Runner | None = None,
    artifact_type: str = "registry_hive",
) -> ParserResult:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")

    if artifact_type not in ACCEPTED_INPUT_ARTIFACT_TYPES:
        return _skipped_result(
            case_id=case_id,
            artifact_id=artifact_id,
            reason=(
                "Registry Run Key parser accepts artifact_type in "
                f"{sorted(ACCEPTED_INPUT_ARTIFACT_TYPES)}, got {artifact_type}"
            ),
        )

    resolved_hive_path = Path(hive_path)
    resolved_runs_root = Path(runs_root)
    if not resolved_hive_path.exists():
        raise FileNotFoundError(f"Registry hive input does not exist: {resolved_hive_path}")
    if resolved_hive_path.is_dir():
        raise ValueError(
            f"Registry hive input must be a file, not a directory: {resolved_hive_path}"
        )

    targets = _targets_for_hive(resolved_hive_path)
    if not targets:
        return _skipped_result(
            case_id=case_id,
            artifact_id=artifact_id,
            reason=(
                "Registry Run Key parser supports SOFTWARE and NTUSER.DAT hives, "
                f"got {resolved_hive_path.name}"
            ),
        )

    try:
        command_base = resolve_parser_command(PARSER_NAME, command_config)
    except (KeyError, TypeError, ValueError) as exc:
        return ParserResult.missing_command(
            case_id=case_id,
            artifact_id=artifact_id,
            artifact_type=OUTPUT_ARTIFACT_TYPE,
            parser_name=PARSER_NAME,
            source_tool=SOURCE_TOOL,
            reason=f"RECmd command is not available: {exc}",
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

    runner_fn = runner or run_command
    started_at_utc = _utc_now_z()
    commands: list[tuple[str, ...]] = []
    candidate_files: list[Path] = []
    events: list[ParserEvent] = []
    warnings: list[str] = []
    errors: list[str] = []
    successful_command_count = 0
    failed_command_count = 0
    missing_csv_count = 0
    duration_ms = 0

    for target in targets:
        csv_path = output_dir / target.csv_name
        json_path = output_dir / target.json_name
        stdout_path = logs_dir / f"{PARSER_NAME}_{artifact_id}_{target.label}_stdout.log"
        stderr_path = logs_dir / f"{PARSER_NAME}_{artifact_id}_{target.label}_stderr.log"
        candidate_files.extend((csv_path, json_path, stdout_path, stderr_path))
        command = (
            *command_base,
            "-f",
            str(resolved_hive_path),
            "--kn",
            target.key_path,
            "--csv",
            str(output_dir),
            "--csvf",
            target.csv_name,
            "--json",
            str(output_dir),
            "--nl",
        )
        commands.append(command)

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
        duration_ms += getattr(tool_result, "duration_ms", 0)

        target_failed = tool_result.status != "success"
        stdout_error = _known_stdout_error(stdout_path)
        if stdout_error is not None:
            target_failed = True
            errors.append(f"RECmd target {target.label} stdout reported: {stdout_error}")

        if csv_path.exists():
            target_events, target_warnings, target_errors = normalize_recmd_runkeys_csv(
                csv_path=csv_path,
                case_id=case_id,
                artifact_id=artifact_id,
            )
            events.extend(target_events)
            warnings.extend(
                f"{target.label}: {warning}" for warning in target_warnings
            )
            errors.extend(f"{target.label}: {error}" for error in target_errors)
            if target_failed:
                warnings.append(f"RECmd command failed but {target.csv_name} was present")
                errors.append(_tool_error(tool_result, target))
        elif json_path.exists():
            target_events, target_warnings, target_errors = normalize_recmd_runkeys_json(
                json_path=json_path,
                case_id=case_id,
                artifact_id=artifact_id,
                hive=resolved_hive_path.name,
                key_path=_display_key_path(resolved_hive_path, target),
            )
            events.extend(target_events)
            warnings.extend(
                f"{target.label}: {warning}" for warning in target_warnings
            )
            errors.extend(f"{target.label}: {error}" for error in target_errors)
            if target_failed:
                warnings.append(f"RECmd command failed but {target.json_name} was present")
                errors.append(_tool_error(tool_result, target))
        else:
            missing_csv_count += 1
            errors.append(
                f"expected RECmd CSV or JSON was not created: {csv_path} or {json_path}"
            )
            if target_failed:
                errors.append(_tool_error(tool_result, target))

        target_output_exists = csv_path.exists() or json_path.exists()
        if target_failed or not target_output_exists:
            failed_command_count += 1
        else:
            successful_command_count += 1

    ended_at_utc = _utc_now_z()
    output_files = _existing_files(candidate_files)
    output_hashes = _existing_file_hashes(candidate_files)

    if not events and not errors:
        errors.append("RECmd outputs contained no normalizable Run Key values")

    if events:
        status = (
            "partial_success"
            if warnings or errors or failed_command_count > 0 or missing_csv_count > 0
            else "success"
        )
    else:
        status = "failed"

    metadata: dict[str, JSON_SCALAR] = {
        "command_count": len(commands),
        "successful_command_count": successful_command_count,
        "failed_command_count": failed_command_count,
        "missing_csv_count": missing_csv_count,
    }
    for index, target in enumerate(targets, start=1):
        metadata[f"target_{index}_label"] = target.label

    return ParserResult(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=OUTPUT_ARTIFACT_TYPE,
        parser_name=PARSER_NAME,
        source_tool=SOURCE_TOOL,
        status=status,
        command=commands[0] if commands else None,
        output_dir=str(output_dir),
        output_files=output_files,
        output_hashes=output_hashes,
        events=events,
        warnings=warnings,
        errors=errors,
        started_at_utc=started_at_utc,
        ended_at_utc=ended_at_utc,
        duration_ms=duration_ms,
        metadata=metadata,
    )


def parse_registry_runkeys_artifact(
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
    if artifact.artifact_type not in ACCEPTED_INPUT_ARTIFACT_TYPES:
        raise ValueError(
            "expected artifact_type in "
            f"{sorted(ACCEPTED_INPUT_ARTIFACT_TYPES)}, got {artifact.artifact_type}"
        )
    return parse_registry_runkeys(
        case_id=case_id,
        artifact_id=artifact.artifact_id,
        hive_path=Path(artifact.path),
        runs_root=runs_root,
        evidence_root=evidence_root,
        ledger_path=ledger_path,
        command_config=command_config,
        timeout_seconds=timeout_seconds,
        runner=runner,
        artifact_type=artifact.artifact_type,
    )
