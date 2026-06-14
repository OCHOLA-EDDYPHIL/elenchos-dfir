from __future__ import annotations

import codecs
import csv
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from elenchos.correlation.event_schema import JSON_SCALAR, ParserEvent, RawRecordRef
from elenchos.evidence.hashing import sha256_file
from elenchos.evidence.manifest import EvidenceArtifact
from elenchos.parser.config import ParserCommandConfig, resolve_parser_command
from elenchos.parser.paths import build_parser_logs_dir, ensure_parser_output_dir
from elenchos.parser.result import ParserResult
from elenchos.runner.subprocess_runner import run_command
from elenchos.runner.tool_result import ToolResult

PARSER_NAME = "recmd"
SOURCE_TOOL = "RECmd"
OUTPUT_ARTIFACT_TYPE = "registry_user_activity"
ACCEPTED_INPUT_ARTIFACT_TYPES = {"registry", "registry_hive"}
EVENT_LIMIT_WARNING_PREFIX = "max_events="

Runner = Callable[..., ToolResult]
CoverageGap = dict[str, JSON_SCALAR]

_ABSENT_TIMESTAMPS = {"", "n/a", "na", "none", "null", "0"}
_USER_ACTIVITY_ARTIFACT_TYPES = {
    "userassist",
    "recentdocs",
    "opensavepidlmru",
    "lastvisitedpidlmru",
    "typedpaths",
}
_EVENT_TYPE_BY_ARTIFACT_TYPE = {
    "userassist": "registry_userassist_program_use",
    "recentdocs": "registry_recent_document_candidate",
    "opensavepidlmru": "registry_opensave_file_candidate",
    "lastvisitedpidlmru": "registry_lastvisited_program_candidate",
    "typedpaths": "registry_typed_path_candidate",
}
_INTERPRETATION_BY_ARTIFACT_TYPE = {
    "userassist": (
        "Program-use candidate from NTUSER.DAT UserAssist; not proof of malware execution."
    ),
    "recentdocs": "Recent document candidate from NTUSER.DAT; not proof of theft.",
    "opensavepidlmru": "Open/save dialog candidate from NTUSER.DAT; not proof of exfiltration.",
    "lastvisitedpidlmru": "Program/file-dialog interaction candidate from NTUSER.DAT.",
    "typedpaths": "Explorer typed-path navigation candidate from NTUSER.DAT.",
}


@dataclass(frozen=True, slots=True)
class UserActivityTarget:
    label: str
    artifact_type: str
    key_path: str
    csv_name: str
    json_name: str


_NTUSER_TARGETS = (
    UserActivityTarget(
        label="ntuser-userassist",
        artifact_type="userassist",
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        csv_name="ntuser-userassist.csv",
        json_name="UserAssist.json",
    ),
    UserActivityTarget(
        label="ntuser-recentdocs",
        artifact_type="recentdocs",
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        csv_name="ntuser-recentdocs.csv",
        json_name="RecentDocs.json",
    ),
    UserActivityTarget(
        label="ntuser-opensavepidlmru",
        artifact_type="opensavepidlmru",
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        csv_name="ntuser-opensavepidlmru.csv",
        json_name="OpenSavePidlMRU.json",
    ),
    UserActivityTarget(
        label="ntuser-lastvisitedpidlmru",
        artifact_type="lastvisitedpidlmru",
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
        csv_name="ntuser-lastvisitedpidlmru.csv",
        json_name="LastVisitedPidlMRU.json",
    ),
    UserActivityTarget(
        label="ntuser-typedpaths",
        artifact_type="typedpaths",
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        csv_name="ntuser-typedpaths.csv",
        json_name="TypedPaths.json",
    ),
)


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _require_non_empty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")


def _validate_artifact_type(artifact_type: str) -> str:
    if artifact_type not in _USER_ACTIVITY_ARTIFACT_TYPES:
        raise ValueError(f"unsupported Registry user-activity artifact_type: {artifact_type}")
    return artifact_type


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


def _gap_id(
    *,
    artifact_id: str,
    artifact_type: str,
    reason: str,
    key_path: str | None,
) -> str:
    payload = f"{artifact_id}:{artifact_type}:{reason}:{key_path or ''}".encode()
    return f"gap_registry_user_activity_{hashlib.sha256(payload).hexdigest()[:16]}"


def _coverage_gap(
    *,
    artifact_id: str,
    artifact_type: str,
    reason: str,
    impact: str,
    recommended_next_step: str,
    key_path: str | None = None,
) -> CoverageGap:
    return {
        "gap_id": _gap_id(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            reason=reason,
            key_path=key_path,
        ),
        "artifact_family": "registry_user_activity",
        "artifact_type": artifact_type,
        "source_artifact_id": artifact_id,
        "reason": reason,
        "impact": impact,
        "recommended_next_step": recommended_next_step,
        "registry_key_path": key_path,
    }


def _profile_fields(
    *,
    profile_id: str | None,
    profile_display_name: str | None,
    sanitized_profile_hint: str | None,
    source_candidate_ref: str | None,
) -> dict[str, JSON_SCALAR]:
    fields: dict[str, JSON_SCALAR] = {}
    for key, value in (
        ("profile_id", profile_id),
        ("profile_display_name", profile_display_name),
        ("sanitized_profile_hint", sanitized_profile_hint),
        ("source_candidate_ref", source_candidate_ref),
    ):
        if value:
            fields[key] = value
    return fields


def _add_profile_fields_to_events(
    events: list[ParserEvent],
    profile_fields: dict[str, JSON_SCALAR],
) -> list[ParserEvent]:
    if not profile_fields:
        return events
    for event in events:
        event.metadata.update(profile_fields)
    return events


def _add_profile_fields_to_gaps(
    gaps: list[CoverageGap],
    profile_fields: dict[str, JSON_SCALAR],
) -> list[CoverageGap]:
    if not profile_fields:
        return gaps
    return [dict(gap, **profile_fields) for gap in gaps]


def _record_id(
    hive: str | None,
    key_path: str | None,
    value_name: str | None,
    target: str | None,
) -> str | None:
    parts = [part for part in (hive, key_path, value_name, target) if part]
    return "|".join(parts) if parts else None


def _rot13(value: str | None) -> str | None:
    if value is None:
        return None
    decoded = codecs.decode(value, "rot_13").strip()
    return decoded or None


def _target_from_row(
    *,
    artifact_type: str,
    value_name: str | None,
    value_data: str | None,
    row: dict[str, str],
) -> str | None:
    target = _row_get(
        row,
        "DecodedValue",
        "Decoded Value",
        "DecodedName",
        "Decoded Name",
        "Target",
        "Path",
        "FilePath",
        "File Path",
        "FileName",
        "File Name",
        "ProgramName",
        "Program Name",
    )
    if target is not None:
        return target
    if artifact_type == "typedpaths":
        return value_data or value_name
    if artifact_type == "userassist":
        return _rot13(value_name) or value_data
    if value_name is not None and value_name.casefold() not in {"mrulist", "mrulistex"}:
        return value_data or value_name
    return value_data


def _timestamp_from_row(row: dict[str, str]) -> tuple[str | None, str | None, list[str]]:
    warnings: list[str] = []
    for field in (
        "LastWriteTime",
        "LastWriteTimeUtc",
        "LastWriteTimestamp",
        "Timestamp",
        "TimeStamp",
    ):
        raw_timestamp = _row_get(row, field)
        if raw_timestamp is None:
            continue
        try:
            return _normalize_timestamp(raw_timestamp), "registry_key_last_write", warnings
        except ValueError:
            warnings.append(f"invalid timestamp in {field}")
            return None, None, warnings
    return None, None, warnings


def _metadata(
    *,
    artifact_id: str,
    artifact_type: str,
    key_path: str | None,
    target: str | None,
    decoded_value: str | None,
    hive_display_ref: str | None,
    timestamp_kind: str | None,
    source_id: str | None,
    source_role: str | None,
    parser_status: str,
    source_format: str,
    row_status: str,
) -> dict[str, JSON_SCALAR]:
    metadata: dict[str, JSON_SCALAR] = {
        "artifact_family": "registry_user_activity",
        "registry_artifact_type": artifact_type,
        "source_artifact_id": artifact_id,
        "registry_key_path": key_path,
        "decoded_value": decoded_value,
        "target": target,
        "registry_hive_path": hive_display_ref,
        "timestamp_kind": timestamp_kind,
        "source_id": source_id,
        "source_role": source_role,
        "evidence_ref": f"{artifact_id}:{artifact_type}:{target or key_path or 'record'}",
        "parser_status": parser_status,
        "confidence_basis": "registry parser output",
        "interpretation_note": _INTERPRETATION_BY_ARTIFACT_TYPE[artifact_type],
        "source_format": source_format,
        "row_status": row_status,
    }
    return metadata


def _user_activity_event(
    *,
    case_id: str,
    artifact_id: str,
    artifact_type: str,
    raw_source_path: Path,
    row_number: int,
    hive: str | None,
    hive_display_ref: str | None,
    key_path: str | None,
    value_name: str | None,
    value_data: str | None,
    target: str | None,
    timestamp_utc: str | None,
    timestamp_kind: str | None,
    status: str,
    source_id: str | None,
    source_role: str | None,
    source_format: str,
) -> ParserEvent:
    metadata = _metadata(
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        key_path=key_path,
        target=target,
        decoded_value=target,
        hive_display_ref=hive_display_ref,
        timestamp_kind=timestamp_kind,
        source_id=source_id,
        source_role=source_role,
        parser_status="normalized" if status == "normalized" else status,
        source_format=source_format,
        row_status=status,
    )
    return ParserEvent(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        parser_name=PARSER_NAME,
        source_tool=SOURCE_TOOL,
        event_type=_EVENT_TYPE_BY_ARTIFACT_TYPE[artifact_type],
        timestamp_utc=timestamp_utc,
        timestamp_description=timestamp_kind,
        subject=target or value_name or key_path,
        path=target,
        key_path=key_path,
        value_name=value_name,
        value_data=value_data or target,
        evidence_refs=[artifact_id],
        raw_record_ref=RawRecordRef(
            source_path=str(raw_source_path),
            row_number=row_number,
            record_id=_record_id(hive, key_path, value_name, target),
        ),
        status=status,
        confidence="tool_reported",
        metadata=metadata,
    )


def normalize_recmd_user_activity_csv(
    *,
    csv_path: Path,
    case_id: str,
    artifact_id: str,
    artifact_type: str,
    hive_display_ref: str | None = None,
    source_id: str | None = None,
    source_role: str | None = None,
    max_events: int | None = None,
) -> tuple[list[ParserEvent], list[str], list[str], list[CoverageGap]]:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")
    artifact_type = _validate_artifact_type(artifact_type)
    max_events = _validate_max_events(max_events)

    if not csv_path.exists():
        return (
            [],
            [],
            [f"RECmd user-activity CSV does not exist: {csv_path}"],
            [
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="parser_error",
                    impact="Registry user-activity rows were not available for normalization.",
                    recommended_next_step="Review RECmd execution logs and rerun the parser.",
                )
            ],
        )
    if csv_path.is_dir():
        return (
            [],
            [],
            [f"RECmd user-activity CSV path is a directory: {csv_path}"],
            [
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="unsupported_format",
                    impact="Registry user-activity CSV input was not a file.",
                    recommended_next_step="Provide a RECmd CSV file for this artifact family.",
                )
            ],
        )

    events: list[ParserEvent] = []
    warnings: list[str] = []
    errors: list[str] = []
    gaps: list[CoverageGap] = []
    limit_reached = False
    row_count = 0

    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return (
                [],
                [],
                [f"RECmd user-activity CSV has no header row: {csv_path}"],
                [
                    _coverage_gap(
                        artifact_id=artifact_id,
                        artifact_type=artifact_type,
                        reason="unsupported_format",
                        impact="Registry user-activity CSV header was missing.",
                        recommended_next_step="Review parser output format and rerun RECmd.",
                    )
                ],
            )

        for row_number, row in enumerate(reader, start=2):
            if max_events is not None and len(events) >= max_events:
                limit_reached = True
                break
            row_count += 1
            hive = _row_get(row, "Hive")
            key_path = _row_get(row, "KeyPath", "Key Path")
            value_name = _row_get(row, "ValueName", "Value Name")
            value_data = _row_get(row, "ValueData", "Value Data", "Data")
            target = _target_from_row(
                artifact_type=artifact_type,
                value_name=value_name,
                value_data=value_data,
                row=row,
            )
            timestamp_utc, timestamp_kind, timestamp_warnings = _timestamp_from_row(row)
            for warning in timestamp_warnings:
                warnings.append(f"row {row_number}: {warning}")

            malformed = False
            if key_path is None:
                warnings.append(f"row {row_number}: missing KeyPath")
                malformed = True
            if target is None:
                warnings.append(f"row {row_number}: missing decoded target")
                gaps.append(
                    _coverage_gap(
                        artifact_id=artifact_id,
                        artifact_type=artifact_type,
                        reason="decode_error",
                        impact=(
                            "A Registry user-activity row was present but did not expose "
                            "a decoded target."
                        ),
                        recommended_next_step=(
                            "Review the raw RECmd row or use a decoder for this value type."
                        ),
                        key_path=key_path,
                    )
                )
                malformed = True

            if key_path is None and value_name is None and target is None:
                errors.append(f"row {row_number}: missing Registry row context")
                continue

            events.append(
                _user_activity_event(
                    case_id=case_id,
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    raw_source_path=csv_path,
                    row_number=row_number,
                    hive=hive,
                    hive_display_ref=hive_display_ref or hive,
                    key_path=key_path,
                    value_name=value_name,
                    value_data=value_data,
                    target=target,
                    timestamp_utc=timestamp_utc,
                    timestamp_kind=timestamp_kind,
                    status="malformed" if malformed else "normalized",
                    source_id=source_id,
                    source_role=source_role,
                    source_format="csv",
                )
            )

    if row_count == 0:
        gaps.append(
            _coverage_gap(
                artifact_id=artifact_id,
                artifact_type=artifact_type,
                reason="no_rows",
                impact="The Registry key family produced no user-activity rows.",
                recommended_next_step="Confirm whether this key family exists in the NTUSER hive.",
            )
        )
    if limit_reached:
        warnings.append(
            f"{EVENT_LIMIT_WARNING_PREFIX}{max_events} reached; "
            "remaining RECmd user-activity rows were not normalized"
        )

    return events, warnings, errors, gaps


def normalize_recmd_user_activity_json(
    *,
    json_path: Path,
    case_id: str,
    artifact_id: str,
    artifact_type: str,
    hive_display_ref: str | None,
    key_path: str,
    source_id: str | None = None,
    source_role: str | None = None,
    max_events: int | None = None,
) -> tuple[list[ParserEvent], list[str], list[str], list[CoverageGap]]:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")
    artifact_type = _validate_artifact_type(artifact_type)
    max_events = _validate_max_events(max_events)

    if not json_path.exists():
        return (
            [],
            [],
            [f"RECmd user-activity JSON does not exist: {json_path}"],
            [
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="parser_error",
                    impact="Registry user-activity JSON was not available for normalization.",
                    recommended_next_step="Review RECmd execution logs and rerun the parser.",
                    key_path=key_path,
                )
            ],
        )
    if json_path.is_dir():
        return (
            [],
            [],
            [f"RECmd user-activity JSON path is a directory: {json_path}"],
            [
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="unsupported_format",
                    impact="Registry user-activity JSON input was not a file.",
                    recommended_next_step="Provide a RECmd JSON file for this artifact family.",
                    key_path=key_path,
                )
            ],
        )

    warnings: list[str] = []
    errors: list[str] = []
    gaps: list[CoverageGap] = []
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        return (
            [],
            [],
            [f"RECmd user-activity JSON is malformed: {json_path}: {exc}"],
            [
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="unsupported_format",
                    impact="Registry user-activity JSON was malformed.",
                    recommended_next_step="Review parser output format and rerun RECmd.",
                    key_path=key_path,
                )
            ],
        )
    if not isinstance(payload, dict):
        return (
            [],
            [],
            [f"RECmd user-activity JSON root is not an object: {json_path}"],
            [
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="unsupported_format",
                    impact="Registry user-activity JSON root was not an object.",
                    recommended_next_step="Review parser output format and rerun RECmd.",
                    key_path=key_path,
                )
            ],
        )

    raw_values = payload.get("Values")
    if raw_values in (None, []):
        return (
            [],
            [],
            [],
            [
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="no_rows",
                    impact="The Registry key family produced no user-activity values.",
                    recommended_next_step=(
                        "Confirm whether this key family exists in the NTUSER hive."
                    ),
                    key_path=key_path,
                )
            ],
        )
    if not isinstance(raw_values, list):
        return (
            [],
            [],
            [f"RECmd user-activity JSON Values field is not a list: {json_path}"],
            [
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="unsupported_format",
                    impact="Registry user-activity JSON Values field was not a list.",
                    recommended_next_step="Review parser output format and rerun RECmd.",
                    key_path=key_path,
                )
            ],
        )

    timestamp_utc: str | None = None
    timestamp_kind: str | None = None
    raw_timestamp = payload.get("LastWriteTimestamp")
    if isinstance(raw_timestamp, str) and raw_timestamp.strip():
        try:
            timestamp_utc = _normalize_timestamp(raw_timestamp)
            timestamp_kind = "registry_key_last_write"
        except ValueError:
            warnings.append("json key: invalid timestamp in LastWriteTimestamp")

    events: list[ParserEvent] = []
    limit_reached = False
    for value_index, item in enumerate(raw_values, start=1):
        if max_events is not None and len(events) >= max_events:
            limit_reached = True
            break
        if not isinstance(item, dict):
            warnings.append(f"json value {value_index}: value record is not an object")
            continue
        value_name = item.get("ValueName")
        value_data = item.get("ValueData")
        decoded_value = item.get("DecodedValue") or item.get("DecodedName")
        row = {
            "ValueName": value_name if isinstance(value_name, str) else "",
            "ValueData": value_data if isinstance(value_data, str) else "",
            "DecodedValue": decoded_value if isinstance(decoded_value, str) else "",
            "KeyPath": key_path,
        }
        normalized_value_name = value_name.strip() if isinstance(value_name, str) else None
        normalized_value_data = value_data.strip() if isinstance(value_data, str) else None
        target = _target_from_row(
            artifact_type=artifact_type,
            value_name=normalized_value_name,
            value_data=normalized_value_data,
            row=row,
        )
        malformed = target is None
        if malformed:
            gaps.append(
                _coverage_gap(
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    reason="decode_error",
                    impact=(
                        "A Registry user-activity JSON value was present but did not "
                        "expose a decoded target."
                    ),
                    recommended_next_step=(
                        "Review the raw RECmd JSON value or use a decoder for this value type."
                    ),
                    key_path=key_path,
                )
            )

        events.append(
            _user_activity_event(
                case_id=case_id,
                artifact_id=artifact_id,
                artifact_type=artifact_type,
                raw_source_path=json_path,
                row_number=value_index,
                hive=hive_display_ref,
                hive_display_ref=hive_display_ref,
                key_path=key_path,
                value_name=normalized_value_name,
                value_data=normalized_value_data,
                target=target,
                timestamp_utc=timestamp_utc,
                timestamp_kind=timestamp_kind,
                status="malformed" if malformed else "normalized",
                source_id=source_id,
                source_role=source_role,
                source_format="json",
            )
        )

    if limit_reached:
        warnings.append(
            f"{EVENT_LIMIT_WARNING_PREFIX}{max_events} reached; "
            "remaining RECmd user-activity JSON values were not normalized"
        )
    return events, warnings, errors, gaps


def _targets_for_hive(hive_path: Path) -> tuple[UserActivityTarget, ...]:
    if hive_path.name.lower() == "ntuser.dat":
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
        "not found",
        "bad registry hive signature",
        "unable to process",
        "failed to process",
    ):
        if phrase in text:
            return phrase
    return None


def _tool_error(tool_result: ToolResult, target: UserActivityTarget) -> str:
    return (
        f"RECmd target {target.label} failed with status={tool_result.status} "
        f"exit_code={tool_result.exit_code}"
    )


def _skipped_result(
    *,
    case_id: str,
    artifact_id: str,
    reason: str,
    coverage_gaps: list[CoverageGap] | None = None,
) -> ParserResult:
    return ParserResult(
        case_id=case_id,
        artifact_id=artifact_id,
        artifact_type=OUTPUT_ARTIFACT_TYPE,
        parser_name=PARSER_NAME,
        source_tool=SOURCE_TOOL,
        status="skipped",
        errors=[reason],
        coverage_gaps=list(coverage_gaps or []),
    )


def _display_key_path(target: UserActivityTarget) -> str:
    return f"HKCU\\{target.key_path}"


def _parser_unavailable_gaps(
    artifact_id: str,
    targets: Sequence[UserActivityTarget],
) -> list[CoverageGap]:
    return [
        _coverage_gap(
            artifact_id=artifact_id,
            artifact_type=target.artifact_type,
            reason="parser_unavailable",
            impact="Registry user-activity key family was not parsed.",
            recommended_next_step="Install or configure RECmd, then rerun agent run-case.",
            key_path=_display_key_path(target),
        )
        for target in targets
    ]


def parse_registry_user_activity(
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
    source_id: str | None = None,
    source_role: str | None = "disk_image",
    profile_id: str | None = None,
    profile_display_name: str | None = None,
    sanitized_profile_hint: str | None = None,
    source_candidate_ref: str | None = None,
    max_events: int | None = None,
) -> ParserResult:
    _require_non_empty(case_id, "case_id")
    _require_non_empty(artifact_id, "artifact_id")
    max_events = _validate_max_events(max_events)

    if artifact_type not in ACCEPTED_INPUT_ARTIFACT_TYPES:
        return _skipped_result(
            case_id=case_id,
            artifact_id=artifact_id,
            reason=(
                "Registry user-activity parser accepts artifact_type in "
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
                "Registry user-activity parser supports NTUSER.DAT hives, "
                f"got {resolved_hive_path.name}"
            ),
        )
    profile_fields = _profile_fields(
        profile_id=profile_id,
        profile_display_name=profile_display_name,
        sanitized_profile_hint=sanitized_profile_hint,
        source_candidate_ref=source_candidate_ref,
    )

    try:
        command_base = resolve_parser_command(PARSER_NAME, command_config)
    except (KeyError, TypeError, ValueError) as exc:
        result = ParserResult.missing_command(
            case_id=case_id,
            artifact_id=artifact_id,
            artifact_type=OUTPUT_ARTIFACT_TYPE,
            parser_name=PARSER_NAME,
            source_tool=SOURCE_TOOL,
            reason=f"RECmd command is not available: {exc}",
            coverage_gaps=_add_profile_fields_to_gaps(
                _parser_unavailable_gaps(artifact_id, targets),
                profile_fields,
            ),
        )
        result.metadata.update(profile_fields)
        return result

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
    coverage_gaps: list[CoverageGap] = []
    successful_command_count = 0
    failed_command_count = 0
    missing_output_count = 0
    duration_ms = 0

    for target in targets:
        if max_events is not None and len(events) >= max_events:
            break

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
            warnings.append(f"RECmd target {target.label} stdout reported: {stdout_error}")

        remaining = None if max_events is None else max(max_events - len(events), 0)
        if csv_path.exists():
            target_events, target_warnings, target_errors, target_gaps = (
                normalize_recmd_user_activity_csv(
                    csv_path=csv_path,
                    case_id=case_id,
                    artifact_id=artifact_id,
                    artifact_type=target.artifact_type,
                    hive_display_ref=resolved_hive_path.name,
                    source_id=source_id,
                    source_role=source_role,
                    max_events=remaining,
                )
            )
            target_events = _add_profile_fields_to_events(target_events, profile_fields)
            target_gaps = _add_profile_fields_to_gaps(target_gaps, profile_fields)
            events.extend(target_events)
            warnings.extend(f"{target.label}: {warning}" for warning in target_warnings)
            errors.extend(f"{target.label}: {error}" for error in target_errors)
            coverage_gaps.extend(target_gaps)
            if target_failed:
                warnings.append(f"RECmd command failed but {target.csv_name} was present")
                errors.append(_tool_error(tool_result, target))
        elif json_path.exists():
            target_events, target_warnings, target_errors, target_gaps = (
                normalize_recmd_user_activity_json(
                    json_path=json_path,
                    case_id=case_id,
                    artifact_id=artifact_id,
                    artifact_type=target.artifact_type,
                    hive_display_ref=resolved_hive_path.name,
                    key_path=_display_key_path(target),
                    source_id=source_id,
                    source_role=source_role,
                    max_events=remaining,
                )
            )
            target_events = _add_profile_fields_to_events(target_events, profile_fields)
            target_gaps = _add_profile_fields_to_gaps(target_gaps, profile_fields)
            events.extend(target_events)
            warnings.extend(f"{target.label}: {warning}" for warning in target_warnings)
            errors.extend(f"{target.label}: {error}" for error in target_errors)
            coverage_gaps.extend(target_gaps)
            if target_failed:
                warnings.append(f"RECmd command failed but {target.json_name} was present")
                errors.append(_tool_error(tool_result, target))
        else:
            missing_output_count += 1
            reason = "key_absent" if stdout_error in {"does not exist", "not found"} else "no_rows"
            if target_failed:
                reason = "parser_error" if reason == "no_rows" else reason
            coverage_gaps.append(
                _add_profile_fields_to_gaps(
                    [
                        _coverage_gap(
                            artifact_id=artifact_id,
                            artifact_type=target.artifact_type,
                            reason=reason,
                            impact=(
                                "Registry user-activity key family did not produce "
                                "parser rows."
                            ),
                            recommended_next_step=(
                                "Confirm the key exists in the NTUSER hive or review "
                                "RECmd logs."
                            ),
                            key_path=_display_key_path(target),
                        )
                    ],
                    profile_fields,
                )[0]
            )
            warnings.append(
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

    if events:
        status = (
            "partial_success"
            if warnings or errors or coverage_gaps or failed_command_count > 0
            else "success"
        )
    elif errors and not coverage_gaps:
        status = "failed"
    else:
        status = "partial_success"

    metadata: dict[str, JSON_SCALAR] = {
        "artifact_family": "registry_user_activity",
        "command_count": len(commands),
        "successful_command_count": successful_command_count,
        "failed_command_count": failed_command_count,
        "missing_output_count": missing_output_count,
        "coverage_gap_count": len(coverage_gaps),
        "max_events": max_events,
        "source_rows_seen": len(events),
        "source_events_seen": len(events),
    }
    metadata.update(profile_fields)
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
        coverage_gaps=coverage_gaps,
        started_at_utc=started_at_utc,
        ended_at_utc=ended_at_utc,
        duration_ms=duration_ms,
        metadata=metadata,
    )


def parse_registry_user_activity_artifact(
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
    if artifact.artifact_type not in ACCEPTED_INPUT_ARTIFACT_TYPES:
        raise ValueError(
            "expected artifact_type in "
            f"{sorted(ACCEPTED_INPUT_ARTIFACT_TYPES)}, got {artifact.artifact_type}"
        )
    return parse_registry_user_activity(
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
        source_id=artifact.source_image_id,
        source_role="disk_image",
        profile_id=artifact.profile_id,
        profile_display_name=artifact.profile_display_name,
        sanitized_profile_hint=artifact.sanitized_profile_hint,
        source_candidate_ref=artifact.source_candidate_ref,
        max_events=max_events,
    )
