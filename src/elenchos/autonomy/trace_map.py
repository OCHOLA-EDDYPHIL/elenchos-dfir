"""Build ``trace_map.json`` -- report claim -> finding -> evidence ref -> normalized
event -> tool execution -> artifact hash.

This is a pure *join* over artifacts the deterministic engine already emits
(``report.md``, ``findings.json``, ``normalized_events.json``, ``audit.jsonl``); it
captures no new data. Its purpose is to let a reviewer confirm that every final
report claim resolves to concrete deterministic evidence, and that no claim rests on
model narration alone.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from elenchos.agent.verifier import REPORT_FINDING_RE
from elenchos.audit.execution_ledger import utc_now
from elenchos.integrations.rationale_trace import iter_jsonl, safe_read_json

TRACE_MAP_SCHEMA_VERSION = 1


def _reported_finding_ids(report_path: Path) -> list[str]:
    if not report_path.exists():
        return []
    ids: list[str] = []
    for line in report_path.read_text(encoding="utf-8").splitlines():
        match = REPORT_FINDING_RE.match(line)
        if match is not None:
            ids.append(match.group(1))
    return ids


def _findings(agent_run_dir: Path) -> dict[str, dict[str, Any]]:
    payload = safe_read_json(agent_run_dir / "findings.json") or {}
    rows = payload.get("findings")
    findings: dict[str, dict[str, Any]] = {}
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("finding_id"), str):
                findings[row["finding_id"]] = row
    return findings


def _normalized_events(agent_run_dir: Path) -> list[dict[str, Any]]:
    payload = safe_read_json(agent_run_dir / "normalized_events.json") or {}
    rows = payload.get("events", payload.get("normalized_events"))
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return []


def _tool_executions(agent_run_dir: Path) -> list[dict[str, Any]]:
    """Audit entries that represent a real tool/parse execution."""
    path = agent_run_dir / "audit.jsonl"
    if not path.exists():
        return []
    try:
        rows = iter_jsonl(path)
    except ValueError:
        return []
    executions: list[dict[str, Any]] = []
    for row in rows:
        event_type = str(row.get("event_type", ""))
        has_tool = bool(row.get("tool_name")) or bool(row.get("command"))
        is_parse_step = row.get("phase") == "parse" and event_type.startswith("agent_step")
        if has_tool or is_parse_step:
            executions.append(row)
    return executions


def _event_matches_ref(event: dict[str, Any], ref: dict[str, Any]) -> bool:
    event_id = event.get("event_id")
    for key in ("evidence_id", "artifact_id", "raw_record_ref"):
        value = ref.get(key)
        if not value:
            continue
        if value == event_id or value == event.get("artifact_id"):
            return True
        if key == "raw_record_ref" and value == event.get("raw_record_ref"):
            return True
    artifact_id = ref.get("artifact_id")
    return bool(artifact_id) and artifact_id == event.get("artifact_id")


def _claim_chain(
    finding: dict[str, Any],
    *,
    events: list[dict[str, Any]],
    parse_executions: list[dict[str, Any]],
) -> dict[str, Any]:
    evidence_refs = finding.get("evidence_refs") or []
    if not isinstance(evidence_refs, list):
        evidence_refs = []
    matched_event_ids: list[str] = []
    for ref in evidence_refs:
        if not isinstance(ref, dict):
            continue
        for event in events:
            if _event_matches_ref(event, ref) and event.get("event_id"):
                event_id = str(event["event_id"])
                if event_id not in matched_event_ids:
                    matched_event_ids.append(event_id)
    artifact_hashes = [h for h in (finding.get("artifact_hashes") or []) if isinstance(h, str)]
    # Any parse-phase/tool execution is the deterministic step that produced the events.
    execution_ids = [
        str(row.get("event_id"))
        for row in parse_executions
        if row.get("event_id")
    ]
    status = finding.get("status")
    supports_final_report = finding.get("supports_final_report") is True
    resolved = bool(
        evidence_refs
        and matched_event_ids
        and execution_ids
        and (artifact_hashes or any(True for _ in matched_event_ids))
    )
    return {
        "finding_id": finding.get("finding_id"),
        "claim": finding.get("claim"),
        "status": status,
        "supports_final_report": supports_final_report,
        "evidence_refs": [dict(ref) for ref in evidence_refs if isinstance(ref, dict)],
        "normalized_event_ids": matched_event_ids,
        "tool_execution_ids": execution_ids,
        "artifact_hashes": artifact_hashes,
        "resolved": resolved,
    }


def build_trace_map(agent_run_dir: Path, *, clock=utc_now) -> dict[str, Any]:
    findings = _findings(agent_run_dir)
    events = _normalized_events(agent_run_dir)
    executions = _tool_executions(agent_run_dir)
    reported_ids = _reported_finding_ids(agent_run_dir / "report.md")

    claims: list[dict[str, Any]] = []
    unresolved: list[str] = []
    seen: set[str] = set()
    for finding_id in reported_ids:
        if finding_id in seen:
            continue
        seen.add(finding_id)
        finding = findings.get(finding_id)
        if finding is None:
            unresolved.append(finding_id)
            claims.append(
                {
                    "finding_id": finding_id,
                    "claim": None,
                    "status": None,
                    "supports_final_report": False,
                    "evidence_refs": [],
                    "normalized_event_ids": [],
                    "tool_execution_ids": [],
                    "artifact_hashes": [],
                    "resolved": False,
                }
            )
            continue
        chain = _claim_chain(finding, events=events, parse_executions=executions)
        claims.append(chain)
        if chain["supports_final_report"] and not chain["resolved"]:
            unresolved.append(finding_id)

    case_payload = safe_read_json(agent_run_dir / "findings.json") or {}
    supported_claims = [c for c in claims if c["supports_final_report"]]
    all_supported_resolved = bool(supported_claims) and all(
        c["resolved"] for c in supported_claims
    )
    return {
        "schema_version": TRACE_MAP_SCHEMA_VERSION,
        "case_id": case_payload.get("case_id"),
        "generated_at_utc": clock(),
        "reported_claim_count": len(claims),
        "supported_claim_count": len(supported_claims),
        "all_supported_claims_resolved": all_supported_resolved,
        "claims": claims,
        "unresolved_supported_claims": unresolved,
    }


def write_trace_map(agent_run_dir: Path, *, clock=utc_now) -> dict[str, Any]:
    from elenchos.autonomy.bundle import trace_map_path

    payload = build_trace_map(agent_run_dir, clock=clock)
    path = trace_map_path(agent_run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload
