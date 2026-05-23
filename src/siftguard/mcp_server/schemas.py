from __future__ import annotations

from dataclasses import dataclass, field

TOOL_NAMES = [
    "create_case",
    "hash_evidence",
    "inventory_artifacts",
    "parse_mft",
    "parse_registry_runkeys",
    "parse_amcache",
    "correlate_timeline",
    "validate_findings",
    "generate_report",
]

PARSER_TOOL_NAMES = ("parse_mft", "parse_registry_runkeys", "parse_amcache")


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    name: str
    description: str
    title: str = ""
    input_schema: dict[str, object] = field(default_factory=dict)
    output_schema: dict[str, object] | None = None
    annotations: dict[str, object] | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("tool descriptor name must be non-empty")
        if not self.description:
            raise ValueError("tool descriptor description must be non-empty")
        if not self.title:
            object.__setattr__(self, "title", self.name.replace("_", " ").title())


def _nullable_string(description: str) -> dict[str, object]:
    return {
        "description": description,
        "anyOf": [{"type": "string"}, {"type": "null"}],
    }


def _path_string(description: str) -> dict[str, object]:
    return {"type": "string", "description": description}


def _timeout_schema() -> dict[str, object]:
    return {
        "type": "integer",
        "minimum": 1,
        "default": 900,
        "description": "Maximum parser runtime in seconds.",
    }


def _base_parser_properties() -> dict[str, object]:
    return {
        "case_id": {"type": "string", "description": "Case identifier."},
        "artifact_id": {"type": "string", "description": "Source artifact identifier."},
        "runs_root": _path_string("Directory where parser outputs must be written."),
        "evidence_root": _nullable_string("Optional evidence root for output safety checks."),
        "ledger_path": _nullable_string("Optional audit ledger JSONL path."),
        "timeout_seconds": _timeout_schema(),
        "json_out": _nullable_string("Optional ParserResult JSON path under runs_root."),
    }


def _parser_input_schema(
    *,
    artifact_path_name: str,
    artifact_path_description: str,
    extra_properties: dict[str, object] | None = None,
) -> dict[str, object]:
    properties = _base_parser_properties()
    properties[artifact_path_name] = _path_string(artifact_path_description)
    if extra_properties:
        properties.update(extra_properties)
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": ["case_id", "artifact_id", artifact_path_name, "runs_root"],
    }


def _parser_output_schema() -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "case_id": {"type": "string"},
            "artifact_id": {"type": "string"},
            "artifact_type": {"type": "string"},
            "parser_name": {"type": "string"},
            "source_tool": {"type": "string"},
            "status": {
                "type": "string",
                "enum": ["success", "partial_success", "skipped", "failed"],
            },
            "output_dir": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "output_files": {"type": "array", "items": {"type": "string"}},
            "output_hashes": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
            "event_count": {"type": "integer", "minimum": 0},
            "events": {"type": "array", "items": {"type": "object"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "errors": {"type": "array", "items": {"type": "string"}},
            "started_at_utc": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "ended_at_utc": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "duration_ms": {"anyOf": [{"type": "integer", "minimum": 0}, {"type": "null"}]},
            "metadata": {"type": "object"},
        },
        "required": [
            "case_id",
            "artifact_id",
            "artifact_type",
            "parser_name",
            "source_tool",
            "status",
            "event_count",
            "events",
            "warnings",
            "errors",
        ],
    }


def _placeholder_descriptor(name: str) -> ToolDescriptor:
    return ToolDescriptor(
        name=name,
        title=name.replace("_", " ").title(),
        description="Planned SIFTGuard tool descriptor.",
        input_schema={"type": "object", "additionalProperties": False, "properties": {}},
    )


def _parser_descriptors() -> dict[str, ToolDescriptor]:
    output_schema = _parser_output_schema()
    return {
        "parse_mft": ToolDescriptor(
            name="parse_mft",
            title="Parse MFT",
            description=(
                "Parse a supplied MFT artifact with the constrained parser wrapper and "
                "return normalized observational parser events. Outputs are scoped under runs."
            ),
            input_schema=_parser_input_schema(
                artifact_path_name="mft_path",
                artifact_path_description="Path to the supplied MFT artifact.",
            ),
            output_schema=output_schema,
            annotations={"readOnlyHint": True},
        ),
        "parse_registry_runkeys": ToolDescriptor(
            name="parse_registry_runkeys",
            title="Parse Registry Run Keys",
            description=(
                "Parse supplied SOFTWARE or NTUSER.DAT hive Run and RunOnce values with the "
                "constrained parser wrapper and return normalized observational parser events. "
                "Outputs are scoped under runs."
            ),
            input_schema=_parser_input_schema(
                artifact_path_name="hive_path",
                artifact_path_description="Path to the supplied SOFTWARE or NTUSER.DAT hive.",
                extra_properties={
                    "artifact_type": {
                        "type": "string",
                        "enum": ["registry_hive", "registry"],
                        "default": "registry_hive",
                        "description": "Input artifact type.",
                    },
                },
            ),
            output_schema=output_schema,
            annotations={"readOnlyHint": True},
        ),
        "parse_amcache": ToolDescriptor(
            name="parse_amcache",
            title="Parse Amcache",
            description=(
                "Parse a supplied Amcache hive with the constrained parser wrapper and return "
                "normalized observational parser events. Outputs are scoped under runs."
            ),
            input_schema=_parser_input_schema(
                artifact_path_name="amcache_path",
                artifact_path_description="Path to the supplied Amcache artifact.",
            ),
            output_schema=output_schema,
            annotations={"readOnlyHint": True},
        ),
    }


def get_tool_descriptors() -> list[ToolDescriptor]:
    parser_descriptors = _parser_descriptors()
    return [
        parser_descriptors.get(tool_name, _placeholder_descriptor(tool_name))
        for tool_name in TOOL_NAMES
    ]


def get_parser_tool_descriptors() -> list[ToolDescriptor]:
    parser_descriptors = _parser_descriptors()
    return [parser_descriptors[name] for name in PARSER_TOOL_NAMES]


def get_tool_descriptor(name: str) -> ToolDescriptor:
    for descriptor in get_tool_descriptors():
        if descriptor.name == name:
            return descriptor
    raise KeyError(f"unknown tool descriptor: {name}")


def to_mcp_tool(descriptor: ToolDescriptor) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": descriptor.name,
        "title": descriptor.title,
        "description": descriptor.description,
        "inputSchema": descriptor.input_schema,
    }
    if descriptor.output_schema is not None:
        payload["outputSchema"] = descriptor.output_schema
    if descriptor.annotations is not None:
        payload["annotations"] = descriptor.annotations
    return payload
