from __future__ import annotations

from typing import Any

from elenchos.mcp_server import schemas

FORBIDDEN_EXECUTION_FIELDS = {"command", "cmd", "argv", "shell", "executable"}
FORBIDDEN_REGISTRY_FIELDS = {"bn", "batch_file_path", "sync"}


def walk_schema_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key))
            keys.update(walk_schema_keys(child))
    elif isinstance(value, list):
        for item in value:
            keys.update(walk_schema_keys(item))
    return keys


def parser_descriptors_by_name() -> dict[str, schemas.ToolDescriptor]:
    return {descriptor.name: descriptor for descriptor in schemas.get_parser_tool_descriptors()}


def test_tool_names_include_parser_tools():
    assert {"parse_mft", "parse_registry_runkeys", "parse_amcache"}.issubset(
        set(schemas.TOOL_NAMES)
    )


def test_parser_tool_descriptors_have_required_fields():
    descriptors = parser_descriptors_by_name()

    assert set(descriptors) == {"parse_mft", "parse_registry_runkeys", "parse_amcache"}
    for descriptor in descriptors.values():
        assert descriptor.name
        assert descriptor.title
        assert descriptor.description
        assert descriptor.input_schema
        assert descriptor.output_schema


def test_to_mcp_tool_uses_mcp_schema_field_names():
    descriptor = parser_descriptors_by_name()["parse_mft"]

    payload = schemas.to_mcp_tool(descriptor)

    assert payload["name"] == "parse_mft"
    assert payload["title"]
    assert payload["description"]
    assert payload["inputSchema"] == descriptor.input_schema
    assert payload["outputSchema"] == descriptor.output_schema


def schema_required(descriptor_name: str) -> list[str]:
    required = parser_descriptors_by_name()[descriptor_name].input_schema["required"]
    assert isinstance(required, list)
    return [str(item) for item in required]


def test_parse_mft_input_schema_requires_safe_fields():
    assert schema_required("parse_mft") == ["case_id", "artifact_id", "mft_path", "runs_root"]


def test_parse_registry_runkeys_input_schema_requires_safe_fields():
    assert schema_required("parse_registry_runkeys") == [
        "case_id",
        "artifact_id",
        "hive_path",
        "runs_root",
    ]


def test_parse_amcache_input_schema_requires_safe_fields():
    assert schema_required("parse_amcache") == [
        "case_id",
        "artifact_id",
        "amcache_path",
        "runs_root",
    ]


def test_parser_schemas_do_not_expose_execution_fields():
    for descriptor in schemas.get_parser_tool_descriptors():
        input_keys = walk_schema_keys(descriptor.input_schema)
        output_keys = walk_schema_keys(descriptor.output_schema)
        assert not (input_keys & FORBIDDEN_EXECUTION_FIELDS)
        assert not (output_keys & FORBIDDEN_EXECUTION_FIELDS)


def test_registry_schema_does_not_expose_batch_or_sync_fields():
    descriptor = parser_descriptors_by_name()["parse_registry_runkeys"]
    keys = walk_schema_keys(descriptor.input_schema)

    assert not (keys & FORBIDDEN_REGISTRY_FIELDS)


def test_output_schema_status_enum_matches_parser_result_statuses():
    descriptor = parser_descriptors_by_name()["parse_mft"]
    output_schema = descriptor.output_schema
    assert output_schema is not None
    properties = output_schema["properties"]
    assert isinstance(properties, dict)
    status_schema = properties["status"]
    assert isinstance(status_schema, dict)

    assert status_schema["enum"] == ["success", "partial_success", "skipped", "failed"]


def test_parser_schema_descriptions_avoid_conclusion_claims():
    forbidden_terms = (
        "mal" + "ware",
        "attack" + "er",
        "comprom" + "ised",
        "exfil" + "tration",
        "persistence " + "confirmed",
        "executed " + "confirmed",
        "sus" + "picious",
    )

    for descriptor in schemas.get_parser_tool_descriptors():
        text = " ".join(
            [
                descriptor.title,
                descriptor.description,
                str(descriptor.input_schema),
                str(descriptor.output_schema),
            ]
        ).lower()
        for term in forbidden_terms:
            assert term not in text


def test_get_tool_descriptor_and_schema_import_without_runtime_dependencies():
    descriptor = schemas.get_tool_descriptor("parse_amcache")
    assert descriptor.name == "parse_amcache"

    all_descriptors: list[Any] = schemas.get_tool_descriptors()
    assert len(all_descriptors) == len(schemas.TOOL_NAMES)
