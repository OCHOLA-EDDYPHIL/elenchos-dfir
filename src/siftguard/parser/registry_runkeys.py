from __future__ import annotations

from siftguard.parser.result import ParserResult

PARSER_NAME = "registry_runkeys_parser"
EXPECTED_ARTIFACT_TYPE = "registry_hive"


def parse_registry_runkeys(*args, **kwargs) -> ParserResult:
    raise NotImplementedError("Parser wrapper not implemented yet. This will be completed in M2.")
