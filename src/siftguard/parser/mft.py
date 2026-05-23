from __future__ import annotations

from siftguard.parser.result import ParserResult

PARSER_NAME = "mft_parser"
EXPECTED_ARTIFACT_TYPE = "mft"


def parse_mft(*args, **kwargs) -> ParserResult:
    raise NotImplementedError("Parser wrapper not implemented yet. This will be completed in M2.")
