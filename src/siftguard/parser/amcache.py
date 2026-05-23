from __future__ import annotations

from siftguard.parser.result import ParserResult

PARSER_NAME = "amcache_parser"
EXPECTED_ARTIFACT_TYPE = "amcache"


def parse_amcache(*args, **kwargs) -> ParserResult:
    raise NotImplementedError("Parser wrapper not implemented yet. This will be completed in M2.")
