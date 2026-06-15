from __future__ import annotations

import pytest

from elenchos.parser.config import (
    ParserCommandConfig,
    ParserToolCommand,
    default_parser_command_config,
    resolve_parser_command,
)


def test_default_parser_command_config_returns_argv_tuples():
    config = default_parser_command_config(environ={})

    assert resolve_parser_command("mftecmd", config) == ("MFTECmd",)
    assert resolve_parser_command("recmd", config) == ("RECmd",)
    assert resolve_parser_command("amcacheparser", config) == ("AmcacheParser",)


def test_parser_command_config_supports_safe_env_override():
    config = default_parser_command_config(
        environ={"ELENCHOS_MFT_PARSER": "/usr/local/bin/MFTECmd"}
    )

    assert resolve_parser_command("mftecmd", config) == ("/usr/local/bin/MFTECmd",)


def test_parser_command_config_rejects_malicious_env_override():
    with pytest.raises(ValueError, match="forbidden shell token"):
        default_parser_command_config(
            environ={"ELENCHOS_MFT_PARSER": "MFTECmd; rm -rf ..."}
        )


def test_parser_tool_command_rejects_single_command_string():
    with pytest.raises(ValueError, match="single argv element"):
        ParserToolCommand("mftecmd", "MFTECmd -f file --csv out")


def test_parser_tool_command_rejects_shell_metacharacters_in_args():
    with pytest.raises(ValueError, match="forbidden token"):
        ParserToolCommand("mftecmd", "MFTECmd", ("--csv", "out;rm"))


def test_parser_tool_command_rejects_string_base_args():
    with pytest.raises(TypeError, match="not a shell string"):
        ParserToolCommand("mftecmd", "MFTECmd", "--help")


def test_custom_parser_command_config_resolves_base_args():
    config = ParserCommandConfig(
        {
            "recmd": ParserToolCommand(
                parser_name="recmd",
                executable="RECmd",
                base_args=("--nl",),
            )
        }
    )

    assert resolve_parser_command("recmd", config) == ("RECmd", "--nl")


def test_resolve_parser_command_rejects_unknown_parser():
    with pytest.raises(KeyError, match="not configured"):
        resolve_parser_command("unknown", ParserCommandConfig({}))
