from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

SHELL_FORBIDDEN_TOKENS = (";", "&", "|", ">", "<", "`", "$", "\n", "\r")
ARG_FORBIDDEN_TOKENS = SHELL_FORBIDDEN_TOKENS + ("\x00",)

PARSER_ENV_OVERRIDES = {
    "mftecmd": "SIFTGUARD_MFT_PARSER",
    "recmd": "SIFTGUARD_REGISTRY_PARSER",
    "amcacheparser": "SIFTGUARD_AMCACHE_PARSER",
}


def _validate_parser_name(parser_name: str) -> str:
    if not isinstance(parser_name, str) or not parser_name:
        raise ValueError("parser_name must be a non-empty string")
    normalized = parser_name.lower()
    if normalized != parser_name:
        raise ValueError("parser_name must be lowercase")
    return normalized


def _validate_executable(executable: str) -> str:
    if not isinstance(executable, str) or not executable:
        raise ValueError("executable must be a non-empty string")
    if executable != executable.strip():
        raise ValueError("executable must not contain leading or trailing whitespace")
    for token in SHELL_FORBIDDEN_TOKENS:
        if token in executable:
            raise ValueError(f"executable contains forbidden shell token: {token}")
    if any(char.isspace() for char in executable):
        raise ValueError("executable must be a single argv element, not a command string")
    return executable


def _validate_args(args: Sequence[str]) -> tuple[str, ...]:
    if isinstance(args, str):
        raise TypeError("base_args must be a sequence of strings, not a shell string")
    if not isinstance(args, Sequence):
        raise TypeError("base_args must be a sequence of strings")

    normalized: list[str] = []
    for arg in args:
        if not isinstance(arg, str):
            raise TypeError("base_args must contain only strings")
        for token in ARG_FORBIDDEN_TOKENS:
            if token in arg:
                raise ValueError(f"base_args contains forbidden token: {token}")
        normalized.append(arg)
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class ParserToolCommand:
    parser_name: str
    executable: str
    base_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "parser_name", _validate_parser_name(self.parser_name))
        object.__setattr__(self, "executable", _validate_executable(self.executable))
        object.__setattr__(self, "base_args", _validate_args(self.base_args))

    def argv(self) -> tuple[str, ...]:
        return (self.executable, *self.base_args)


@dataclass(frozen=True, slots=True)
class ParserCommandConfig:
    tools: Mapping[str, ParserToolCommand] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized: dict[str, ParserToolCommand] = {}
        for parser_name, command in self.tools.items():
            safe_name = _validate_parser_name(parser_name)
            if not isinstance(command, ParserToolCommand):
                raise TypeError("tools values must be ParserToolCommand instances")
            if command.parser_name != safe_name:
                raise ValueError("tool mapping key must match ParserToolCommand parser_name")
            normalized[safe_name] = command
        object.__setattr__(self, "tools", normalized)


def default_parser_command_config(
    environ: Mapping[str, str] | None = None,
) -> ParserCommandConfig:
    env = os.environ if environ is None else environ
    defaults = {
        "mftecmd": ParserToolCommand("mftecmd", "MFTECmd"),
        "recmd": ParserToolCommand("recmd", "RECmd"),
        "amcacheparser": ParserToolCommand("amcacheparser", "AmcacheParser"),
    }

    configured: dict[str, ParserToolCommand] = {}
    for parser_name, command in defaults.items():
        env_name = PARSER_ENV_OVERRIDES[parser_name]
        executable = env.get(env_name, command.executable)
        configured[parser_name] = ParserToolCommand(
            parser_name=parser_name,
            executable=executable,
            base_args=command.base_args,
        )

    return ParserCommandConfig(configured)


def resolve_parser_command(
    parser_name: str,
    config: ParserCommandConfig | None = None,
) -> tuple[str, ...]:
    safe_name = _validate_parser_name(parser_name)
    resolved_config = config or default_parser_command_config()
    command = resolved_config.tools.get(safe_name)
    if command is None:
        raise KeyError(f"parser command is not configured: {safe_name}")
    return command.argv()
