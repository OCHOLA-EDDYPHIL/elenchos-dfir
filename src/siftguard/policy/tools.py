from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

FORBIDDEN_EXECUTABLES = {
    "rm",
    "dd",
    "mkfs",
    "shred",
    "wipefs",
    "curl",
    "wget",
    "ssh",
    "scp",
    "nc",
    "ncat",
    "socat",
    "ftp",
    "sftp",
    "rsync",
    "chmod",
    "chown",
    "sudo",
    "su",
}

FORBIDDEN_TOKENS = {
    ";",
    "&&",
    "||",
    "|",
    ">",
    ">>",
    "<",
    "$(",
    "`",
    "${",
}


def is_command_allowed(command: Sequence[str]) -> tuple[bool, str]:
    if isinstance(command, str):
        return False, "command must be a non-empty sequence of strings, not a string"

    if not isinstance(command, Sequence):
        return False, "command must be a non-empty sequence of strings"

    if len(command) == 0:
        return False, "command is empty"

    if not all(isinstance(item, str) for item in command):
        return False, "command must contain only strings"

    executable = Path(command[0]).name.lower()
    if executable in FORBIDDEN_EXECUTABLES:
        return False, f"forbidden executable: {executable}"

    ordered_tokens = sorted(FORBIDDEN_TOKENS, key=len, reverse=True)
    for token in command:
        for forbidden in ordered_tokens:
            if forbidden in token:
                return False, f"forbidden shell token detected: {forbidden}"

    return True, "allowed"
