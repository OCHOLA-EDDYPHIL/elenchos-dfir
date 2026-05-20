from __future__ import annotations

from pathlib import Path
from typing import Sequence

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
}

FORBIDDEN_TOKENS = {
    ";",
    "&&",
    "||",
    "|",
    ">",
    ">>",
    "<",
    "$()",
    "`",
}


def is_command_allowed(command: Sequence[str]) -> tuple[bool, str]:
    if not command:
        return False, "command is empty"

    if not all(isinstance(item, str) for item in command):
        return False, "command must be Sequence[str]"

    executable = Path(command[0]).name.lower()
    if executable in FORBIDDEN_EXECUTABLES:
        return False, f"forbidden executable: {executable}"

    for token in command:
        if "$(" in token or "`" in token:
            return False, "forbidden shell expression token"

        for forbidden in FORBIDDEN_TOKENS:
            if forbidden in token:
                return False, f"forbidden token in command: {forbidden}"

    return True, "allowed"
