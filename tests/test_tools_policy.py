from __future__ import annotations

import sys

from siftguard.policy.tools import is_command_allowed


def test_harmless_command_allowed():
    allowed, reason = is_command_allowed([sys.executable, "--version"])
    assert allowed
    assert reason == "allowed"


def test_forbidden_executable_denied():
    allowed, reason = is_command_allowed(["sudo", "ls"])
    assert not allowed
    assert "forbidden executable" in reason


def test_shell_metacharacter_denied():
    allowed, reason = is_command_allowed(["echo", "hello|wc"])
    assert not allowed
    assert "forbidden shell token" in reason


def test_string_command_denied():
    allowed, reason = is_command_allowed("ls -la")
    assert not allowed
    assert "not a string" in reason


def test_empty_command_denied():
    allowed, reason = is_command_allowed([])
    assert not allowed
    assert "empty" in reason
