from __future__ import annotations

import pytest

from elenchos.config.runtime import (
    DEFAULT_PARSER_TIMEOUT_SECONDS,
    DEFAULT_PREPARE_CASE_TIMEOUT_SECONDS,
    ELENCHOS_PREPARE_TIMEOUT_SECONDS,
    get_prepare_case_timeout_seconds,
)
from elenchos.parser.amcache import parse_amcache
from elenchos.parser.mft import parse_mft
from elenchos.parser.registry_runkeys import parse_registry_runkeys
from elenchos.parser.registry_user_activity import parse_registry_user_activity


def test_prepare_case_timeout_default_is_unbounded():
    assert DEFAULT_PREPARE_CASE_TIMEOUT_SECONDS is None
    assert get_prepare_case_timeout_seconds(environ={}) is None


def test_prepare_case_timeout_empty_env_uses_default():
    assert get_prepare_case_timeout_seconds(
        environ={ELENCHOS_PREPARE_TIMEOUT_SECONDS: "  "},
    ) is None


@pytest.mark.parametrize("value", ["none", "off", "disabled", "0"])
def test_prepare_case_timeout_env_can_disable_timeout(value: str):
    assert get_prepare_case_timeout_seconds(
        environ={ELENCHOS_PREPARE_TIMEOUT_SECONDS: value},
    ) is None


def test_prepare_case_timeout_env_positive_integer():
    assert get_prepare_case_timeout_seconds(
        environ={ELENCHOS_PREPARE_TIMEOUT_SECONDS: "123"},
    ) == 123


def test_prepare_case_timeout_explicit_wins_over_env():
    assert (
        get_prepare_case_timeout_seconds(
            explicit=45,
            environ={ELENCHOS_PREPARE_TIMEOUT_SECONDS: "123"},
        )
        == 45
    )


def test_prepare_case_timeout_explicit_zero_disables_timeout():
    assert get_prepare_case_timeout_seconds(explicit=0) is None


@pytest.mark.parametrize("value", ["soon", "-1"])
def test_prepare_case_timeout_invalid_env_fails_clearly(value: str):
    with pytest.raises(ValueError, match=ELENCHOS_PREPARE_TIMEOUT_SECONDS):
        get_prepare_case_timeout_seconds(
            environ={ELENCHOS_PREPARE_TIMEOUT_SECONDS: value},
        )


def test_parser_timeout_default_remains_bounded():
    assert isinstance(DEFAULT_PARSER_TIMEOUT_SECONDS, int)
    assert DEFAULT_PARSER_TIMEOUT_SECONDS > 0


@pytest.mark.parametrize(
    "func",
    [
        parse_mft,
        parse_amcache,
        parse_registry_runkeys,
        parse_registry_user_activity,
    ],
)
def test_parser_wrappers_use_bounded_default_timeout(func):
    assert func.__kwdefaults__["timeout_seconds"] == DEFAULT_PARSER_TIMEOUT_SECONDS
