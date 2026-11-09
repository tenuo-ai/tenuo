"""Tier 1 constraints require the constrained arguments to be passed."""

import pytest

pytest.importorskip("openai")

from tenuo import Subpath, Wildcard  # noqa: E402
from tenuo.openai import OpenAIConstraintViolation, verify_tool_call  # noqa: E402


def check(arguments, constraints):
    return verify_tool_call("read_file", arguments, ["read_file"], None, {"read_file": constraints})


def test_omitting_a_constrained_argument_is_denied():
    constraints = {"path": Subpath("/data")}
    check({"path": "/data/x"}, constraints)
    with pytest.raises(OpenAIConstraintViolation):
        check({}, constraints)


def test_wildcard_arguments_may_be_omitted():
    constraints = {"path": Subpath("/data"), "encoding": Wildcard()}
    check({"path": "/data/x"}, constraints)
    with pytest.raises(OpenAIConstraintViolation):
        check({"encoding": "utf-8"}, constraints)


def test_allow_unknown_marker_is_not_an_argument():
    check({"path": "/data/x", "extra": 1}, {"path": Subpath("/data"), "_allow_unknown": True})
