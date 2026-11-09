"""Tier 1 constraints require the constrained arguments to be passed."""

import pytest

pytest.importorskip("openai")

from tenuo import Subpath, Wildcard  # noqa: E402
from tenuo.openai import OpenAIConstraintViolation, verify_tool_call, verify_tool_call_async  # noqa: E402


@pytest.fixture(params=[verify_tool_call, verify_tool_call_async])
def check(request):
    async def verify(arguments, constraints):
        import inspect

        result = request.param("read_file", arguments, ["read_file"], None, {"read_file": constraints})
        return await result if inspect.isawaitable(result) else result
    return verify


@pytest.mark.asyncio
async def test_omitting_a_constrained_argument_is_denied(check):
    constraints = {"path": Subpath("/data")}
    await check({"path": "/data/x"}, constraints)
    with pytest.raises(OpenAIConstraintViolation):
        await check({}, constraints)


@pytest.mark.asyncio
async def test_wildcard_arguments_may_be_omitted(check):
    constraints = {"path": Subpath("/data"), "encoding": Wildcard()}
    await check({"path": "/data/x"}, constraints)
    with pytest.raises(OpenAIConstraintViolation):
        await check({"encoding": "utf-8"}, constraints)


@pytest.mark.asyncio
async def test_allow_unknown_marker_is_not_an_argument(check):
    await check({"path": "/data/x", "extra": 1}, {"path": Subpath("/data"), "_allow_unknown": True})
