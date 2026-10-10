"""A2A writes enforce-mode rejections to audit_log as warrant_rejected."""

import asyncio
import io
import json
import time

import pytest

pytest.importorskip("starlette")

from tenuo_core import Pattern, SigningKey, Warrant  # noqa: E402

from tenuo.a2a import A2AServer  # noqa: E402
from tenuo.a2a.errors import ConstraintViolationError, UntrustedIssuerError  # noqa: E402
from tenuo.config import reset_config  # noqa: E402

SECRET = "hunter2-secret-value"


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    yield
    reset_config()


def _setup(trusted):
    root_key, holder_key = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("search", query=Pattern("ok*"))
        .holder(holder_key.public_key)
        .ttl(3600)
        .mint(root_key)
    )
    log = io.StringIO()
    server = A2AServer(
        name="Audit Agent",
        url="http://test",
        public_key="server_key",
        trusted_issuers=[(root_key if trusted else SigningKey.generate()).public_key.to_bytes().hex()],
        require_warrant=True,
        require_audience=False,
        require_pop=True,
        check_replay=False,
        audit_log=log,
    )

    @server.skill("search")
    async def search(query: str) -> str:
        return query

    return holder_key, warrant, server, log


def _validate(server, warrant, holder_key, args):
    pop = bytes(warrant.sign(holder_key, "search", args, int(time.time())))
    return asyncio.run(server.validate_warrant(warrant.to_base64(), "search", args, pop_signature=pop))


def _events(log):
    return [json.loads(line) for line in log.getvalue().splitlines() if line.strip()]


def test_constraint_violation_is_audited_as_rejected():
    holder_key, warrant, server, log = _setup(trusted=True)
    with pytest.raises(ConstraintViolationError):
        _validate(server, warrant, holder_key, {"query": SECRET})
    event = _events(log)[-1]
    assert (event["event"], event["outcome"], event["observed"]) == ("warrant_rejected", "denied", False)
    assert event["skill"] == "search"
    assert event["reason"].startswith("ConstraintViolationError")
    assert SECRET not in log.getvalue()


def test_untrusted_issuer_is_audited_as_rejected():
    holder_key, warrant, server, log = _setup(trusted=False)
    with pytest.raises(UntrustedIssuerError):
        _validate(server, warrant, holder_key, {"query": "ok-1"})
    assert _events(log)[-1]["event"] == "warrant_rejected"


def test_allowed_call_is_audited_once_as_validated():
    holder_key, warrant, server, log = _setup(trusted=True)
    _validate(server, warrant, holder_key, {"query": "ok-1"})
    assert [e["event"] for e in _events(log)] == ["warrant_validated"]
