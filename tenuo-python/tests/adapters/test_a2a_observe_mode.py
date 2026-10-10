"""A2A records denials that observe mode lets through as observed denials.

In observe mode the shared ``verify_inbound_call`` returns ``allowed=True,
observed=True`` for a would-be denial. The server lets the call proceed but
must audit it as the denial it was, not as ``warrant_validated``/``allowed``.
"""

import asyncio
import io
import json
import time

import pytest

pytest.importorskip("starlette")

from tenuo_core import Pattern, SigningKey, Warrant  # noqa: E402

from tenuo.a2a import A2AServer  # noqa: E402
from tenuo.a2a.errors import ConstraintViolationError  # noqa: E402
from tenuo.config import configure, reset_config  # noqa: E402


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    yield
    reset_config()


def _setup():
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
        name="Observe Agent",
        url="http://test",
        public_key="server_key",
        trusted_issuers=[root_key.public_key.to_bytes().hex()],
        require_warrant=True,
        require_audience=False,
        require_pop=True,
        check_replay=False,
        audit_log=log,
    )

    @server.skill("search")
    async def search(query: str) -> str:
        return f"found {query}"

    return root_key, holder_key, warrant, server, log


def _validate(server, warrant, holder_key, args):
    pop = bytes(warrant.sign(holder_key, "search", args, int(time.time())))
    return asyncio.run(server.validate_warrant(warrant.to_base64(), "search", args, pop_signature=pop))


def _events(log):
    return [json.loads(line) for line in log.getvalue().splitlines() if line.strip()]


def test_enforce_mode_rejects_constraint_violation():
    _, holder_key, warrant, server, _ = _setup()
    with pytest.raises(ConstraintViolationError):
        _validate(server, warrant, holder_key, {"query": "nope"})


def test_observe_mode_audits_observed_denial_not_validated():
    root_key, holder_key, warrant, server, log = _setup()
    configure(trusted_roots=[root_key.public_key], mode="observe")

    assert _validate(server, warrant, holder_key, {"query": "nope"}) is not None

    event = _events(log)[-1]
    assert event["event"] == "warrant_rejected"
    assert event["outcome"] == "denied"
    assert event["observed"] is True
    assert event["reason"]


def test_observe_mode_allowed_call_is_plain_validated():
    root_key, holder_key, warrant, server, log = _setup()
    configure(trusted_roots=[root_key.public_key], mode="observe")

    _validate(server, warrant, holder_key, {"query": "ok-1"})

    event = _events(log)[-1]
    assert (event["event"], event["outcome"], event["observed"]) == ("warrant_validated", "allowed", False)
