"""
A delegated warrant sent without its parent chain is denied as ``chain_missing``.

The core reports this as an untrusted root issuer, which reads like a trust
misconfiguration and invites the wrong fix (adding the intermediate key to
trusted_roots, which promotes it to a root). The enforcement layer re-labels
that one denial; it adds no new rejection.
"""

import time

import pytest

from tenuo import Pattern, SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call, enforce_tool_call_async, verify_inbound_call
from tenuo.exceptions import UntrustedRoot
from tenuo_core import Authorizer

ARGS = {"query": "papers/ai"}


@pytest.fixture
def keys():
    return SigningKey.generate(), SigningKey.generate(), SigningKey.generate()


@pytest.fixture
def chain(keys):
    root_key, mid_key, leaf_key = keys
    root = Warrant.issue(
        root_key,
        capabilities={"search": {"query": Pattern("*")}},
        ttl_seconds=3600,
        holder=mid_key.public_key,
    )
    child = root.attenuate(
        signing_key=mid_key,
        holder=leaf_key.public_key,
        capabilities={"search": {"query": Pattern("papers/*")}},
        ttl_seconds=600,
    )
    return root, child


def _assert_chain_missing(result):
    assert result.allowed is False
    assert result.error_type == "chain_missing"
    assert "presented without its parent chain" in result.denial_reason
    assert "Do not add intermediate keys to trusted_roots" in result.denial_reason
    # The original core reason is kept for debugging.
    assert "Root warrant issuer is not trusted" in result.denial_reason


def test_sign_path_leaf_alone_is_chain_missing(keys, chain):
    root_key, _, leaf_key = keys
    _, child = chain
    result = enforce_tool_call("search", ARGS, child.bind(leaf_key), trusted_roots=[root_key.public_key])
    _assert_chain_missing(result)
    with pytest.raises(UntrustedRoot, match="without its parent chain"):
        result.raise_if_denied()


async def test_async_sign_path_leaf_alone_is_chain_missing(keys, chain):
    root_key, _, leaf_key = keys
    _, child = chain
    result = await enforce_tool_call_async("search", ARGS, child.bind(leaf_key), trusted_roots=[root_key.public_key])
    _assert_chain_missing(result)


def test_verify_path_leaf_alone_is_chain_missing(keys, chain):
    root_key, _, leaf_key = keys
    _, child = chain
    result = verify_inbound_call(
        tool_name="search",
        tool_args=ARGS,
        warrant=child,
        pop_signature=bytes(child.sign(leaf_key, "search", ARGS, int(time.time()))),
        authorizer=Authorizer(trusted_roots=[root_key.public_key]),
    )
    _assert_chain_missing(result)


def test_leaf_with_chain_is_allowed(keys, chain):
    root_key, _, leaf_key = keys
    root, child = chain
    result = enforce_tool_call(
        "search", ARGS, child.bind(leaf_key), trusted_roots=[root_key.public_key], warrant_chain=[root]
    )
    assert result.allowed is True, result.denial_reason


def test_delegated_warrant_from_trusted_issuer_alone_still_allowed(keys):
    # The core accepts a lone delegated warrant whose own issuer is trusted.
    root_key, _, leaf_key = keys
    root = Warrant.issue(
        root_key,
        capabilities={"search": {"query": Pattern("*")}},
        ttl_seconds=3600,
        holder=root_key.public_key,
    )
    child = root.attenuate(
        signing_key=root_key,
        holder=leaf_key.public_key,
        capabilities={"search": {"query": Pattern("papers/*")}},
        ttl_seconds=600,
    )
    assert child.depth > 0
    result = enforce_tool_call("search", ARGS, child.bind(leaf_key), trusted_roots=[root_key.public_key])
    assert result.allowed is True, result.denial_reason


def test_untrusted_root_warrant_keeps_untrusted_issuer(keys):
    root_key, _, leaf_key = keys
    rogue = Warrant.issue(
        SigningKey.generate(),
        capabilities={"search": {"query": Pattern("*")}},
        ttl_seconds=3600,
        holder=leaf_key.public_key,
    )
    assert rogue.depth == 0
    result = enforce_tool_call("search", ARGS, rogue.bind(leaf_key), trusted_roots=[root_key.public_key])
    assert result.allowed is False
    assert result.error_type == "untrusted_issuer"
    assert result.denial_reason == "Root warrant issuer is not trusted"
