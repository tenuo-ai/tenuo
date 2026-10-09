"""Trust-anchor behaviour of ``BoundWarrant.validate()`` (issue #675).

``validate()`` used to build its Authorizer from the warrant's own issuer, so
every warrant was trusted by construction and the ``trusted_roots`` supplied at
bind time were silently ignored. It now resolves roots the same way
``enforce_tool_call`` does and fails closed when none are available.
"""

import pytest

from tenuo import (
    ConfigurationError,
    Exact,
    HolderIdentity,
    Pattern,
    Runtime,
    SigningKey,
    Warrant,
    decode_warrant_stack_base64,
)
from tenuo_core import SignedRevocationList
from tenuo._enforcement import enforce_tool_call


@pytest.fixture
def delegation():
    """root -> supervisor -> worker, with only the root as a trusted issuer."""
    root_key = SigningKey.generate()
    supervisor_key = SigningKey.generate()
    worker_key = SigningKey.generate()

    task = (
        Warrant.mint_builder()
        .capability("lookup_order", order_id=Pattern("A-*"))
        .holder(supervisor_key.public_key)
        .ttl(600)
        .mint(root_key)
    )
    child = (
        task.grant_builder()
        .holder(worker_key.public_key)
        .capability("lookup_order", order_id=Exact("A-100"))
        .ttl(120)
        .grant(supervisor_key)
    )
    return {
        "root_key": root_key,
        "supervisor_key": supervisor_key,
        "worker_key": worker_key,
        "task": task,
        "child": child,
        "args": {"order_id": "A-100"},
    }


def test_validate_requires_a_trust_anchor(delegation):
    """No roots at the call site, at bind time, or in config: fail closed."""
    bound = delegation["child"].bind(delegation["worker_key"])
    with pytest.raises(ConfigurationError, match="self-signed"):
        bound.validate("lookup_order", delegation["args"])


def test_validate_honors_bind_time_roots(delegation):
    """Roots passed at bind time are the anchor, not the warrant's own issuer."""
    unrelated = SigningKey.generate().public_key
    bound = delegation["child"].bind(delegation["worker_key"], trusted_roots=[unrelated])

    result = bound.validate("lookup_order", delegation["args"])

    assert not result
    assert "not trusted" in result.reason


def test_validate_rejects_delegated_leaf_without_its_parents(delegation):
    """A delegated warrant is issued by its delegator, not by a trusted root."""
    bound = delegation["child"].bind(
        delegation["worker_key"], trusted_roots=[delegation["root_key"].public_key]
    )

    result = bound.validate("lookup_order", delegation["args"])

    assert not result
    assert "not trusted" in result.reason
    assert any("warrant_chain" in s for s in result.suggestions)


def test_validate_accepts_delegated_leaf_with_its_parents(delegation):
    """The same warrant validates once the path back to the root is presented."""
    bound = delegation["child"].bind(
        delegation["worker_key"], trusted_roots=[delegation["root_key"].public_key]
    )

    result = bound.validate(
        "lookup_order", delegation["args"], warrant_chain=[delegation["task"]]
    )

    assert result, result.reason


def test_validate_rejects_a_chain_that_does_not_link_to_the_leaf(delegation):
    """A sibling from the same trusted root is not this warrant's parent."""
    sibling = (
        Warrant.mint_builder()
        .capability("lookup_order", order_id=Pattern("A-*"))
        .holder(delegation["supervisor_key"].public_key)
        .ttl(600)
        .mint(delegation["root_key"])
    )
    bound = delegation["child"].bind(
        delegation["worker_key"], trusted_roots=[delegation["root_key"].public_key]
    )

    result = bound.validate(
        "lookup_order", delegation["args"], warrant_chain=[sibling]
    )

    assert not result
    assert "parent_hash mismatch" in result.reason


def test_validate_explicit_roots_override_bind_time_roots(delegation):
    """The call-site argument wins, matching enforce_tool_call's ladder."""
    unrelated = SigningKey.generate().public_key
    bound = delegation["child"].bind(delegation["worker_key"], trusted_roots=[unrelated])

    result = bound.validate(
        "lookup_order",
        delegation["args"],
        trusted_roots=[delegation["root_key"].public_key],
        warrant_chain=[delegation["task"]],
    )

    assert result, result.reason


def test_validate_falls_back_to_global_configuration(delegation, monkeypatch):
    """tenuo.configure(trusted_roots=[...]) satisfies the anchor requirement."""
    import tenuo

    tenuo.configure(trusted_roots=[delegation["root_key"].public_key])
    try:
        bound = delegation["child"].bind(delegation["worker_key"])
        result = bound.validate(
            "lookup_order", delegation["args"], warrant_chain=[delegation["task"]]
        )
        assert result, result.reason
    finally:
        tenuo.reset_config()


@pytest.mark.parametrize("with_chain", [False, True], ids=["leaf-only", "with-chain"])
def test_validate_agrees_with_enforce_tool_call(delegation, with_chain):
    """The two entry points must not disagree about the same warrant."""
    roots = [delegation["root_key"].public_key]
    chain = [delegation["task"]] if with_chain else None
    bound = delegation["child"].bind(delegation["worker_key"], trusted_roots=roots)

    validated = bool(bound.validate("lookup_order", delegation["args"], warrant_chain=chain))
    enforced = enforce_tool_call(
        "lookup_order",
        delegation["args"],
        delegation["child"].bind(delegation["worker_key"]),
        trusted_roots=roots,
        warrant_chain=chain,
    ).allowed

    assert validated == enforced


def test_headers_forwards_the_chain(delegation):
    """headers() pre-flights and transports the same complete chain."""
    bound = delegation["child"].bind(
        delegation["worker_key"], trusted_roots=[delegation["root_key"].public_key]
    )

    with pytest.raises(RuntimeError, match="Authorization failed"):
        bound.headers("lookup_order", delegation["args"])

    headers = bound.headers(
        "lookup_order", delegation["args"], warrant_chain=[delegation["task"]]
    )
    assert set(headers) == {"X-Tenuo-Warrant", "X-Tenuo-PoP"}
    stack = decode_warrant_stack_base64(headers["X-Tenuo-Warrant"])
    assert [w.id for w in stack] == [delegation["task"].id, delegation["child"].id]


def test_validate_applies_active_runtime_revocation(delegation):
    """validate() and enforcement must agree when Runtime revokes the leaf."""
    builder = SignedRevocationList.builder()
    builder.revoke(delegation["child"].id)
    builder.version(1)
    srl = builder.build(delegation["root_key"])
    runtime = Runtime(
        identity=HolderIdentity.from_signing_key(delegation["worker_key"]),
        trusted_roots=[delegation["root_key"].public_key],
        revocation_list=srl,
    )
    bound = delegation["child"].bind(
        delegation["worker_key"],
        trusted_roots=[delegation["root_key"].public_key],
    )

    with runtime.bind():
        validated = bound.validate(
            "lookup_order",
            delegation["args"],
            warrant_chain=[delegation["task"]],
        )
        enforced = enforce_tool_call(
            "lookup_order",
            delegation["args"],
            bound,
            warrant_chain=[delegation["task"]],
        )

    assert not validated
    assert not enforced.allowed
    assert "revoked" in validated.reason.lower()
    assert enforced.error_type == "revoked"


def test_root_warrant_still_validates_against_its_issuer(delegation):
    """A non-delegated warrant needs no chain when its issuer is trusted."""
    bound = delegation["task"].bind(
        delegation["supervisor_key"], trusted_roots=[delegation["root_key"].public_key]
    )

    assert bound.validate("lookup_order", delegation["args"])
