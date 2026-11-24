"""Authorizer host policy ceilings.

A host policy is the enforcement point's own per-argument limit for a tool. A
call must satisfy both the warrant chain and the policy. Receipts commit to the
policy as key 11 (policy_definition_hash), computed the same way as the
TypeScript SDK's ``verify(..., { allow })`` so the digests agree across SDKs.
"""

from __future__ import annotations

import time

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

from tenuo import (  # noqa: E402
    AnyOf,
    Authorizer,
    Cidr,
    Contains,
    Exact,
    HolderIdentity,
    Not,
    NotOneOf,
    OneOf,
    Pattern,
    Range,
    Regex,
    Runtime,
    Shlex,
    SigningKey,
    Subpath,
    Subset,
    UrlPattern,
    UrlSafe,
    Warrant,
    Wildcard,
    verify_receipt,
)
from tenuo._enforcement import verify_inbound_call  # noqa: E402
from tenuo.exceptions import ConstraintViolation, ValidationError  # noqa: E402
from tenuo.receipts import collect_enforcement_receipt  # noqa: E402
from tenuo_core import ReceiptIssuer  # noqa: E402

TOOL = "route_ticket"
GOOD = {"ticket_id": "1042", "queue": "general", "auto_close": False}


def _setup():
    root = SigningKey.generate()
    holder = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability(TOOL, ticket_id=Wildcard(), queue=OneOf(["general", "billing"]), auto_close=Exact(False))
        .holder(holder.public_key)
        .ttl(600)
        .mint(root)
    )
    return root, holder, warrant


def _sign(warrant, holder, args):
    return warrant.sign(holder, TOOL, args, int(time.time()))


def _ceiling():
    return {"ticket_id": Wildcard(), "queue": OneOf(["general"]), "auto_close": Exact(False)}


def test_call_within_both_warrant_and_ceiling_is_allowed():
    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy(TOOL, _ceiling())
    auth.check_chain([warrant], TOOL, GOOD, _sign(warrant, holder, GOOD))
    auth.authorize(warrant, TOOL, GOOD, _sign(warrant, holder, GOOD))
    auth.authorize_one(warrant, TOOL, GOOD, _sign(warrant, holder, GOOD))


def test_ceiling_denies_what_the_warrant_allows_on_every_method():
    root, holder, warrant = _setup()
    args = {**GOOD, "queue": "billing"}  # warrant allows billing, ceiling does not
    sig = _sign(warrant, holder, args)

    open_auth = Authorizer(trusted_roots=[root.public_key])
    open_auth.check_chain([warrant], TOOL, args, sig)

    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy(TOOL, _ceiling())
    calls = [
        lambda: auth.check_chain([warrant], TOOL, args, sig),
        lambda: auth.check_chain([warrant], TOOL, args, sig, as_of=int(time.time())),
        lambda: auth.authorize(warrant, TOOL, args, sig),
        lambda: auth.check(warrant, TOOL, args, sig),
        lambda: auth.authorize_one(warrant, TOOL, args, sig),
        lambda: auth.authorize_one_with_pop_args(warrant, TOOL, args, args, sig),
        lambda: auth.check_chain_with_pop_args([warrant], TOOL, args, args, sig),
    ]
    for call in calls:
        with pytest.raises(ConstraintViolation):
            call()


def test_ceiling_is_closed_world():
    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy(TOOL, {"queue": OneOf(["general"])})
    # The warrant allows these arguments, but the ceiling does not name them.
    with pytest.raises(ConstraintViolation):
        auth.check_chain([warrant], TOOL, GOOD, _sign(warrant, holder, GOOD))


def test_tools_without_a_ceiling_are_unchanged():
    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy("other_tool", {"x": Exact("y")})
    assert auth.host_policy_hash(TOOL) is None
    auth.check_chain([warrant], TOOL, GOOD, _sign(warrant, holder, GOOD))


def test_empty_ceiling_is_open_but_committed():
    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy(TOOL, {})
    auth.check_chain([warrant], TOOL, GOOD, _sign(warrant, holder, GOOD))
    assert auth.host_policy_hash(TOOL).hex() == PARITY["empty"]


def test_ceiling_cannot_be_replaced_or_misconfigured():
    auth = Authorizer(trusted_roots=[SigningKey.generate().public_key])
    auth.set_host_policy(TOOL, _ceiling())
    first = auth.host_policy_hash(TOOL)
    with pytest.raises(ValidationError):
        auth.set_host_policy(TOOL, {})
    assert auth.host_policy_hash(TOOL) == first
    assert auth.host_policy_tools() == [TOOL]
    with pytest.raises(ValidationError):
        auth.set_host_policy("t", {"x": "not a constraint"})
    with pytest.raises(ValidationError):
        auth.set_host_policy("t", {"_allow_unknown": True})
    with pytest.raises(ValidationError):
        auth.set_host_policy("", {})


@pytest.mark.parametrize(
    "constraint",
    [
        UrlSafe(allow_ports=[443]),
        OneOf([1, 2]),
        NotOneOf([1]),
    ],
)
def test_constraints_the_commitment_cannot_describe_are_rejected(constraint):
    auth = Authorizer(trusted_roots=[SigningKey.generate().public_key])
    with pytest.raises(ValidationError):
        auth.set_host_policy("t", {"x": constraint})
    assert auth.host_policy_tools() == []


def test_receipts_carry_the_policy_digest_for_allow_and_deny():
    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy(TOOL, _ceiling())
    issuer = ReceiptIssuer(SigningKey.generate())
    issuer.bind_authorizer(auth)

    result = auth.check_chain([warrant], TOOL, GOOD, _sign(warrant, holder, GOOD))
    allow = verify_receipt(issuer.issue_receipt(result, TOOL, True, int(time.time()), "req-allow"))
    assert allow.outcome == "allow"
    assert allow.policy_definition_hash == auth.host_policy_hash(TOOL).hex()

    bad = {**GOOD, "queue": "billing"}
    with pytest.raises(ConstraintViolation) as caught:
        auth.check_chain([warrant], TOOL, bad, _sign(warrant, holder, bad))
    decision = caught.value._chain_result
    deny_wire = issuer.issue_receipt(decision, TOOL, False, int(time.time()), "req-deny", "constraint-violation")
    with pytest.raises(ValueError, match="denial cannot produce an allow"):
        issuer.issue_receipt(decision, TOOL, True, int(time.time()), "forged-allow")
    deny = verify_receipt(deny_wire)
    assert deny.outcome == "deny"
    assert deny.policy_definition_hash == auth.host_policy_hash(TOOL).hex()

    other = verify_receipt(
        issuer.issue_denial_receipt([warrant], "close_ticket", {}, int(time.time()), "req-other", "tool-not-authorized")
    )
    assert other.policy_definition_hash is None


def test_runtime_receipts_through_verify_inbound_call():
    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy(TOOL, _ceiling())
    runtime = Runtime(HolderIdentity(SigningKey.generate()), [root.public_key], receipts="collect")

    for args in (GOOD, {**GOOD, "queue": "billing"}):
        result = verify_inbound_call(
            tool_name=TOOL,
            tool_args=args,
            warrant=warrant,
            pop_signature=_sign(warrant, holder, args),
            authorizer=auth,
            apply_observe=False,
        )
        collect_enforcement_receipt(result, getattr(result, "chain_result", None), runtime=runtime)

    allow, deny = (verify_receipt(r) for r in runtime.peek_receipts())
    assert (allow.outcome, deny.outcome) == ("allow", "deny")
    assert deny.decision_code == "constraint-violation"
    for receipt in (allow, deny):
        assert receipt.policy_definition_hash == auth.host_policy_hash(TOOL).hex()


# Digests @tenuo/core writes as policyDefinitionHash for the same ceilings,
# passed as `verify(presented, tool, args, { allow })`. Produced from
# tenuo-ts/packages/core/src at this commit with:
#   routing:   { ticket_id: exact("1042"), queue: oneOf(["benefits-review", "general-inquiries"]), auto_close: exact(false) }
#   numeric:   { amount: range({ min: 0, max: 1000 }), rate: range({ max: 2.5 }), count: exact(3) }
#   paths:     { path: under("/data/reports"), name: pattern("*.pdf"), id: regex("^[a-z]+$") }
#   network:   { url: urlSafe({ allowDomains: ["api.example.com"] }), host: cidr("10.0.0.0/8"),
#                endpoint: urlPattern("https://api.example.com/*") }
#   composite: { region: anyOf([exact("ca-central-1"), pattern("ca-west-*")]), env: not(exact("prod")),
#                cmd: shlex(["ls", "cat"]), tags: subset(["a", "b"]), labels: contains(["reviewed"]),
#                blocked: notOneOf(["root"]), note: wildcard() }
#   empty:     {}
PARITY = {
    "routing": "193aa9b6044c60e1405b754e4b010fc9db0394f73be2b4bc48316737482f7f45",
    "numeric": "8e7f8f305187251bef3dde13102ccb02759825caf446de2b6a2b82f90ae32256",
    "paths": "3a9650ba739a196f3c89002df971134793368dc4406f9264cb85d7b27d6b1386",
    "network": "140b575406ae9d437fa5790210b1dd9de5a1356a45eb1c0b588e191e9b885017",
    "composite": "10acee0704c2111de24827c70d2d3f011aed3f7fbfe8b758efe99c814e1ab4f0",
    "empty": "c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0",
}

PYTHON_CEILINGS = {
    "routing": lambda: {
        "ticket_id": Exact("1042"),
        "queue": OneOf(["benefits-review", "general-inquiries"]),
        "auto_close": Exact(False),
    },
    "numeric": lambda: {"amount": Range(min=0, max=1000), "rate": Range(max=2.5), "count": Exact(3)},
    "paths": lambda: {"path": Subpath("/data/reports"), "name": Pattern("*.pdf"), "id": Regex("^[a-z]+$")},
    "network": lambda: {
        "url": UrlSafe(allow_domains=["api.example.com"]),
        "host": Cidr("10.0.0.0/8"),
        "endpoint": UrlPattern("https://api.example.com/*"),
    },
    "composite": lambda: {
        "region": AnyOf([Exact("ca-central-1"), Pattern("ca-west-*")]),
        "env": Not(Exact("prod")),
        "cmd": Shlex(["ls", "cat"]),
        "tags": Subset(["a", "b"]),
        "labels": Contains(["reviewed"]),
        "blocked": NotOneOf(["root"]),
        "note": Wildcard(),
    },
    "empty": lambda: {},
}


@pytest.mark.parametrize("name", sorted(PARITY))
def test_digest_matches_typescript(name):
    auth = Authorizer(trusted_roots=[SigningKey.generate().public_key])
    auth.set_host_policy(name, PYTHON_CEILINGS[name]())
    assert auth.host_policy_hash(name).hex() == PARITY[name]


@pytest.mark.parametrize("native_client", [False, True])
@pytest.mark.parametrize("supplied_tool", [TOOL, "other", "unconfigured"])
def test_decision_digest_survives_rebinding_and_tool_override(native_client, supplied_tool):
    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy(TOOL, _ceiling())
    decision = auth.authorize_one(warrant, TOOL, GOOD, _sign(warrant, holder, GOOD))
    other = Authorizer(trusted_roots=[root.public_key])
    other.set_host_policy(TOOL, {})
    other.set_host_policy("other", {"x": Exact("different")})
    issuer = (
        tenuo_core.ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="test")
        if native_client
        else ReceiptIssuer(SigningKey.generate())
    )
    try:
        issuer.bind_authorizer(other)
        receipt = verify_receipt(issuer.issue_receipt(decision, supplied_tool, True, int(time.time()), "rebound"))
        assert receipt.action == TOOL
        assert receipt.policy_definition_hash == auth.host_policy_hash(TOOL).hex()
    finally:
        if native_client:
            issuer.shutdown(0.1)


def test_late_policy_installation_does_not_rewrite_earlier_decision():
    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    decision = auth.authorize_one(warrant, TOOL, GOOD, _sign(warrant, holder, GOOD))
    auth.set_host_policy(TOOL, _ceiling())
    issuer = ReceiptIssuer(SigningKey.generate())
    issuer.bind_authorizer(auth)
    receipt = verify_receipt(issuer.issue_receipt(decision, TOOL, True, int(time.time()), "earlier"))
    assert receipt.policy_definition_hash is None
    # A raw denial supplies no evidence that the host ceiling was evaluated.
    raw = verify_receipt(issuer.issue_denial_receipt([warrant], TOOL, GOOD, int(time.time()), "raw", "denied"))
    assert raw.policy_definition_hash is None


@pytest.mark.parametrize("allowed", [True, False])
def test_deferred_receipt_keeps_decision_policy_after_client_rebind(allowed):
    import threading
    from tenuo.control_plane import ControlPlaneClient
    from tenuo.receipts import InMemoryReceiptSink

    root, holder, warrant = _setup()
    auth = Authorizer(trusted_roots=[root.public_key])
    auth.set_host_policy(TOOL, _ceiling())
    args = GOOD if allowed else {**GOOD, "queue": "billing"}
    result = verify_inbound_call(
        tool_name=TOOL,
        tool_args=args,
        warrant=warrant,
        pop_signature=_sign(warrant, holder, args),
        authorizer=auth,
        apply_observe=False,
    )
    assert result.allowed is allowed
    sink = InMemoryReceiptSink()
    client = ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="test", receipt_sink=sink)
    started, release = threading.Event(), threading.Event()
    inner = client._inner

    class PausedSigner:
        def issue_receipt(self, *args):
            started.set()
            assert release.wait(5), "test did not release deferred signer"
            return inner.issue_receipt(*args)

    client._receipt_emitter._inner = PausedSigner()
    try:
        client.emit_for_enforcement(result, result.chain_result)
        assert started.wait(5), "decision was not queued"
        other = Authorizer(trusted_roots=[root.public_key])
        other.set_host_policy(TOOL, {})
        client.bind_authorizer(other)
        release.set()
        assert client.flush_receipts()
        assert len(sink.receipts) == 1
        receipt = verify_receipt(sink.receipts[0])
        assert receipt.outcome == ("allow" if allowed else "deny")
        assert receipt.policy_definition_hash == auth.host_policy_hash(TOOL).hex()
    finally:
        release.set()
        client.shutdown(0.1)


@pytest.mark.parametrize("root_path", ["/data/reports", "/data/reports/", "/data/./reports/"])
def test_normalized_path_and_explicit_defaults_match_typescript(root_path):
    auth = Authorizer(trusted_roots=[SigningKey.generate().public_key])
    auth.set_host_policy(
        "paths",
        {
            "path": Subpath(root_path, case_sensitive=True, allow_equal=True),
            "name": Pattern("*.pdf"),
            "id": Regex("^[a-z]+$"),
        },
    )
    assert auth.host_policy_hash("paths").hex() == PARITY["paths"]
    auth.set_host_policy(
        "network",
        {
            **PYTHON_CEILINGS["network"](),
            "url": UrlSafe(allow_schemes=["http", "https"], allow_domains=["api.example.com"]),
        },
    )
    assert auth.host_policy_hash("network").hex() == PARITY["network"]
