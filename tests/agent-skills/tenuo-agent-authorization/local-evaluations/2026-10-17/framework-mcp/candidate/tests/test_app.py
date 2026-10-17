import asyncio
import json
import time

import pytest
from tenuo import Exact, Range, SigningKey, Warrant
from tenuo_core import sign_meta

from client import call_refund, result_is_error
from development import issue_task, presentation


@pytest.fixture
def authority():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    return issuer, holder, issue_task(issuer, holder)


def effect_count(journal):
    return len(journal.read_text().splitlines()) if journal.exists() else 0


def text(result):
    return " ".join(getattr(c, "text", "") for c in result.content)


@pytest.mark.parametrize("amount", [1, 10_000, 20_000, 50_000])
async def test_allowed(tmp_path, authority, amount):
    issuer, holder, warrant = authority
    journal = tmp_path / "refunds"
    result = await call_refund(journal, "123", amount,
        presentation(warrant, holder, "123", amount),
        trusted_root=issuer.public_key.to_bytes().hex())
    assert not result_is_error(result), text(result)
    assert effect_count(journal) == 1
    assert journal.read_text() == f"123:{amount}\n"


@pytest.mark.parametrize("case,expected", [
    ("missing", "warrant"), ("malformed", "Malformed"),
    ("untrusted", "trust"), ("wrong_holder", "PoP"),
    ("missing_pop", "signature"), ("tampered_args", "PoP"),
    ("wrong_capability", "authorized"), ("expired", "expired"),
    ("wrong_order", "constraint"), ("above_limit", "constraint"),
    ("negative", "constraint"), ("zero", "constraint"),
    ("narrower_warrant", "constraint"), ("local_ceiling", "local policy"),
])
async def test_denied_before_effect(tmp_path, authority, case, expected):
    issuer, holder, warrant = authority
    order, amount = "123", 20_000
    signer = holder
    if case == "untrusted":
        warrant = issue_task(SigningKey.generate(), holder)
    if case == "wrong_holder":
        signer = SigningKey.generate()
    if case in ("wrong_capability", "expired", "narrower_warrant", "local_ceiling"):
        tool = "other_tool" if case == "wrong_capability" else "refund_order"
        maximum = 10_000 if case == "narrower_warrant" else 100_000 if case == "local_ceiling" else 50_000
        warrant = Warrant.issue(issuer, capabilities={tool: {
            "order_id": Exact("123"), "amount_cents": Range(min=1, max=maximum),
        }}, ttl_seconds=1 if case == "expired" else 300, holder=holder.public_key)
        if case == "expired":
            await asyncio.sleep(2)
    if case == "wrong_order": order = "456"
    if case in ("above_limit", "local_ceiling"): amount = 50_001
    if case == "negative": amount = -1
    if case == "zero": amount = 0
    meta = presentation(warrant, signer, order, amount)
    if case == "missing": meta = None
    if case == "malformed": meta = {"tenuo": {"warrant": "garbage", "signature": "garbage"}}
    if case == "missing_pop": meta["tenuo"].pop("signature")
    if case == "tampered_args": amount += 1
    journal = tmp_path / "refunds"
    result = await call_refund(journal, order, amount, meta,
        trusted_root=issuer.public_key.to_bytes().hex())
    assert result_is_error(result), text(result)
    assert expected.lower() in text(result).lower(), text(result)
    assert effect_count(journal) == 0


@pytest.mark.parametrize("order,amount", [
    ("123", True), ("123", 20_000.5), ("123", "20000"),
    (123, 20_000), ("123", 2**53 + 1), ("123", 2**64),
])
async def test_invalid_numeric_domain(tmp_path, authority, order, amount):
    issuer, holder, warrant = authority
    journal = tmp_path / "refunds"
    # Sign at the client, but send every fixture to the real server.
    result = await call_refund(journal, order, amount,
        presentation(warrant, holder, order, amount),
        trusted_root=issuer.public_key.to_bytes().hex())
    assert result_is_error(result), text(result)
    assert effect_count(journal) == 0


def test_original_module_route(tmp_path, monkeypatch, authority):
    import server
    from tenuo import Authorizer
    from tenuo.mcp import MCPVerifier
    journal = tmp_path / "refunds"
    monkeypatch.setenv("REFUND_JOURNAL", str(journal))
    issuer, _, _ = authority
    # Even with a real configured verifier, direct invocation at the original
    # defining module has no actual MCP request and cannot reach the effect.
    monkeypatch.setattr(server, "_verifier", MCPVerifier(
        authorizer=Authorizer(trusted_roots=[issuer.public_key]), require_warrant=True))
    with pytest.raises(RuntimeError, match="No active context"):
        server.refund_order("123", 20_000)
    assert effect_count(journal) == 0


async def test_narrow_child_and_missing_parent(tmp_path, authority):
    issuer, delegator, parent = authority
    recipient = SigningKey.generate()
    child = (parent.grant_builder()
        .capability("refund_order", order_id=Exact("123"), amount_cents=Range(min=1, max=20_000))
        .holder(recipient.public_key).ttl(120).terminal().grant(delegator))
    assert child.is_terminal
    args = {"order_id": "123", "amount_cents": 10_000}
    root = issuer.public_key.to_bytes().hex()
    journal = tmp_path / "refunds"
    meta = {"tenuo": sign_meta([parent, child], recipient, "refund_order", json.dumps(args), int(time.time()))}
    result = await call_refund(journal, **args, meta=meta, trusted_root=root)
    assert not result_is_error(result), text(result)
    assert effect_count(journal) == 1
    # Keep the same valid leaf and signer, but omit the root chain.
    meta = presentation(child, recipient, **args)
    result = await call_refund(journal, **args, meta=meta, trusted_root=root)
    assert result_is_error(result)
    assert "trust" in text(result).lower() or "chain" in text(result).lower(), text(result)
    assert effect_count(journal) == 1
    # The SDK rejects widening before it can make a signed child. This is
    # issuer-side evidence, separate from the receiver tests above.
    with pytest.raises(Exception, match="(?i)monotonic|widen|range|constraint"):
        (parent.grant_builder()
            .capability("refund_order", order_id=Exact("123"), amount_cents=Range(min=1, max=50_001))
            .holder(recipient.public_key).ttl(120).terminal().grant(delegator))
