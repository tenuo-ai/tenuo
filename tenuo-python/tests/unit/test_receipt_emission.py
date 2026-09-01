"""The runtime's receipt emission path, end to end and without a control plane.

Receipts are produced by the enforcement point and handed to a sink the host
chooses. Nothing here needs a live control plane: the runtime has to be able to
produce durable evidence on its own, or the evidence story depends on a service
being reachable at exactly the moment it usually is not.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

from tenuo_core import Authorizer, ControlPlaneClient, Pattern, SigningKey, Warrant  # noqa: E402

from tenuo.control_plane import ControlPlaneClient as PythonControlPlaneClient  # noqa: E402
from tenuo.receipts import FileReceiptSink, InMemoryReceiptSink, deliver  # noqa: E402


def _decision():
    """A verified chain result plus the authorizer that produced it."""
    root = SigningKey.generate()
    worker = SigningKey.generate()
    authorizer = Authorizer(trusted_roots=[root.public_key])

    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(worker.public_key)
        .ttl(3600)
        .mint(root)
    )
    args = {"path": "/data/q3.pdf"}
    pop = warrant.sign(worker, "read_file", args, int(time.time()))
    result = authorizer.check_chain([warrant], "read_file", args, pop, [])
    return authorizer, result


def _client():
    # Unreachable on purpose: emission must not depend on the control plane.
    return ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="test")


def test_an_unbound_client_signs_nothing():
    _, result = _decision()
    client = _client()

    # An enforcement point that cannot say what it trusted has nothing worth
    # signing, so it declines rather than emitting an unqualified claim.
    assert client.issue_receipt(result, "read_file", True, int(time.time()), "req-1") is None


def test_a_bound_client_signs_a_verifiable_receipt():
    authorizer, result = _decision()
    client = _client()
    client.bind_authorizer(authorizer)

    wire = client.issue_receipt(result, "read_file", True, 1_700_000_000, "req-1")
    payload = tenuo_core.verify_receipt(wire)

    assert payload.outcome == "allow"
    assert payload.action == "read_file"
    assert payload.request_id == "req-1"
    assert payload.signer_key == client.receipt_signer_key
    # An allow without a PoP is evidence of nothing but the signer's word.
    assert payload.pop_signature is not None


def test_python_emission_auto_binds_receipt_trust_context():
    authorizer, result = _decision()
    sink = InMemoryReceiptSink()
    client = PythonControlPlaneClient(
        url="http://127.0.0.1:1",
        api_key="k",
        authorizer_name="test",
        receipt_sink=sink,
    )
    decision = SimpleNamespace(
        allowed=True,
        tool="read_file",
        arguments={"path": "/data/q3.pdf"},
        warrant_id="wrt-test",
        chain_result=result,
        authorizer=authorizer,
    )

    client.emit_for_enforcement(decision, chain_result=result, request_id="req-auto")

    assert len(sink.receipts) == 1
    payload = tenuo_core.verify_receipt(sink.receipts[0])
    assert payload.request_id == "req-auto"
    assert payload.trusted_roots_hash == authorizer.trusted_roots_hash.hex()


def test_the_receipt_commits_to_the_authorizers_own_trust_context():
    authorizer, result = _decision()
    client = _client()
    client.bind_authorizer(authorizer)

    payload = tenuo_core.verify_receipt(
        client.issue_receipt(result, "read_file", True, 1_700_000_000, "req-1")
    )

    # Read from the authorizer, not configured separately — that is what stops
    # a receipt claiming a trust context this enforcement point never had.
    assert payload.trusted_roots_hash == authorizer.trusted_roots_hash.hex()
    # No revocation list was installed, and the receipt says so rather than
    # implying revocation was consulted.
    assert payload.srl_hash is None


def test_receipts_chain_so_a_withheld_one_is_detectable():
    authorizer, result = _decision()
    client = _client()
    client.bind_authorizer(authorizer)

    first = client.issue_receipt(result, "read_file", True, 1_700_000_000, "req-1")
    second = client.issue_receipt(result, "read_file", True, 1_700_000_001, "req-2")
    third = client.issue_receipt(result, "read_file", True, 1_700_000_002, "req-3")

    import hashlib

    p_first = tenuo_core.verify_receipt(first)
    p_second = tenuo_core.verify_receipt(second)
    p_third = tenuo_core.verify_receipt(third)

    assert p_first.prev_receipt_hash is None
    assert p_second.prev_receipt_hash == hashlib.sha256(bytes.fromhex(first)).hexdigest()
    assert p_third.prev_receipt_hash == hashlib.sha256(bytes.fromhex(second)).hexdigest()

    # Withhold the second: the third now points at something absent.
    kept = {hashlib.sha256(bytes.fromhex(r)).hexdigest() for r in (first, third)}
    assert p_third.prev_receipt_hash not in kept


def test_a_denial_is_receipted_too():
    authorizer, result = _decision()
    client = _client()
    client.bind_authorizer(authorizer)

    payload = tenuo_core.verify_receipt(
        client.issue_receipt(
            result, "read_file", False, 1_700_000_000, "req-1", "tool-not-authorized"
        )
    )

    assert payload.outcome == "deny"
    assert payload.decision_code == "tool-not-authorized"


def test_in_memory_sink_bounds_growth_and_counts_what_it_dropped():
    sink = InMemoryReceiptSink(max_receipts=2)

    for i in range(5):
        sink.handle(f"receipt-{i}")

    # A full buffer must be visible, not silent.
    assert len(sink) == 2
    assert sink.dropped == 3
    assert sink.receipts == ["receipt-3", "receipt-4"]


def test_file_sink_appends_one_line_per_receipt(tmp_path):
    sink = FileReceiptSink(tmp_path / "nested" / "receipts.jsonl", fsync=False)

    sink.handle("aa")
    sink.handle("bb")

    lines = sink.path.read_text().strip().splitlines()
    assert [__import__("json").loads(line)["receipt"] for line in lines] == ["aa", "bb"]


def test_a_failing_sink_never_reaches_the_caller():
    class Broken:
        def handle(self, receipt_hex):
            raise RuntimeError("disk full")

    seen = []

    # Authorization is already decided; a sink must not turn a permitted call
    # into a failed one. But the gap is reported rather than swallowed.
    deliver(Broken(), "deadbeef", seen.append)

    assert len(seen) == 1
    assert isinstance(seen[0], RuntimeError)


def test_delivery_is_a_no_op_without_a_sink_or_a_receipt():
    deliver(None, "deadbeef", None)
    deliver(InMemoryReceiptSink(), None, None)


def _expired_denial():
    """A real denial: check_chain raises ExpiredError, so there is no chain_result.

    An earlier version of this fixture passed as_of as a keyword the binding
    did not accept, so pytest.raises was satisfied by a TypeError and the
    "expired" denial was neither. The match= below pins that the failure is
    the one this fixture claims to produce.
    """
    import pytest as _pytest

    root, worker = SigningKey.generate(), SigningKey.generate()
    authorizer = Authorizer(trusted_roots=[root.public_key])
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(worker.public_key)
        .ttl(3600)
        .mint(root)
    )
    args = {"path": "/data/q3.pdf"}
    pop = warrant.sign(worker, "read_file", args, int(time.time()))

    # Verify well past expiry so the chain genuinely fails, on expiry.
    with _pytest.raises(Exception, match="[Ee]xpire"):
        authorizer.check_chain(
            [warrant], "read_file", args, signature=pop, as_of=int(time.time()) + 86_400
        )
    return authorizer, [warrant], args


def test_a_real_denial_has_no_chain_result_to_build_from():
    """The reason denials need their own path: check_chain raises."""
    authorizer, chain, args = _expired_denial()

    # There is no ChainVerificationResult here at all — that is the whole
    # problem issue_denial_receipt exists to solve.
    assert chain and authorizer is not None


def test_an_expired_warrant_is_receipted_from_the_presented_chain():
    authorizer, chain, args = _expired_denial()
    client = _client()
    client.bind_authorizer(authorizer)

    wire = client.issue_denial_receipt(
        chain, "read_file", args, 1_700_000_000, "req-deny", "warrant-expired"
    )
    payload = tenuo_core.verify_receipt(wire)

    assert payload.outcome == "deny"
    assert payload.decision_code == "warrant-expired"
    assert payload.action == "read_file"
    # Possession was not asserted, because expiry is reached before the PoP is
    # trusted — claiming it would be a false claim.
    assert payload.pop_signature is None
    # The refusal still commits to what was asked for.
    assert payload.request_hash is not None
    assert payload.trusted_roots_hash is not None


def test_denials_and_allows_share_one_chain():
    """The point of receipting denials: no silent gaps between allows."""
    import hashlib

    authorizer, result = _decision()
    client = _client()
    client.bind_authorizer(authorizer)

    allow = client.issue_receipt(result, "read_file", True, 1_700_000_000, "req-1")
    _, chain, args = _expired_denial()
    deny = client.issue_denial_receipt(
        chain, "read_file", args, 1_700_000_001, "req-2", "warrant-expired"
    )

    p_deny = tenuo_core.verify_receipt(deny)
    assert p_deny.prev_receipt_hash == hashlib.sha256(bytes.fromhex(allow)).hexdigest()


def test_a_structural_refusal_is_not_receipted():
    """No warrant presented means no chain for a receipt to commit to.

    Signing these would also let an unauthenticated caller compel signature and
    sink work. They stay in the audit stream instead.
    """
    authorizer, _ = _decision()
    client = _client()
    client.bind_authorizer(authorizer)

    assert (
        client.issue_denial_receipt(
            [], "read_file", {}, 1_700_000_000, "req", "no-warrant"
        )
        is None
    )
