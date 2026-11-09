"""A presented PoP is admitted once when the inbound replay check is on."""

import time

import pytest

pytest.importorskip("tenuo_core")

from tenuo_core import Authorizer  # noqa: E402

from tenuo import SigningKey, Subpath, Warrant  # noqa: E402
from tenuo._enforcement import verify_inbound_call  # noqa: E402
from tenuo.nonce import NonceStore, disable_default_nonce_store, enable_default_nonce_store  # noqa: E402


@pytest.fixture(autouse=True)
def no_default_store():
    disable_default_nonce_store()
    yield
    disable_default_nonce_store()


@pytest.fixture
def call():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Subpath("/data"))
        .holder(holder.public_key)
        .ttl(300)
        .mint(issuer)
    )
    authorizer = Authorizer(trusted_roots=[issuer.public_key])

    def verify(path="/data/x", signature=None, **kwargs):
        args = {"path": path}
        if signature is None:
            signature = bytes(warrant.sign(holder, "read_file", args, int(time.time())))
        result = verify_inbound_call(
            tool_name="read_file",
            tool_args=args,
            warrant=warrant,
            pop_signature=signature,
            authorizer=authorizer,
            **kwargs,
        )
        return result, signature

    return verify


def test_replayed_pop_is_denied_with_an_explicit_store(call):
    store = NonceStore(ttl_seconds=120)
    first, signature = call(check_replay=True, nonce_store=store)
    assert first.allowed
    replay, _ = call(signature=signature, check_replay=True, nonce_store=store)
    assert not replay.allowed
    assert replay.error_type == "invalid_pop"


def test_replayed_pop_is_denied_with_the_process_wide_store(call):
    enable_default_nonce_store()
    first, signature = call(check_replay=True)
    assert first.allowed
    assert not call(signature=signature, check_replay=True)[0].allowed
    # A different request under the same warrant is a different signature.
    assert call(path="/data/y", check_replay=True)[0].allowed


def test_a_denied_request_does_not_use_up_its_signature(call):
    store = NonceStore(ttl_seconds=120)
    denied, _ = call(path="/etc/x", check_replay=True, nonce_store=store)
    assert not denied.allowed
    assert call(check_replay=True, nonce_store=store)[0].allowed


def test_replay_check_is_off_unless_requested(call):
    enable_default_nonce_store()
    first, signature = call()
    assert first.allowed
    assert call(signature=signature)[0].allowed
    assert call(signature=signature, check_replay=True)[0].allowed
    assert not call(signature=signature, check_replay=True)[0].allowed


def test_no_store_means_no_replay_check(call):
    first, signature = call(check_replay=True)
    assert first.allowed
    assert call(signature=signature, check_replay=True)[0].allowed
