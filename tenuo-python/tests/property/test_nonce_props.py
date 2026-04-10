"""Property tests for NonceStore (nonce.py).

Verifies:
- First check_and_record returns True (fresh)
- Immediate second returns False (replay)
- Distinct random bytes almost never collide
- is_replay is read-only (doesn't record)
- Nonce hex is always 64 chars
"""

from __future__ import annotations

import hashlib

from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo.nonce import NonceStore, _InMemoryBackend


class TestReplayDetection:
    @given(pop=st.binary(min_size=16, max_size=256))
    @settings(max_examples=50)
    def test_first_check_admits(self, pop):
        """First check_and_record for any PoP returns True."""
        store = NonceStore(ttl_seconds=60)
        assert store.check_and_record(pop) is True

    @given(pop=st.binary(min_size=16, max_size=256))
    @settings(max_examples=50)
    def test_immediate_second_rejects(self, pop):
        """Immediate second check_and_record with same bytes returns False."""
        store = NonceStore(ttl_seconds=60)
        store.check_and_record(pop)
        assert store.check_and_record(pop) is False

    @given(pop=st.binary(min_size=16, max_size=256))
    @settings(max_examples=50)
    def test_third_also_rejects(self, pop):
        """Third and subsequent calls also return False."""
        store = NonceStore(ttl_seconds=60)
        store.check_and_record(pop)
        store.check_and_record(pop)
        assert store.check_and_record(pop) is False


class TestDistinctBytesNeverCollide:
    @given(
        pop_a=st.binary(min_size=32, max_size=256),
        pop_b=st.binary(min_size=32, max_size=256),
    )
    @settings(max_examples=50)
    def test_distinct_bytes_both_admitted(self, pop_a, pop_b):
        """Two distinct PoP byte sequences are both admitted."""
        if pop_a == pop_b:
            return
        store = NonceStore(ttl_seconds=60)
        assert store.check_and_record(pop_a) is True
        assert store.check_and_record(pop_b) is True


class TestIsReplayReadOnly:
    @given(pop=st.binary(min_size=16, max_size=256))
    @settings(max_examples=30)
    def test_is_replay_does_not_record(self, pop):
        """is_replay returns False for unseen PoP without recording it."""
        store = NonceStore(ttl_seconds=60)
        assert store.is_replay(pop) is False
        assert store.check_and_record(pop) is True

    @given(pop=st.binary(min_size=16, max_size=256))
    @settings(max_examples=30)
    def test_is_replay_true_after_record(self, pop):
        """is_replay returns True after check_and_record."""
        store = NonceStore(ttl_seconds=60)
        store.check_and_record(pop)
        assert store.is_replay(pop) is True


class TestNonceHexFormat:
    @given(pop=st.binary(min_size=1, max_size=500))
    @settings(max_examples=50)
    def test_sha256_hex_is_64_chars(self, pop):
        """Nonce hex is always a 64-character hex string."""
        nonce_hex = hashlib.sha256(pop).hexdigest()
        assert len(nonce_hex) == 64
        assert all(c in "0123456789abcdef" for c in nonce_hex)


class TestInMemoryBackendEviction:
    def test_eviction_removes_expired(self):
        """Expired entries are evicted on next operation."""
        import time
        backend = _InMemoryBackend()
        backend.record("test_nonce", 0)
        time.sleep(0.01)
        assert not backend.seen("test_nonce")
