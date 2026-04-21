from concurrent.futures import ThreadPoolExecutor
import random
from datetime import timedelta

from tenuo_core import SigningKey, Warrant, py_compute_request_hash


def _shuffled_args(base_args: dict) -> dict:
    items = list(base_args.items())
    random.shuffle(items)
    return {k: v for k, v in items}


def _assert_all_equal(values: list):
    assert values, "expected non-empty output collection"
    first = values[0]
    for idx, value in enumerate(values[1:], 1):
        assert value == first, f"determinism mismatch at index {idx}"


def test_end_to_end_deterministic_sign_dedup_and_request_hash():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    tool_name = "determinism.python.e2e"
    timestamp = 1_800_000_000

    warrant = Warrant.issue(
        issuer,
        capabilities={tool_name: {}},
        ttl_seconds=int(timedelta(minutes=10).total_seconds()),
        holder=holder.public_key,
    )
    args = {
        "path": "/data/demo.txt",
        "count": 3,
        "flag": True,
        "tags": ["a", "b"],
        "score": 1.5,
    }

    def run_sign() -> bytes:
        shuffled = _shuffled_args(args)
        return warrant.sign(holder, tool_name, shuffled, timestamp=timestamp)

    def run_dedup() -> str:
        shuffled = _shuffled_args(args)
        return warrant.dedup_key(tool_name, shuffled)

    def run_hash() -> bytes:
        shuffled = _shuffled_args(args)
        return bytes(
            py_compute_request_hash(
                str(warrant.id),
                tool_name,
                shuffled,
                holder.public_key,
            )
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        sign_values = list(pool.map(lambda _: run_sign(), range(100)))
        dedup_values = list(pool.map(lambda _: run_dedup(), range(100)))
        hash_values = list(pool.map(lambda _: run_hash(), range(100)))

    _assert_all_equal(sign_values)
    _assert_all_equal(dedup_values)
    _assert_all_equal(hash_values)
