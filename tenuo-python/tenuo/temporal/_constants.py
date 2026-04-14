"""Header constants, plugin identifiers, and wire format for Tenuo-Temporal."""

from __future__ import annotations

import gzip
import io

TENUO_WARRANT_HEADER = "x-tenuo-warrant"
TENUO_KEY_ID_HEADER = "x-tenuo-key-id"
TENUO_COMPRESSED_HEADER = "x-tenuo-compressed"
TENUO_POP_HEADER = "x-tenuo-pop"
TENUO_CHAIN_HEADER = "x-tenuo-warrant-chain"
TENUO_ARG_KEYS_HEADER = "x-tenuo-arg-keys"
TENUO_WIRE_FORMAT_HEADER = "x-tenuo-wire-format"
TENUO_APPROVALS_HEADER = "x-tenuo-approvals"

# Stable integration id for logs and Temporal Web activity summaries.
TENUO_TEMPORAL_PLUGIN_ID = "tenuo.TenuoTemporalPlugin"

# Value for ``x-tenuo-wire-format`` on outgoing headers: identifies that
# ``x-tenuo-warrant`` carries raw CBOR bytes (optionally gzip-compressed).
_TEMPORAL_WARRANT_ENCODING_VERSION = b"2"

# PoP timestamp validation window (seconds). The scheduled_time must be
# within this window. This is not configurable — security is non-negotiable.
# NOTE: this constant is currently unused; the actual PoP window is controlled
# by the Rust Authorizer (pop_window_secs=30, pop_max_windows=5 → ±60s).
# Kept for reference; do not use POP_WINDOW_SECONDS in new code.
POP_WINDOW_SECONDS = 300

# Hard cap on decompressed warrant bytes — must match tenuo_core.MAX_WARRANT_SIZE
# (64 KB, enforced again by the Rust deserializer). Capping here prevents gzip
# amplification from consuming Python memory before Rust even sees the bytes.
try:
    from tenuo_core import MAX_WARRANT_SIZE as _WARRANT_DECOMPRESS_MAX_BYTES  # type: ignore[import-not-found]
except ImportError:
    _WARRANT_DECOMPRESS_MAX_BYTES = 64 * 1024  # 64 KB fallback


def _gzip_decompress_limited(data: bytes, max_length: int = _WARRANT_DECOMPRESS_MAX_BYTES) -> bytes:
    """Decompress gzip data with a hard cap on the output size.

    ``gzip.decompress`` has no built-in size limit, so we read through a
    ``GzipFile`` and stop early if the output exceeds ``max_length``.
    """
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gf:
        result = gf.read(max_length + 1)
    if len(result) > max_length:
        raise ValueError(
            f"Decompressed warrant exceeds {max_length} bytes limit ({len(result)} bytes)"
        )
    return result
