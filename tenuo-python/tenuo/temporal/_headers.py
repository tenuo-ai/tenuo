"""Header serialization and extraction for Tenuo-Temporal warrant transport."""

from __future__ import annotations

import binascii
import gzip
import logging
from typing import Any, Dict, Optional

from tenuo.temporal._constants import (
    TENUO_COMPRESSED_HEADER,
    TENUO_KEY_ID_HEADER,
    TENUO_WARRANT_HEADER,
    TENUO_WIRE_FORMAT_HEADER,
    _TEMPORAL_WARRANT_ENCODING_VERSION,
    _WARRANT_DECOMPRESS_MAX_BYTES,
    _gzip_decompress_limited,
)
from tenuo.temporal.exceptions import ChainValidationError, TenuoContextError

logger = logging.getLogger("tenuo.temporal")


def tenuo_headers(
    warrant: Any,
    key_id: str,
    *,
    compress: bool = True,
) -> Dict[str, bytes]:
    """Create headers dict for starting a workflow with Tenuo authorization.

    Args:
        warrant: The warrant authorizing this workflow
        key_id: Identifier for the holder's signing key. The actual signing
            key is resolved at runtime by workers via KeyResolver from secure
            storage (Vault, AWS Secrets Manager, GCP Secret Manager, etc.).
        compress: Whether to gzip compress the warrant (default: True)

    Returns:
        Headers dict to pass to client.start_workflow()

    Security:
        **CRITICAL**: Private keys are NEVER transmitted in headers. Workers
        resolve keys from secure storage using the key_id. This ensures:
        - Keys never leave secure boundaries (HSM, KMS, Vault)
        - Keys are not persisted in Temporal's database
        - Keys are not transmitted over the network
        - Compliance with NIST SP 800-57, OWASP, SOC2 requirements

    Example:
        await client.start_workflow(
            MyWorkflow.run,
            args=[...],
            headers=tenuo_headers(warrant, "prod-agent-2024"),
        )
    """
    try:
        from tenuo_core import SigningKey
        if isinstance(key_id, SigningKey):
            raise TypeError(
                "key_id must be a string identifier, not a SigningKey. "
                "Private keys must never be transmitted in headers. "
                "Use a string key ID and configure KeyResolver on workers."
            )
    except ImportError:
        pass
    if not isinstance(key_id, str):
        raise TypeError(
            f"key_id must be a string identifier, got {type(key_id).__name__}. "
            "Private keys must never be transmitted in headers."
        )

    warrant_bytes = bytes(warrant.to_bytes())

    headers: Dict[str, bytes] = {
        TENUO_KEY_ID_HEADER: key_id.encode("utf-8"),
        TENUO_WIRE_FORMAT_HEADER: _TEMPORAL_WARRANT_ENCODING_VERSION,
    }

    if compress:
        compressed = gzip.compress(warrant_bytes, compresslevel=9)
        headers[TENUO_WARRANT_HEADER] = compressed
        headers[TENUO_COMPRESSED_HEADER] = b"1"
    else:
        headers[TENUO_WARRANT_HEADER] = warrant_bytes
        headers[TENUO_COMPRESSED_HEADER] = b"0"

    return headers


def _extract_warrant_from_headers(headers: Dict[str, bytes]) -> Any:
    """Extract and deserialize warrant from headers.

    ``x-tenuo-warrant`` must be raw CBOR (optionally gzip-compressed when
    ``x-tenuo-compressed`` is ``1``). Payloads that are not valid warrant CBOR
    raise ``ChainValidationError``.

    Returns:
        Warrant object, or None if no warrant header present.

    Raises:
        ChainValidationError: If warrant cannot be deserialized
    """
    from tenuo_core import Warrant

    raw = headers.get(TENUO_WARRANT_HEADER)
    if raw is None:
        return None

    try:
        is_compressed = headers.get(TENUO_COMPRESSED_HEADER, b"0") == b"1"

        if is_compressed:
            cbor_bytes = _gzip_decompress_limited(raw)
        else:
            cbor_bytes = raw
            if len(cbor_bytes) > _WARRANT_DECOMPRESS_MAX_BYTES:
                raise ValueError(
                    f"Warrant payload too large: {len(cbor_bytes)} bytes "
                    f"(limit {_WARRANT_DECOMPRESS_MAX_BYTES})"
                )
        return Warrant.from_bytes(cbor_bytes)

    except (ValueError, EOFError, gzip.BadGzipFile, UnicodeDecodeError, binascii.Error) as e:
        raise ChainValidationError(
            reason=f"Failed to deserialize warrant: {e}",
            depth=0,
        )
    except ChainValidationError:
        raise
    except Exception:
        raise


def _extract_key_id_from_headers(headers: Dict[str, bytes]) -> Optional[str]:
    """Extract key ID from headers."""
    raw = headers.get(TENUO_KEY_ID_HEADER)
    if raw is None:
        return None
    return raw.decode("utf-8")


def _unwrap_payload_headers(headers: Any) -> Dict[str, bytes]:
    """Convert a Temporal header mapping to plain ``Dict[str, bytes]``.

    ``workflow.info().headers`` is ``Mapping[str, Payload]`` where each
    ``Payload`` has a ``.data`` attribute containing the raw bytes.
    ``_workflow_headers_store`` values are already ``Dict[str, bytes]``.

    This helper normalises both representations so callers don't need
    to care which one they received.
    """
    out: Dict[str, bytes] = {}
    for k, v in (headers or {}).items():
        if isinstance(v, bytes):
            out[k] = v
        elif hasattr(v, "data") and isinstance(getattr(v, "data", None), bytes):
            out[k] = v.data
        else:
            out[k] = bytes(v) if v is not None else b""
    return out


def _current_workflow_headers() -> Dict[str, bytes]:
    """Return Tenuo headers from the active workflow as plain bytes.

    Raises ``TenuoContextError`` if ``temporalio`` is not importable.
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    info = workflow.info()
    return _unwrap_payload_headers(getattr(info, "headers", {}))
