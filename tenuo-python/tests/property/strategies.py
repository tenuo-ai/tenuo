"""Reusable Hypothesis strategies for Tenuo property-based tests.

Provides strategies for generating warrants, keys, tool names, argument dicts,
MCP meta envelopes, Temporal headers, and other domain objects used across all
adapter property tests.
"""

from __future__ import annotations

import base64
import time
from typing import Any, Dict, List, Optional, Tuple

from hypothesis import strategies as st

from tenuo import SigningKey, Warrant
from tenuo.bound_warrant import BoundWarrant

# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

st_tool_name = st.from_regex(r"[a-z][a-z0-9_]{0,29}", fullmatch=True)

st_simple_value = st.one_of(
    st.text(min_size=0, max_size=50),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
    st.booleans(),
)

st_args_dict = st.dictionaries(
    keys=st.from_regex(r"[a-z][a-z0-9_]{0,19}", fullmatch=True),
    values=st_simple_value,
    min_size=0,
    max_size=8,
)

st_base64_blob = st.binary(min_size=0, max_size=200).map(
    lambda b: base64.b64encode(b).decode()
)

# RFC 3339 timestamps in various forms
st_rfc3339 = st.one_of(
    st.just("2025-01-01T00:00:00Z"),
    st.just("2025-06-15T12:30:00+00:00"),
    st.just("2025-12-31T23:59:59Z"),
    st.just(""),
    st.integers(min_value=0, max_value=2_000_000_000).map(str),
)

# ---------------------------------------------------------------------------
# Warrant bundles (real cryptographic objects via Rust)
# ---------------------------------------------------------------------------


def st_signing_key() -> st.SearchStrategy[SigningKey]:
    """Generate a fresh Ed25519 signing key via tenuo_core."""
    return st.builds(SigningKey.generate)


@st.composite
def st_warrant_bundle(
    draw: st.DrawFn,
    *,
    tool_name: Optional[st.SearchStrategy[str]] = None,
    args: Optional[st.SearchStrategy[Dict[str, Any]]] = None,
    ttl_seconds: int = 3600,
    with_constraints: bool = False,
) -> Tuple[Warrant, SigningKey, str, Dict[str, Any]]:
    """Generate a (warrant, issuer_key, tool_name, args) bundle.

    The warrant is self-issued (issuer == holder) for simplicity.
    The Rust core will accept it when the issuer is in trusted_roots.
    """
    key = SigningKey.generate()
    tool = draw(tool_name or st_tool_name)
    tool_args = draw(args or st_args_dict)

    capabilities: Dict[str, Any] = {tool: {}}
    warrant = Warrant.issue(
        keypair=key,
        capabilities=capabilities,
        ttl_seconds=ttl_seconds,
        holder=key.public_key,
    )
    return warrant, key, tool, tool_args


@st.composite
def st_bound_warrant_bundle(
    draw: st.DrawFn,
    *,
    tool_name: Optional[st.SearchStrategy[str]] = None,
    args: Optional[st.SearchStrategy[Dict[str, Any]]] = None,
) -> Tuple[BoundWarrant, SigningKey, str, Dict[str, Any]]:
    """Generate (bound_warrant, issuer_key, tool_name, args).

    Returns a BoundWarrant usable with enforce_tool_call in sign mode.
    """
    warrant, key, tool, tool_args = draw(
        st_warrant_bundle(tool_name=tool_name, args=args)
    )
    bound = warrant.bind(key)
    return bound, key, tool, tool_args


@st.composite
def st_delegation_chain(
    draw: st.DrawFn,
    depth: int = 2,
) -> Tuple[List[Warrant], SigningKey, SigningKey, str, Dict[str, Any]]:
    """Generate a delegation chain of the given depth.

    Returns (chain_warrants, root_key, holder_key, tool, args) where
    chain_warrants[0] is the root warrant and chain_warrants[-1] is the leaf.
    """
    root_key = SigningKey.generate()
    tool = draw(st_tool_name)
    tool_args = draw(st_args_dict)

    chain: List[Warrant] = []
    current_issuer = root_key

    for i in range(depth):
        next_holder = SigningKey.generate() if i < depth - 1 else SigningKey.generate()
        if i == 0:
            w = Warrant.issue(
                keypair=current_issuer,
                capabilities={tool: {}},
                ttl_seconds=3600,
                holder=next_holder.public_key,
            )
        else:
            w = chain[-1].delegate(
                current_issuer,
                capabilities={tool: {}},
                ttl_seconds=3600,
                holder=next_holder.public_key,
            )
        chain.append(w)
        current_issuer = next_holder

    return chain, root_key, current_issuer, tool, tool_args


# ---------------------------------------------------------------------------
# MCP meta envelopes
# ---------------------------------------------------------------------------

st_meta_tenuo_envelope = st.fixed_dictionaries(
    mapping={},
    optional={
        "warrant": st.one_of(st_base64_blob, st.none()),
        "signature": st.one_of(st_base64_blob, st.none()),
        "approvals": st.lists(st_base64_blob, max_size=10),
    },
)

st_mcp_meta = st.one_of(
    st.none(),
    st.fixed_dictionaries(mapping={}, optional={"tenuo": st_meta_tenuo_envelope}),
    st.dictionaries(st.text(min_size=1, max_size=10), st_simple_value, max_size=3),
)


@st.composite
def st_valid_mcp_envelope(
    draw: st.DrawFn,
) -> Tuple[Dict[str, Any], Warrant, SigningKey, str, Dict[str, Any]]:
    """Generate a valid MCP _meta envelope with real warrant and PoP.

    Returns (meta_dict, warrant, key, tool_name, args) where the meta dict
    has properly base64-encoded warrant and signature.
    """
    warrant, key, tool, tool_args = draw(st_warrant_bundle())
    pop = warrant.sign(key, tool, tool_args, int(time.time()))

    meta = {
        "tenuo": {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(bytes(pop)).decode(),
        }
    }
    return meta, warrant, key, tool, tool_args


# ---------------------------------------------------------------------------
# Temporal headers
# ---------------------------------------------------------------------------

@st.composite
def st_temporal_headers(draw: st.DrawFn) -> Dict[str, bytes]:
    """Random bytes that look like Temporal activity headers."""
    keys_strat = st.sampled_from([
        "x-tenuo-warrant", "x-tenuo-key-id", "x-tenuo-compressed",
        "x-tenuo-pop", "x-tenuo-stack",
    ])
    return draw(st.dictionaries(
        keys=keys_strat,
        values=st.binary(min_size=0, max_size=500),
        min_size=0,
        max_size=5,
    ))


# ---------------------------------------------------------------------------
# Denial reason strings (for _extract_violated_field)
# ---------------------------------------------------------------------------

st_denial_reason = st.one_of(
    st.none(),
    st.just(""),
    st.text(min_size=0, max_size=200),
    st.just("Constraint 'amount' not satisfied"),
    st.just("Range exceeded for 'path'"),
    st.just("Pattern mismatch for 'query'"),
    st.just("'recipient' constraint violation"),
    st.just("field 'name'"),
)

# ---------------------------------------------------------------------------
# Expires-at values (for warrant_expires_at_unix)
# ---------------------------------------------------------------------------

st_expires_at = st.one_of(
    st.none(),
    st.just(""),
    st.integers(min_value=0, max_value=2_000_000_000),
    st.just("2025-01-01T00:00:00Z"),
    st.just("2025-06-15T12:30:00+00:00"),
    st.just("not-a-date"),
    st.just("2025-12-31T23:59:59Z"),
    st.text(min_size=0, max_size=30),
)
