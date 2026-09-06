"""Exact-argument terminal leaves for the broker and containment check."""

from __future__ import annotations

import pytest

pytest.importorskip("tenuo_core")

from tenuo import Pattern
from tenuo.exceptions import MonotonicityError
from tenuo.mcp import derive_terminal_leaf, exact_argument_constraints
from tenuo_core import SigningKey, Warrant


def test_exact_argument_constraints_mapping():
    mapped = exact_argument_constraints(
        {
            "repository": "acme/widgets",
            "issue": 4127,
            "draft": True,
            "labels": ["bug"],
            "note": None,
        }
    )
    assert type(mapped["repository"]).__name__ == "Exact"
    assert type(mapped["issue"]).__name__ == "Range"
    assert type(mapped["draft"]).__name__ == "Exact"
    assert type(mapped["labels"]).__name__ == "Subset"
    assert "note" not in mapped


def test_terminal_leaf_binds_exact_args():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    parent = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(holder.public_key)
        .ttl(3600)
        .mint(issuer)
    )
    leaf, leaf_key = derive_terminal_leaf(
        parent, holder, "read_file", {"path": "/data/report.txt"}, ttl=30
    )
    assert leaf_key is not None
    holder_pk = leaf.authorized_holder
    holder_pk = holder_pk() if callable(holder_pk) else holder_pk
    assert holder_pk.to_bytes() == leaf_key.public_key.to_bytes()


def test_widening_the_path_fails_before_sign():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    parent = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(holder.public_key)
        .ttl(3600)
        .mint(issuer)
    )
    with pytest.raises(MonotonicityError):
        derive_terminal_leaf(
            parent, holder, "read_file", {"path": "/etc/passwd"}, ttl=30
        )


def test_unknown_tool_fails():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    parent = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(holder.public_key)
        .ttl(3600)
        .mint(issuer)
    )
    with pytest.raises(Exception):
        derive_terminal_leaf(parent, holder, "delete_file", {"path": "/data/x"})
