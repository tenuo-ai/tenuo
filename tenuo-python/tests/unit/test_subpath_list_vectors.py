"""Core matching and delegation decisions shared with Rust and TypeScript."""

import json
from pathlib import Path

import pytest

from tenuo import Exact, SigningKey, Subpath, Subset, Warrant

SUITE = json.loads((Path(__file__).resolve().parents[3] / "tests/vectors/subpath-lists.json").read_text())


def parent(root, key):
    return Warrant.mint_builder().capability("read", paths=Subpath(root)).holder(key.public_key).ttl(60).mint(key)


@pytest.mark.parametrize("case", SUITE["matching"], ids=lambda case: case["name"])
def test_subpath_list_matching(case):
    key = SigningKey.generate()
    assert parent(case["root"], key).allows("read", {"paths": case["value"]}) is case["allowed"]


@pytest.mark.parametrize("case", SUITE["attenuation"], ids=lambda case: case["name"])
def test_subpath_list_attenuation(case):
    key = SigningKey.generate()
    constraint = Subset(case["value"]) if case["kind"] == "subset" else Exact(case["value"])
    builder = parent(case["root"], key).grant_builder().capability("read", paths=constraint).holder(key.public_key)
    if case["allowed"]:
        builder.grant(key)
    else:
        with pytest.raises(Exception):
            builder.grant(key)
