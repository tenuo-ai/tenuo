"""ADK audit timestamps are valid ISO 8601 and hints list each skill once."""

import io
import json
from datetime import datetime

import pytest

pytest.importorskip("google.adk")

from tenuo_core import Pattern, SigningKey, Warrant  # noqa: E402

from tenuo.google_adk import TenuoGuard  # noqa: E402
from tenuo.google_adk.helpers import generate_hints  # noqa: E402


def _warrant():
    key = SigningKey.generate()
    w = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/tmp/*"))
        .capability("web_search", query=Pattern("*"))
        .holder(key.public_key)
        .ttl(600)
        .mint(key)
    )
    return w, key


def test_audit_timestamp_is_valid_iso8601_utc():
    w, key = _warrant()
    log = io.StringIO()
    guard = TenuoGuard(warrant=w, signing_key=key, trusted_roots=[key.public_key], audit_log=log)
    guard._audit("tool_allowed", "read_file", {"path": "/tmp/a"})
    ts = json.loads(log.getvalue().strip().splitlines()[-1])["timestamp"]
    assert ts.endswith("Z") and "+00:00" not in ts
    assert datetime.fromisoformat(ts.replace("Z", "+00:00")).utcoffset().total_seconds() == 0


def test_hints_list_each_skill_once():
    w, _ = _warrant()
    hints = generate_hints("shell", {"cmd": "ls"}, warrant=w)
    skills_hint = next(h for h in hints if h.startswith("Warrant has skills:"))
    assert skills_hint.count("read_file") == 1
    assert skills_hint.count("web_search") == 1
