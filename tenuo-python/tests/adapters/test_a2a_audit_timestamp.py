"""A2A audit timestamps are valid ISO 8601 with a single UTC ``Z`` suffix."""

from datetime import datetime, timedelta, timezone

import pytest

from tenuo.a2a import AuditEvent, AuditEventType


def _event(ts: datetime) -> AuditEvent:
    return AuditEvent(timestamp=ts, event=AuditEventType.SKILL_INVOKED, task_id="t1")


@pytest.mark.parametrize(
    "ts",
    [
        datetime(2026, 10, 17, 12, 0, 0, 123456, tzinfo=timezone.utc),
        datetime(2026, 10, 17, 12, 0, 0, 123456),  # naive, taken as UTC
        datetime(2026, 10, 17, 17, 30, 0, 123456, tzinfo=timezone(timedelta(hours=5, minutes=30))),
    ],
)
def test_audit_timestamp_is_valid_iso8601_utc(ts):
    out = _event(ts).to_dict()["timestamp"]
    assert out == "2026-10-17T12:00:00.123456Z"
    assert out.count("Z") == 1 and "+00:00" not in out
    parsed = datetime.fromisoformat(out.replace("Z", "+00:00"))
    assert parsed.utcoffset() == timedelta(0)


def test_server_style_now_timestamp_has_one_suffix():
    out = _event(datetime.now(timezone.utc)).to_dict()["timestamp"]
    assert out.endswith("Z") and not out.endswith("+00:00Z")
    datetime.fromisoformat(out.replace("Z", "+00:00"))
