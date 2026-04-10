"""Property tests for approval module (approval.py).

Verifies:
- warrant_expires_at_unix never crashes for arbitrary input shapes
- ApprovalRequest.for_warrant_gate never crashes for mock warrants
- ApprovalRequest fields are consistent
"""

from __future__ import annotations

from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo.approval import ApprovalRequest, warrant_expires_at_unix

from .strategies import st_args_dict, st_expires_at, st_tool_name


# ---------------------------------------------------------------------------
# warrant_expires_at_unix: robustness
# ---------------------------------------------------------------------------


class TestWarrantExpiresAtUnix:
    @given(exp_value=st_expires_at)
    @settings(max_examples=100)
    def test_never_crashes(self, exp_value):
        """warrant_expires_at_unix returns int or None for any input shape."""
        mock_warrant = MagicMock()
        mock_warrant.expires_at = exp_value
        result = warrant_expires_at_unix(mock_warrant)
        assert result is None or isinstance(result, int)

    @given(ts=st.integers(min_value=0, max_value=2_000_000_000))
    @settings(max_examples=50)
    def test_int_passthrough(self, ts):
        """Integer timestamps are returned as-is."""
        mock_warrant = MagicMock()
        mock_warrant.expires_at = ts
        result = warrant_expires_at_unix(mock_warrant)
        assert result == ts

    def test_none_returns_none(self):
        mock_warrant = MagicMock()
        mock_warrant.expires_at = None
        assert warrant_expires_at_unix(mock_warrant) is None

    def test_empty_string_returns_none(self):
        mock_warrant = MagicMock()
        mock_warrant.expires_at = ""
        assert warrant_expires_at_unix(mock_warrant) is None

    @given(s=st.text(min_size=1, max_size=100))
    @settings(max_examples=50)
    def test_arbitrary_string_never_crashes(self, s):
        """Arbitrary strings either parse or return None, never crash."""
        mock_warrant = MagicMock()
        mock_warrant.expires_at = s
        result = warrant_expires_at_unix(mock_warrant)
        assert result is None or isinstance(result, int)

    def test_callable_expires_at(self):
        """When expires_at is callable, it is called first."""
        mock_warrant = MagicMock()
        mock_warrant.expires_at = lambda: 1700000000
        result = warrant_expires_at_unix(mock_warrant)
        assert result == 1700000000


# ---------------------------------------------------------------------------
# ApprovalRequest.for_warrant_gate: robustness
# ---------------------------------------------------------------------------


class TestApprovalRequestForWarrantGate:
    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=30)
    def test_never_crashes_with_mock_warrant(self, tool, args):
        """for_warrant_gate handles mock warrants without crashing."""
        mock_warrant = MagicMock()
        mock_warrant.id = "test-warrant-id"
        mock_warrant.required_approvers = MagicMock(return_value=None)
        mock_warrant.approval_threshold = MagicMock(return_value=1)
        mock_warrant.expires_at = None

        request = ApprovalRequest.for_warrant_gate(
            tool, args, mock_warrant,
            request_hash=b"\x00" * 32,
            holder_key=None,
        )
        assert isinstance(request, ApprovalRequest)
        assert request.tool == tool
        assert request.arguments == args
        assert request.warrant_id == "test-warrant-id"

    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=30)
    def test_holder_key_threaded_through(self, tool, args):
        """holder_key is preserved in the ApprovalRequest."""
        mock_warrant = MagicMock()
        mock_warrant.id = "w-123"
        mock_warrant.required_approvers = MagicMock(return_value=None)
        mock_warrant.approval_threshold = MagicMock(return_value=1)
        mock_warrant.expires_at = None

        holder = MagicMock()
        request = ApprovalRequest.for_warrant_gate(
            tool, args, mock_warrant,
            request_hash=b"\x00" * 32,
            holder_key=holder,
        )
        assert request.holder_key is holder

    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=30)
    def test_request_id_is_bytes(self, tool, args):
        """request_id is always 16 bytes."""
        mock_warrant = MagicMock()
        mock_warrant.id = "w-456"
        mock_warrant.required_approvers = MagicMock(return_value=None)
        mock_warrant.approval_threshold = MagicMock(return_value=1)
        mock_warrant.expires_at = None

        request = ApprovalRequest.for_warrant_gate(
            tool, args, mock_warrant,
            request_hash=b"\x00" * 32,
        )
        assert isinstance(request.request_id, bytes)
        assert len(request.request_id) == 16
