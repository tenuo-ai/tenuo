"""
Tests for AuthorizedWorkflow base class.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tenuo.temporal import AuthorizedWorkflow, TenuoContextError

try:
    from temporalio.exceptions import ApplicationError
    _HAS_TEMPORALIO = True
except ImportError:
    _HAS_TEMPORALIO = False


def _run(coro):
    """Run an async coroutine on a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# Mock dependencies
@pytest.fixture
def mock_context():
    with patch("tenuo.temporal.current_warrant") as mock_warrant, \
         patch("tenuo.temporal.current_key_id") as mock_key_id, \
         patch("tenuo.temporal.tenuo_execute_activity", new_callable=AsyncMock) as mock_exec:
        yield mock_warrant, mock_key_id, mock_exec


# When temporalio is installed, __init__ wraps TenuoContextError in ApplicationError
# (non-retryable). When it's not installed, TenuoContextError is re-raised directly.
_INIT_ERROR = ApplicationError if _HAS_TEMPORALIO else TenuoContextError


class TestAuthorizedWorkflow:
    def test_init_raises_if_no_warrant(self, mock_context):
        """Test that initialization fails fast if warrant is missing."""
        mock_warrant, _, _ = mock_context
        mock_warrant.side_effect = TenuoContextError("missing warrant")

        with pytest.raises(_INIT_ERROR) as exc:
            AuthorizedWorkflow()
        assert "missing warrant" in str(exc.value)

    def test_init_raises_if_no_key_id(self, mock_context):
        """Test that initialization fails fast if key ID is missing."""
        mock_warrant, mock_key_id, _ = mock_context
        mock_warrant.return_value = MagicMock()
        mock_key_id.side_effect = TenuoContextError("missing key")

        with pytest.raises(_INIT_ERROR) as exc:
            AuthorizedWorkflow()
        assert "missing key" in str(exc.value)

    def test_init_succeeds_with_warrant(self, mock_context):
        """Test that initialization succeeds when dependencies are present."""
        mock_warrant, mock_key_id, _ = mock_context
        mock_warrant.return_value = MagicMock()
        mock_key_id.return_value = "key-123"

        # Should not raise
        AuthorizedWorkflow()

        # Verify validation calls were made
        mock_warrant.assert_called()
        mock_key_id.assert_called()

    def test_execute_authorized_activity_delegates_correctly(self, mock_context):
        """Test that execute_authorized_activity calls tenuo_execute_activity."""
        mock_warrant, mock_key_id, mock_exec = mock_context
        mock_warrant.return_value = MagicMock()
        mock_key_id.return_value = "key-123"

        wf = AuthorizedWorkflow()
        activity_mock = MagicMock()

        async def _test():
            await wf.execute_authorized_activity(
                activity_mock,
                args=["foo"],
                start_to_close_timeout=60,
            )
        _run(_test())

        # Verify delegation
        mock_exec.assert_awaited_once_with(
            activity_mock,
            args=["foo"],
            start_to_close_timeout=60,
        )

    def test_multiple_activities_context_access(self, mock_context):
        """Test that multiple activity calls succeed (fetching context each time)."""
        mock_warrant, mock_key_id, mock_exec = mock_context
        mock_warrant.return_value = MagicMock()
        mock_key_id.return_value = "key-123"

        wf = AuthorizedWorkflow()

        async def _test():
            await wf.execute_authorized_activity("Act1", args=[1])
            await wf.execute_authorized_activity("Act2", args=[2])
        _run(_test())

        assert mock_exec.await_count == 2

    def test_escape_hatch_availability(self):
        """Verify tenuo_execute_activity is available as an escape hatch."""
        from tenuo.temporal import tenuo_execute_activity
        assert callable(tenuo_execute_activity)
