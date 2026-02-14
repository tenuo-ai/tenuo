"""
Tests for AuthorizedWorkflow base class.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from tenuo.temporal import AuthorizedWorkflow, TenuoContextError

# Mock dependencies
@pytest.fixture
def mock_context():
    with patch("tenuo.temporal.current_warrant") as mock_warrant, \
         patch("tenuo.temporal.current_key_id") as mock_key_id, \
         patch("tenuo.temporal.tenuo_execute_activity", new_callable=AsyncMock) as mock_exec:
        yield mock_warrant, mock_key_id, mock_exec

class TestAuthorizedWorkflow:
    def test_init_raises_if_no_warrant(self, mock_context):
        """Test that initialization fails fast if warrant is missing."""
        mock_warrant, _, _ = mock_context
        mock_warrant.side_effect = TenuoContextError("missing warrant")

        with pytest.raises(TenuoContextError) as exc:
            AuthorizedWorkflow()
        assert "AuthorizedWorkflow requires Tenuo headers" in str(exc.value)

    def test_init_raises_if_no_key_id(self, mock_context):
        """Test that initialization fails fast if key ID is missing."""
        mock_warrant, mock_key_id, _ = mock_context
        mock_warrant.return_value = MagicMock()
        mock_key_id.side_effect = TenuoContextError("missing key")

        with pytest.raises(TenuoContextError) as exc:
            AuthorizedWorkflow()
        assert "AuthorizedWorkflow requires Tenuo headers" in str(exc.value)

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

    @pytest.mark.asyncio
    async def test_execute_authorized_activity_delegates_correctly(self, mock_context):
        """Test that execute_authorized_activity calls tenuo_execute_activity."""
        mock_warrant, mock_key_id, mock_exec = mock_context
        mock_warrant.return_value = MagicMock()
        mock_key_id.return_value = "key-123"

        wf = AuthorizedWorkflow()
        activity_mock = MagicMock()

        # Execute
        await wf.execute_authorized_activity(
            activity_mock,
            args=["foo"],
            start_to_close_timeout=60
        )

        # Verify delegation
        mock_exec.assert_awaited_once_with(
            activity_mock,
            args=["foo"],
            start_to_close_timeout=60
        )

    @pytest.mark.asyncio
    async def test_multiple_activities_context_access(self, mock_context):
        """Test that multiple activity calls succeed (fetching context each time)."""
        mock_warrant, mock_key_id, mock_exec = mock_context
        mock_warrant.return_value = MagicMock()
        mock_key_id.return_value = "key-123"

        wf = AuthorizedWorkflow()

        # Call 1
        await wf.execute_authorized_activity("Act1", args=[1])
        # Call 2
        await wf.execute_authorized_activity("Act2", args=[2])

        assert mock_exec.await_count == 2

    def test_escape_hatch_availability(self):
        """Verify tenuo_execute_activity is available as an escape hatch."""
        from tenuo.temporal import tenuo_execute_activity
        assert callable(tenuo_execute_activity)
