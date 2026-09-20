import os
import sys
import unittest
from unittest.mock import MagicMock

# External dependencies might still be missing in some minimal envs, so we conditionally mock them
# BUT we always want real tenuo_core to pinpoint integration issues.

# Mock external dependencies if missing
sys.modules.setdefault("typing_extensions", MagicMock())
if "typing_extensions" in sys.modules and isinstance(sys.modules["typing_extensions"], MagicMock):

    class MockAnnotated:
        def __class_getitem__(cls, item):  # type: ignore[misc]
            return item

    sys.modules["typing_extensions"].Annotated = MockAnnotated  # type: ignore[attr-defined]

sys.modules.setdefault("fastapi", MagicMock())
sys.modules.setdefault("pydantic", MagicMock())
if "pydantic" in sys.modules and isinstance(sys.modules["pydantic"], MagicMock):

    class MockBaseModel:
        pass

    sys.modules["pydantic"].BaseModel = MockBaseModel  # type: ignore[attr-defined]

# Set test mode
os.environ["TENUO_TEST_MODE"] = "1"

from tenuo.exceptions import AuthorizationDenied  # noqa: E402
from tenuo.testing import AuthorizationAssertionError, assert_authorized, assert_denied  # noqa: E402


class TestDXTooling(unittest.TestCase):
    def test_assert_denied_context(self):
        """Test assert_denied as a context manager."""

        # 1. Should catch AuthorizationDenied
        with assert_denied():
            raise AuthorizationDenied("Denied!")

        # 2. Should catch with matching code
        with assert_denied(code="ScopeViolation"):
            # Mock error with code
            err = AuthorizationDenied("Scope violation")
            err.error_code = "ScopeViolation"
            raise err

        # 3. Should fail if matching code is wrong
        with self.assertRaises(AssertionError):
            with assert_denied(code="ScopeViolation"):
                err = AuthorizationDenied("Other error")
                err.error_code = "OtherError"
                raise err

        # 4. Should fail if no exception raised
        with self.assertRaises(AssertionError):
            with assert_denied():
                pass

    def test_assert_authorized_context(self):
        """Test assert_authorized as a context manager."""

        # 1. Should pass if checks succeed
        with assert_authorized():
            pass

        # 2. Should fail if AuthorizationDenied is raised
        with self.assertRaises(AssertionError):
            with assert_authorized():
                raise AuthorizationDenied("Should not happen")

    @unittest.skip("FIXME: Mock behavior in Python 3.9 causes confusion in assert_denied logic")
    def test_legacy_assert_denied(self):
        """Ensure legacy assert_denied still works."""
        mock_warrant = MagicMock()
        mock_warrant.sign.return_value = b"signature"
        mock_key = MagicMock()

        # Case: Authorization succeeds (should fail assertion)
        mock_warrant.authorize.return_value = True
        with self.assertRaises(AuthorizationAssertionError):
            assert_denied(mock_warrant, mock_key, "tool")

        # Case: Authorization fails (should pass assertion)
        mock_warrant.authorize.return_value = False
        assert_denied(mock_warrant, mock_key, "tool")


class TestWarrantAssertionTrustAnchor(unittest.TestCase):
    """The warrant-and-key mode of the assertion helpers (issue #675).

    ``validate()`` now requires a trust anchor. These helpers assert what a
    warrant permits, so they resolve one rather than propagating the error —
    and a missing anchor must never read as a denial.
    """

    def setUp(self):
        from tenuo import SigningKey, Warrant

        self.warrant, self.key = Warrant.quick_mint(["search"], ttl=3600)
        self.other_key = SigningKey.generate()

    def test_assert_authorized_accepts_a_permitted_tool(self):
        with assert_authorized(self.warrant, self.key, "search", {"query": "x"}):
            pass

    def test_assert_authorized_rejects_a_tool_outside_the_warrant(self):
        with self.assertRaises(AuthorizationAssertionError):
            with assert_authorized(self.warrant, self.key, "delete_everything", {}):
                pass

    def test_assert_denied_accepts_a_tool_outside_the_warrant(self):
        with assert_denied(self.warrant, self.key, "delete_everything", {}):
            pass

    def test_assert_denied_rejects_a_permitted_tool(self):
        """The regression: a resolution failure must not read as a denial."""
        with self.assertRaises(AuthorizationAssertionError):
            with assert_denied(self.warrant, self.key, "search", {"query": "x"}):
                pass

    def test_explicit_roots_are_honoured(self):
        """Passing roots asserts issuer trust on top of policy."""
        untrusted = [self.other_key.public_key]
        with assert_denied(
            self.warrant, self.key, "search", {"query": "x"}, trusted_roots=untrusted
        ):
            pass
        with assert_authorized(
            self.warrant,
            self.key,
            "search",
            {"query": "x"},
            trusted_roots=[self.warrant.issuer],
        ):
            pass
