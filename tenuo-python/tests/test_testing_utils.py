
import unittest
import os
from unittest.mock import MagicMock

# Mock tenuo_core BEFORE tenuo imports
import sys
sys.modules["tenuo_core"] = MagicMock()
sys.modules["tenuo_core"].SigningKey = MagicMock()  # type: ignore[attr-defined]
sys.modules["tenuo_core"].Warrant = MagicMock()  # type: ignore[attr-defined]

# Mock external dependencies
sys.modules["typing_extensions"] = MagicMock()
class MockAnnotated:
    def __class_getitem__(cls, item):  # type: ignore[misc]
        return item
sys.modules["typing_extensions"].Annotated = MockAnnotated  # type: ignore[attr-defined]

sys.modules["fastapi"] = MagicMock()
sys.modules["pydantic"] = MagicMock()
class MockBaseModel:
    pass
sys.modules["pydantic"].BaseModel = MockBaseModel  # type: ignore[attr-defined]

# Set test mode
os.environ["TENUO_TEST_MODE"] = "1"

from tenuo.testing import assert_denied, assert_authorized, AuthorizationAssertionError  # noqa: E402
from tenuo.exceptions import AuthorizationDenied  # noqa: E402

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

