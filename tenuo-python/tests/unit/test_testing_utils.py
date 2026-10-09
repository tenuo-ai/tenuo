import os
import sys
import types
import unittest
from unittest import mock
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
from tenuo.testing import (  # noqa: E402
    AuthorizationAssertionError,
    _is_test_environment,
    assert_authorized,
    assert_can_grant,
    assert_cannot_grant,
    assert_denied,
)


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


class TestGrantAssertions(unittest.TestCase):
    """assert_can_grant / assert_cannot_grant against real grants.

    assert_can_grant used to pass the parent's timedelta TTL to the builder,
    so every grant raised TypeError and assert_cannot_grant, which treated any
    failure as a refusal, passed vacuously.
    """

    def setUp(self):
        from tenuo import Exact, SigningKey, Warrant

        self.Exact = Exact
        self.key = SigningKey.generate()
        self.parent = (
            Warrant.mint_builder()
            .capability("read_record", record_id=Exact("a"))
            .holder(self.key.public_key)
            .ttl(300)
            .mint(self.key)
        )

    def test_can_grant_returns_a_usable_child(self):
        child, child_key = assert_can_grant(self.parent, self.key, ["read_record"], {"record_id": self.Exact("a")})
        self.assertEqual(child.expires_at(), self.parent.expires_at())
        with assert_authorized(child, child_key, "read_record", {"record_id": "a"}):
            pass

    def test_can_grant_rejects_a_widening(self):
        with self.assertRaises(AuthorizationAssertionError):
            assert_can_grant(self.parent, self.key, ["read_record"], {"record_id": self.Exact("b")})

    def test_cannot_grant_accepts_a_widened_value(self):
        assert_cannot_grant(
            self.parent,
            self.key,
            ["read_record"],
            {"record_id": self.Exact("b")},
            expected_reason="ExactValueMismatch",
        )

    def test_cannot_grant_accepts_an_unheld_tool(self):
        assert_cannot_grant(self.parent, self.key, ["delete_record"], expected_reason="MonotonicityError")

    def test_cannot_grant_rejects_a_valid_narrowing(self):
        """The regression: a grant that succeeds must fail the assertion."""
        with self.assertRaisesRegex(AuthorizationAssertionError, "Expected grant to FAIL"):
            assert_cannot_grant(self.parent, self.key, ["read_record"], {"record_id": self.Exact("a")})

    def test_cannot_grant_custom_message_still_fails(self):
        with self.assertRaisesRegex(AuthorizationAssertionError, "^custom$"):
            assert_cannot_grant(
                self.parent, self.key, ["read_record"], {"record_id": self.Exact("a")}, message="custom"
            )

    def test_cannot_grant_rejects_a_non_attenuation_failure(self):
        """Signing with a key that does not hold the parent is a broken test, not a refusal."""
        from tenuo import SigningKey

        with self.assertRaisesRegex(AuthorizationAssertionError, "attenuation reason"):
            assert_cannot_grant(self.parent, SigningKey.generate(), ["delete_record"])

    def test_cannot_grant_checks_expected_reason(self):
        with self.assertRaisesRegex(AuthorizationAssertionError, "does not contain"):
            assert_cannot_grant(self.parent, self.key, ["delete_record"], expected_reason="ClearanceViolation")


class TestEnvironmentDetection(unittest.TestCase):
    """Detection without TENUO_TEST_MODE, as a consumer's test suite runs.

    The pytest check used to look for the word "pytest" inside the test id, so
    it only passed when the test path happened to contain it.
    """

    def _detect(self, env, main_spec_name):
        main = types.ModuleType("__main__")
        main.__spec__ = types.SimpleNamespace(name=main_spec_name) if main_spec_name else None
        clean = {k: v for k, v in os.environ.items() if k not in ("TENUO_TEST_MODE", "PYTEST_CURRENT_TEST")}
        with mock.patch.dict(os.environ, {**clean, **env}, clear=True):
            with mock.patch.dict(sys.modules, {"__main__": main}):
                return _is_test_environment()

    def test_pytest_test_id_without_pytest_in_path(self):
        self.assertTrue(self._detect({"PYTEST_CURRENT_TEST": "tests/test_app.py::test_read (call)"}, None))

    def test_python_m_unittest(self):
        self.assertTrue(self._detect({}, "unittest.__main__"))

    def test_plain_script_is_not_a_test_environment(self):
        self.assertFalse(self._detect({}, None))
