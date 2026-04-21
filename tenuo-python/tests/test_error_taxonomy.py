import pytest

import tenuo_core as core
from tenuo.exceptions import TenuoError


def _assert_tenuo_error(fn):
    with pytest.raises(Exception) as exc_info:
        fn()
    assert isinstance(exc_info.value, TenuoError), (
        f"expected TenuoError subclass, got {type(exc_info.value).__name__}: {exc_info.value}"
    )


def test_common_invalid_inputs_raise_tenuo_errors():
    _assert_tenuo_error(lambda: core.SigningKey.from_bytes(b"short"))
    _assert_tenuo_error(lambda: core.PublicKey.from_bytes(b"short"))
    _assert_tenuo_error(lambda: core.Signature.from_bytes(b"short"))
    _assert_tenuo_error(lambda: core.WarrantType("invalid"))
    _assert_tenuo_error(lambda: core.Clearance(object()))
    _assert_tenuo_error(lambda: core.Authorizer().verify_chain([]))


def test_function_level_validation_errors_are_tenuo_errors():
    _assert_tenuo_error(lambda: core.py_compute_request_hash("w", "t", {"k": object()}, None))
    _assert_tenuo_error(lambda: core.verify_approvals(b"short", [], [], 1, 30))
    _assert_tenuo_error(lambda: core.verify_approvals(bytes(32), [], [], 0, 30))


def test_mcp_config_errors_are_tenuo_errors(tmp_path):
    missing = tmp_path / "missing.yml"
    _assert_tenuo_error(lambda: core.McpConfig.from_file(str(missing)))
