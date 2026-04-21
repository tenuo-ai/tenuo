import pytest
import time

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


def test_to_py_err_exception_names_exist():
    import tenuo.exceptions as exc

    required_names = {
        "InvalidWarrantType",
        "IssueDepthExceeded",
        "IssuerChainTooLong",
        "SelfIssuanceProhibited",
        "ClearanceLevelExceeded",
        "UnauthorizedToolIssuance",
        "DelegationAuthorityError",
        "ConstraintDepthExceeded",
        "PayloadTooLarge",
        "RangeInclusivityExpanded",
        "ValueNotInRange",
    }
    missing = sorted(name for name in required_names if not hasattr(exc, name))
    assert not missing, f"missing exception classes in tenuo.exceptions: {missing}"


def test_warrant_expired_preserves_warrant_id():
    issuer = core.SigningKey.generate()
    holder = core.SigningKey.generate()
    warrant = core.Warrant.issue(
        issuer,
        capabilities={"tool.expire": {}},
        ttl_seconds=1,
        holder=holder.public_key,
    )
    time.sleep(2)

    authorizer = core.Authorizer(trusted_roots=[issuer.public_key])
    with pytest.raises(TenuoError) as exc_info:
        authorizer.authorize_one(warrant, "tool.expire", {}, None)

    err = exc_info.value
    details = getattr(err, "details", {})
    assert details.get("warrant_id") == str(warrant.id)
