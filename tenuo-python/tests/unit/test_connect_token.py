"""ConnectToken: strict version, field validation, redaction, normalization."""

from __future__ import annotations

import base64
import pickle

import pytest

from tenuo import ConnectToken
from tenuo.exceptions import ConfigurationError


def _token(payload: str, *, padded: bool = False) -> str:
    raw = payload.encode("utf-8")
    engine = base64.urlsafe_b64encode(raw)
    if not padded:
        engine = engine.rstrip(b"=")
    return "tenuo_ct_" + engine.decode("ascii")


def test_parse_strips_v1_and_trailing_slash():
    raw = _token('{"v":1,"e":"https://control.example.com/v1/","k":"tc_abc","a":"ag","t":"tok"}')
    ct = ConnectToken.parse(raw)
    assert ct.version == 1
    assert ct.endpoint == "https://control.example.com"
    assert ct.api_key == "tc_abc"
    assert ct.agent_id == "ag"
    assert ct.registration_token == "tok"
    assert not ct.needs_endpoint_base


def test_reject_missing_version():
    raw = _token('{"e":"https://control.example.com","k":"tc_abc"}')
    with pytest.raises(ConfigurationError, match="version"):
        ConnectToken.parse(raw)


def test_reject_v0_and_future_versions():
    with pytest.raises(ConfigurationError, match="version 0"):
        ConnectToken.parse(_token('{"v":0,"e":"https://control.example.com","k":"tc_abc"}'))
    with pytest.raises(ConfigurationError, match="version 2"):
        ConnectToken.parse(_token('{"v":2,"e":"https://control.example.com","k":"tc_abc"}'))


def test_reject_empty_fields():
    with pytest.raises(ConfigurationError, match="endpoint"):
        ConnectToken.parse(_token('{"v":1,"e":"","k":"tc_abc"}'))
    with pytest.raises(ConfigurationError, match="api_key"):
        ConnectToken.parse(_token('{"v":1,"e":"https://control.example.com","k":""}'))


def test_reject_missing_prefix_and_empty():
    with pytest.raises(ConfigurationError):
        ConnectToken.parse("not_a_token")
    with pytest.raises(ConfigurationError):
        ConnectToken.parse("   ")


def test_padded_base64url_and_registration_alias():
    raw = _token(
        '{"v":1,"e":"https://control.example.com/v1","k":"tc_abc","r":"tok-alias"}',
        padded=True,
    )
    ct = ConnectToken.parse(raw)
    assert ct.registration_token == "tok-alias"


def test_relative_endpoint_needs_caller_base():
    ct = ConnectToken.parse(_token('{"v":1,"e":"/v1","k":"tc_abc"}'))
    assert ct.needs_endpoint_base
    ct.resolve_endpoint("https://control.example.com/v1")
    assert ct.endpoint == "https://control.example.com"
    assert not ct.needs_endpoint_base


def test_resolve_endpoint_does_not_replace_absolute_origin():
    ct = ConnectToken.parse(_token('{"v":1,"e":"https://control.example.com/v1","k":"tc_abc"}'))
    ct.resolve_endpoint("https://other.example")
    assert ct.endpoint == "https://control.example.com"


def test_resolve_endpoint_rejects_empty_or_relative_base():
    ct = ConnectToken.parse(_token('{"v":1,"e":"/v1","k":"tc_abc"}'))
    with pytest.raises(ConfigurationError):
        ct.resolve_endpoint("/v1")
    with pytest.raises(ConfigurationError):
        ct.resolve_endpoint("")


def test_repr_str_pickle_and_errors_never_leak_credentials():
    secret_key = "tc_super_secret_key"
    secret_reg = "reg_token_secret"
    raw = _token(
        f'{{"v":1,"e":"https://control.example.com/v1","k":"{secret_key}","t":"{secret_reg}"}}'
    )
    ct = ConnectToken.parse(raw)
    for rendered in (repr(ct), str(ct), f"{ct}"):
        assert secret_key not in rendered
        assert secret_reg not in rendered
        assert "[REDACTED]" in rendered
        assert "https://control.example.com" in rendered
    with pytest.raises(TypeError):
        pickle.dumps(ct)
    with pytest.raises(ConfigurationError) as exc:
        ConnectToken.parse("tenuo_ct_%%%%")
    assert secret_key not in str(exc.value)
    assert raw not in str(exc.value)
