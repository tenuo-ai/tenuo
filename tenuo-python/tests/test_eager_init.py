from pathlib import Path

import pytest
import tenuo_core as core
from tenuo.exceptions import ConfigurationError, TenuoError, ValidationError


def _assert_raises(exc_type, fn):
    with pytest.raises(exc_type):
        fn()


def test_authorizer_init_fails_immediately_on_invalid_args():
    _assert_raises(ValidationError, lambda: core.Authorizer(clock_tolerance_secs=-1))
    _assert_raises(ValidationError, lambda: core.Authorizer(pop_window_secs=0))
    _assert_raises(ValidationError, lambda: core.Authorizer(pop_max_windows=0))


def test_key_and_warrant_parsers_fail_at_construction():
    _assert_raises(ValidationError, lambda: core.SigningKey.from_bytes(b"short"))
    _assert_raises(ValidationError, lambda: core.PublicKey.from_bytes(b"short"))
    _assert_raises(TenuoError, lambda: core.Warrant.from_bytes(b"not-cbor"))
    _assert_raises(TenuoError, lambda: core.Warrant.from_base64("not-base64"))


def test_mcp_config_parsers_fail_at_construction(tmp_path: Path):
    missing = tmp_path / "missing.yaml"
    _assert_raises(ConfigurationError, lambda: core.McpConfig.from_file(str(missing)))

    tools = []
    for i in range(201):
        tools.append(
            f"  tool_{i}:\n"
            f"    description: \"Tool {i}\"\n"
            "    constraints: {}\n"
        )
    cfg = (
        'version: "1"\n'
        "settings:\n"
        "  trusted_issuers: []\n"
        "tools:\n"
        + "".join(tools)
    )
    cfg_path = tmp_path / "too_many_tools.yaml"
    cfg_path.write_text(cfg, encoding="utf-8")

    parsed = core.McpConfig.from_file(str(cfg_path))
    _assert_raises(ConfigurationError, lambda: core.CompiledMcpConfig.compile(parsed))
