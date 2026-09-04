"""Concierge image does not require a prebuilt TENUO_WHEEL path."""

from __future__ import annotations

from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


def test_dockerfile_installs_tenuo_without_a_wheel_arg():
    text = (PACKAGE / "Dockerfile").read_text(encoding="utf-8")
    assert "TENUO_WHEEL" not in text
    assert "COPY ${TENUO_WHEEL}" not in text
    assert "TENUO_PIP_SPEC" in text
    assert "docker/wheels/*.whl" in text
    assert "--only-binary=:all:" in text
    assert "slim-trixie" in text
    assert "tenuo==0.2.4" in text
    assert "HEALTHCHECK" in text
    healthcheck = text.split("HEALTHCHECK", 1)[1]
    assert "/ready" in healthcheck
    assert "/health" not in healthcheck


def test_pyproject_pins_fastmcp_below_4():
    text = (PACKAGE / "pyproject.toml").read_text(encoding="utf-8")
    assert "fastmcp>=3.2.1,<4" in text


def test_compose_does_not_require_tenuo_wheel():
    text = (PACKAGE / "examples" / "compose.yaml").read_text(encoding="utf-8")
    assert "TENUO_WHEEL" not in text
    assert "TENUO_PIP_SPEC" in text
    assert "linux/amd64" in text
    assert "healthcheck" in text
    assert "/ready" in text
    assert "/health" not in text.split("healthcheck", 1)[1]
