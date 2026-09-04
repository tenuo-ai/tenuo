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


def test_compose_does_not_require_tenuo_wheel():
    text = (PACKAGE / "examples" / "compose.yaml").read_text(encoding="utf-8")
    assert "TENUO_WHEEL" not in text
    assert "TENUO_PIP_SPEC" in text
    assert "linux/amd64" in text
