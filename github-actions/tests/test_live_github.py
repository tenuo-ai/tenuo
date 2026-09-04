"""Live GitHub mutation through the holder. Off unless TENUO_LIVE_GITHUB=1."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("tenuo_core")

from tenuo_gha.check import all_passed, format_table
from tenuo_gha.live import LiveError, app_credentials_from_env, _token_from_env, run_live, run_live_app


@pytest.mark.live
def test_live_comment_and_demo_denials(tmp_path):
    if os.environ.get("TENUO_LIVE_GITHUB") != "1":
        pytest.skip("set TENUO_LIVE_GITHUB=1 to call api.github.com")
    try:
        token = _token_from_env()
    except LiveError as exc:
        pytest.skip(str(exc))
    repository = os.environ.get("TENUO_LIVE_GITHUB_REPO", "aimable100/tenuo-github-agentic-demo")
    foreign = os.environ.get("TENUO_LIVE_GITHUB_FOREIGN", "aimable100/tenuo-agentic-canary-private")
    result = run_live(
        repository=repository,
        foreign_repository=foreign,
        token=token,
        work=tmp_path,
    )
    assert all_passed(result.rows), format_table(result.rows)
    assert result.comment_url.startswith("https://github.com/")
    assert result.warrant_id
    assert result.receipts.strip()
    assert token not in result.receipts
    assert "installation-token" not in result.receipts
    mcp = Path(tmp_path / "mcp-config.json")
    if mcp.exists():
        text = mcp.read_text(encoding="utf-8")
        assert token not in text
        assert "TENUO_HOLDER_SECRET" not in text


@pytest.mark.live
def test_live_app_comment_and_demo_denials(tmp_path):
    if os.environ.get("TENUO_LIVE_GITHUB") != "1":
        pytest.skip("set TENUO_LIVE_GITHUB=1 to call api.github.com")
    try:
        app = app_credentials_from_env()
    except LiveError as exc:
        pytest.skip(str(exc))
    if app is None:
        pytest.skip("set TENUO_GITHUB_APP_ID and TENUO_GITHUB_APP_KEY_FILE")
    repository = os.environ.get("TENUO_LIVE_GITHUB_REPO", "aimable100/tenuo-github-agentic-demo")
    foreign = os.environ.get("TENUO_LIVE_GITHUB_FOREIGN", "aimable100/tenuo-agentic-canary-private")
    pem = Path(app["key_file"]).read_bytes()
    result = run_live_app(
        repository=repository,
        foreign_repository=foreign,
        app_id=app["app_id"],
        app_pem=pem,
        installation_id=app["installation_id"] or None,
        work=tmp_path,
    )
    assert all_passed(result.rows), format_table(result.rows)
    assert result.comment_url.startswith("https://github.com/")
    assert result.warrant_id
    assert result.receipts.strip()
    assert "BEGIN " not in result.receipts
    assert "PRIVATE KEY" not in result.receipts
    mcp = Path(tmp_path / "mcp-config.json")
    if mcp.exists():
        text = mcp.read_text(encoding="utf-8")
        assert "BEGIN " not in text
        assert "TENUO_HOLDER_SECRET" not in text
