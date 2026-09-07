"""Host-product embed: exchange → leaf → one GitHub call, without the Action."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("tenuo_core")

from tenuo_core import SigningKey

from tenuo_gha.embed import EmbedConfig, EmbedError, EmbedSession

from test_cloud_contract import AUDIENCE, _cloud_stack, _token

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
if str(EXAMPLES) not in sys.path:
    sys.path.insert(0, str(EXAMPLES))

from embed_host import run_host_job  # noqa: E402


def _cfg(root: SigningKey) -> EmbedConfig:
    return EmbedConfig(
        gateway_url="http://test",
        exchange_url="http://test",
        audience=AUDIENCE,
        trusted_roots=[root.public_key.to_bytes().hex()],
        ttl_seconds=180,
    )


def test_host_product_exchanges_then_comments_once(tmp_path):
    root = SigningKey.generate()
    recorded: list = []
    _gateway, _exchange, http, rsa_key = _cloud_stack(tmp_path, root, recorded)
    run = run_host_job(
        _cfg(root),
        oidc_token=_token(rsa_key, jti="embed-1"),
        event_name="issues",
        event={"issue": {"number": 4127}},
        repository="acme/widgets",
        comment_body="Pullfrog-shaped host commented through Tenuo.",
        http=http,
        work_dir=tmp_path,
        environ={"PATH": "/usr/bin"},
    )
    assert run.warrant_id
    assert set(run.tools) == {
        "github.get_issue",
        "github.list_issue_comments",
        "github.add_comment",
    }
    assert run.comment is not None and run.comment.allowed is True
    assert run.comment.leaf_derived is True
    assert run.comment.result.get("html_url")
    assert run.cross_repo is not None and run.cross_repo.allowed is False
    github_calls = [item for item in recorded if item[0] in {"GET", "POST", "PATCH", "PUT", "DELETE"}]
    assert len(github_calls) == 1
    assert "/repos/acme/widgets/issues/4127/comments" in github_calls[0][1]


def test_embed_refuses_untrusted_exchange_roots(tmp_path):
    root = SigningKey.generate()
    recorded: list = []
    _gateway, _exchange, http, rsa_key = _cloud_stack(tmp_path, root, recorded)
    other = SigningKey.generate().public_key.to_bytes().hex()
    with EmbedSession(
        EmbedConfig(
            gateway_url="http://test",
            exchange_url="http://test",
            audience=AUDIENCE,
            trusted_roots=[other],
        ),
        http=http,
        work_dir=tmp_path,
        environ={"PATH": "/usr/bin"},
    ) as session:
        with pytest.raises(EmbedError, match="not in configured trust"):
            session.exchange(
                oidc_token=_token(rsa_key, jti="embed-bad-root"),
                event_name="issues",
                event={"issue": {"number": 4127}},
                repository="acme/widgets",
            )


def test_embed_refuses_unknown_event(tmp_path):
    root = SigningKey.generate()
    recorded: list = []
    _gateway, _exchange, http, rsa_key = _cloud_stack(tmp_path, root, recorded)
    with EmbedSession(
        _cfg(root),
        http=http,
        work_dir=tmp_path,
        environ={"PATH": "/usr/bin"},
    ) as session:
        with pytest.raises(EmbedError, match="pull_request"):
            session.exchange(
                oidc_token=_token(rsa_key, jti="embed-pr"),
                event_name="pull_request",
                event={"pull_request": {"number": 9}},
                repository="acme/widgets",
            )
    assert recorded == []
