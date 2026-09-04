"""Doctor, job summary, and the org reusable workflow."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml
from starlette.testclient import TestClient

pytest.importorskip("tenuo_core")

from tenuo_core import SigningKey

from tenuo_gha.app import Gateway
from tenuo_gha.config import GatewayConfig
from tenuo_gha.doctor import format_report, run_doctor
from tenuo_gha.exchange import Exchange
from tenuo_gha.http import build_http
from tenuo_gha.summary import format_job_summary, write_job_summary

AUDIENCE = "tenuo:org/acme"
ISSUER = "https://token.actions.githubusercontent.com"


PACKAGE = Path(__file__).resolve().parents[1]
WORKFLOW = PACKAGE / ".github" / "workflows" / "agent.yml"


class _Http:
    def __init__(self, app) -> None:
        self._client = TestClient(app)

    def get(self, url, **kwargs):
        return self._client.get(urlparse(url).path or "/")

    def post(self, url, json=None, **kwargs):
        return self._client.post(urlparse(url).path or "/", json=json)

    def close(self) -> None:
        return None


class _Mux:
    def __init__(self, routes: dict) -> None:
        self._routes = routes

    def _pick(self, url: str) -> _Http:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return self._routes[origin]

    def get(self, url, **kwargs):
        return self._pick(url).get(url, **kwargs)

    def post(self, url, json=None, **kwargs):
        return self._pick(url).post(url, json=json, **kwargs)

    def close(self) -> None:
        return None


def _both_roles(tmp_path: Path, issuer: SigningKey) -> GatewayConfig:
    return GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"], "issuer": ISSUER},
            "signing": {"provider": "memory"},
            "role": "both",
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "exchange": {"audience": AUDIENCE, "ttl_max": "15m"},
            "receipts": {"path": str(tmp_path / "receipts.jsonl")},
        },
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ALLOW_COMBINED_ROLES": "1",
            "TENUO_ROLE": "both",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )


def _exchange_only(tmp_path: Path, issuer: SigningKey) -> GatewayConfig:
    return GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"], "issuer": ISSUER},
            "signing": {"provider": "memory"},
            "role": "exchange",
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "exchange": {"audience": AUDIENCE, "ttl_max": "15m"},
            "receipts": {"path": str(tmp_path / "ex-receipts.jsonl")},
        },
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ROLE": "exchange",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )


def _gateway_only(tmp_path: Path, issuer: SigningKey) -> GatewayConfig:
    return GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
            "signing": {"provider": "memory"},
            "role": "gateway",
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "receipts": {"path": str(tmp_path / "gw-receipts.jsonl")},
        },
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ROLE": "gateway",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )


def test_job_summary_names_the_bound_issue_and_tools():
    text = format_job_summary(
        tools=["github.get_issue", "github.add_comment"],
        repository="acme/widgets",
        ttl_seconds=900,
        warrant_id="w-1",
        expires_at="2099-01-01T00:00:00Z",
        gateway_url="https://gateway.example",
        task_binding={"type": "issue", "number": 4127},
    )
    assert "This run may" in text
    assert "`github.add_comment` on `acme/widgets#4127`" in text
    assert "TTL 900s" in text
    assert "Warrant `w-1`" in text
    assert "This warrant cannot" in text
    assert "TENUO_HOLDER_SECRET" not in text
    assert "ghs_" not in text


def test_job_summary_appends_to_github_file(tmp_path):
    dest = tmp_path / "summary.md"
    write_job_summary("## Tenuo\n", path=dest)
    write_job_summary("more", path=dest)
    assert dest.read_text(encoding="utf-8") == "## Tenuo\nmore\n"


def test_doctor_reports_combined_roles_as_a_named_fix(tmp_path):
    issuer = SigningKey.generate()
    config = _both_roles(tmp_path, issuer)
    exchange = Exchange(config, issuer_key=issuer, jwks={"keys": []})
    gateway = Gateway(config)
    http = _Http(build_http(config, exchange=exchange, gateway=gateway))
    report = run_doctor(
        gateway_url="http://test",
        exchange_url="http://test",
        audience=AUDIENCE,
        environ={"PATH": "/usr/bin"},
        client=http,
        config=config,
    )
    by_name = {row.name: row for row in report.rows}
    assert by_name["audience"].ok
    assert by_name["gateway health"].ok
    assert by_name["exchange health"].ok
    assert by_name["gateway fail-closed"].ok
    assert by_name["exchange route"].ok
    assert not by_name["split identities"].ok
    assert "TENUO_ROLE=both" in by_name["split identities"].fix
    assert not report.ok


def test_doctor_passes_split_exchange_and_gateway(tmp_path):
    issuer = SigningKey.generate()
    exchange_config = _exchange_only(tmp_path, issuer)
    gateway_config = _gateway_only(tmp_path, issuer)
    exchange = Exchange(exchange_config, issuer_key=issuer, jwks={"keys": []})
    gateway = Gateway(gateway_config)
    mux = _Mux(
        {
            "http://exchange.test": _Http(build_http(exchange_config, exchange=exchange)),
            "http://gateway.test": _Http(build_http(gateway_config, gateway=gateway)),
        }
    )
    report = run_doctor(
        gateway_url="http://gateway.test",
        exchange_url="http://exchange.test",
        audience=AUDIENCE,
        environ={"PATH": "/usr/bin"},
        client=mux,
        config=gateway_config,
    )
    by_name = {row.name: row for row in report.rows}
    assert by_name["split identities"].ok, format_report(report)
    assert by_name["gateway ready"].detail == "role=gateway"
    assert by_name["exchange ready"].detail == "role=exchange"
    assert by_name["gateway fail-closed"].ok
    assert by_name["exchange route"].ok
    assert report.ok, format_report(report)


def test_doctor_names_the_fix_when_audience_is_missing(tmp_path):
    issuer = SigningKey.generate()
    config = _gateway_only(tmp_path, issuer)
    http = _Http(build_http(config, gateway=Gateway(config)))
    report = run_doctor(
        gateway_url="http://gateway.test",
        exchange_url="http://gateway.test",
        audience="",
        environ={"GITHUB_TOKEN": "ghs_not_a_real_token"},
        client=http,
    )
    by_name = {row.name: row for row in report.rows}
    assert not by_name["audience"].ok
    assert "cloud_audience" in by_name["audience"].fix
    assert not by_name["no GitHub token in environment"].ok
    assert "Unset GITHUB_TOKEN" in by_name["no GitHub token in environment"].fix


def test_doctor_in_process_containment(tmp_path):
    issuer = SigningKey.generate()
    config = _both_roles(tmp_path, issuer)
    exchange = Exchange(config, issuer_key=issuer, jwks={"keys": []})
    http = _Http(build_http(config, exchange=exchange, gateway=Gateway(config)))
    report = run_doctor(
        gateway_url="http://test",
        exchange_url="http://test",
        audience=AUDIENCE,
        environ={"PATH": "/usr/bin", "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1"},
        client=http,
        containment=True,
    )
    by_name = {row.name: row for row in report.rows}
    assert by_name["in-process containment"].ok, by_name["in-process containment"].detail


def test_reusable_workflow_is_a_same_job_paved_road():
    raw = WORKFLOW.read_text(encoding="utf-8")
    loaded = yaml.safe_load(raw)
    triggers = loaded.get("on") or loaded.get(True)
    assert triggers["workflow_call"]
    grant = loaded["jobs"]["grant"]
    perms = grant["permissions"]
    assert perms["id-token"] == "write"
    assert perms["contents"] == "none"
    assert perms["issues"] == "none"
    assert perms["pull-requests"] == "none"
    assert "GITHUB_TOKEN" not in raw
    assert "mcp_config" in raw
    assert "steps.tenuo.outputs.mcp_config" in raw
    assert "same job" in raw
    step = grant["steps"][0]
    assert step["id"] == "tenuo"
    assert step["uses"].startswith("tenuo-ai/")
    assert "github-actions" in step["uses"]
