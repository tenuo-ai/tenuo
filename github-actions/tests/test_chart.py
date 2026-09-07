"""Helm chart: two identities, secret profile, refuse-to-render otherwise."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tenuo_gha.config import GatewayConfig

CHART = Path(__file__).resolve().parents[2] / "charts" / "tenuo-github-actions"
CI_VALUES = CHART / "ci" / "secret-values.yaml"

helm = shutil.which("helm")
needs_helm = pytest.mark.skipif(helm is None, reason="helm is not installed")


def _template(*extra: str) -> subprocess.CompletedProcess[str]:
    assert helm is not None
    return subprocess.run(
        [helm, "template", "tenuo", str(CHART), "-f", str(CI_VALUES), *extra],
        check=False,
        capture_output=True,
        text=True,
    )


@needs_helm
def test_chart_renders_split_identities():
    rendered = _template()
    assert rendered.returncode == 0, rendered.stderr
    docs = [doc for doc in yaml.safe_load_all(rendered.stdout) if doc]
    names = {(doc["kind"], doc["metadata"]["name"]) for doc in docs}
    assert ("Deployment", "tenuo-tenuo-github-actions-exchange") in names
    assert ("Deployment", "tenuo-tenuo-github-actions-gateway") in names
    assert ("ServiceAccount", "tenuo-tenuo-github-actions-exchange") in names
    assert ("ServiceAccount", "tenuo-tenuo-github-actions-gateway") in names

    exchange = next(doc for doc in docs if doc["kind"] == "ConfigMap" and doc["metadata"]["name"].endswith("exchange"))
    gateway = next(doc for doc in docs if doc["kind"] == "ConfigMap" and doc["metadata"]["name"].endswith("gateway"))
    exchange_cfg = yaml.safe_load(exchange["data"]["gateway.yaml"])
    gateway_cfg = yaml.safe_load(gateway["data"]["gateway.yaml"])
    parsed_exchange = GatewayConfig.from_mapping(exchange_cfg, environ={"TENUO_ROLE": "exchange"})
    parsed_gateway = GatewayConfig.from_mapping(gateway_cfg, environ={"TENUO_ROLE": "gateway"})
    assert parsed_exchange.secret_issuer_key == "issuer.pem"
    assert parsed_exchange.github_app_id is None
    assert parsed_gateway.secret_issuer_key is None
    assert parsed_gateway.github_app_id == "123456"


@needs_helm
def test_chart_refuses_kms_and_a_shared_secret():
    kms = _template("--set", "signing.profile=kms")
    assert kms.returncode != 0
    assert "signing.profile must be secret" in kms.stderr
    shared = _template("--set", "gateway.secrets.existingSecret=tenuo-exchange-keys")
    assert shared.returncode != 0
    assert "cannot share a key Secret" in shared.stderr
