"""Customer-gateway configuration shape Cloud and the action share."""

from __future__ import annotations

from pathlib import Path

import yaml

ACTION = Path(__file__).resolve().parents[1] / "action.yml"


def test_customer_gateway_action_inputs():
    spec = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    inputs = spec["inputs"]
    assert list(inputs) == [
        "gateway_url",
        "exchange_url",
        "audience",
        "ttl",
        "trusted_roots",
    ]
    assert inputs["gateway_url"]["required"] is True
    assert "Never" in inputs["gateway_url"]["description"]
    assert "POST /v1/exchange" in inputs["exchange_url"]["description"]
    assert "tenuo:org/" in inputs["audience"]["description"]
    assert "Deploy-time" in inputs["trusted_roots"]["description"]
    assert "cloud_audience" not in inputs
