"""Opt-in: an OAuth gateway (Envoy with Keycloak tokens) that also checks warrants.

CI runs this explicitly, with real Keycloak, Envoy and the Tenuo authorizer.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("TENUO_OAUTH_GATEWAY_SMOKE") != "1",
    reason="Set TENUO_OAUTH_GATEWAY_SMOKE=1; needs Docker Compose",
)
def test_gateway_keeps_its_token_check_and_adds_warrants():
    python_root = Path(__file__).resolve().parents[2]
    subprocess.run(
        [sys.executable, str(python_root / "examples/oauth/gateway/check.py")],
        env={**os.environ, "PYTHONPATH": str(python_root)},
        check=True,
        timeout=600,
    )
