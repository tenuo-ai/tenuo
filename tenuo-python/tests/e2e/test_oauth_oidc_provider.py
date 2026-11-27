"""Independent authorization-server interoperability, using real browser flows."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("TENUO_OIDC_SMOKE") != "1",
    reason="Set TENUO_OIDC_SMOKE=1; needs Node.js, npm ci in oidc-provider-fixture, and Chromium",
)
def test_rfc9068_provider_authorization_refresh_and_enforced_tools():
    python_root = Path(__file__).resolve().parents[2]
    subprocess.run(
        [sys.executable, str(python_root / "examples/oauth/oidc_smoke.py")],
        env={**os.environ, "PYTHONPATH": str(python_root)},
        check=True,
        timeout=180,
    )
