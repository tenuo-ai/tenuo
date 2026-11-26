"""Opt-in real identity-provider/browser/MCP interoperability test.

CI runs this explicitly. It is not silently replaced with generated JWTs.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("TENUO_KEYCLOAK_SMOKE") != "1",
    reason="Set TENUO_KEYCLOAK_SMOKE=1; needs Docker and Playwright Chromium",
)
def test_keycloak_authorization_code_to_enforced_refund():
    python_root = Path(__file__).resolve().parents[2]
    subprocess.run(
        [sys.executable, str(python_root / "examples/oauth/smoke.py")],
        env={**os.environ, "PYTHONPATH": str(python_root)},
        check=True,
        timeout=600,
    )
