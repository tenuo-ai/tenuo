"""The Node action must install Tenuo on a runner that does not already have it."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ACTION_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ACTION_ROOT.parent


def _tenuo_wheel() -> Path:
    wheels = sorted(REPO_ROOT.glob("tenuo-python/target/wheels/tenuo-*.whl"))
    if not wheels:
        pytest.skip("tenuo wheel is not built; run maturin build --release in tenuo-python")
    return wheels[-1]


def _stage_action(tmp_path: Path, *, wheel: Path | None) -> Path:
    dest = tmp_path / "action"
    dest.mkdir()
    for name in ("requirements.lock", "install-runtime.mjs", "index.mjs", "cleanup.mjs", "action.yml"):
        shutil.copy2(ACTION_ROOT / name, dest / name)
    shutil.copytree(ACTION_ROOT / "tenuo_gha", dest / "tenuo_gha")
    vendor = dest / "vendor"
    vendor.mkdir()
    if wheel is not None:
        shutil.copy2(wheel, vendor / wheel.name)
    return dest


def _venv_python(tmp_path: Path) -> Path:
    dest = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(dest)], check=True)
    return dest / "bin" / "python"


def _import_tenuo(python: Path, *, action_path: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(python), "-c", "import tenuo" + ("; import tenuo_gha" if action_path else "")],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": action_path},
    )


def test_clean_runner_action_installs_tenuo_runtime(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to invoke the GitHub Action entrypoint")
    python = _venv_python(tmp_path)
    assert _import_tenuo(python).returncode != 0
    action = _stage_action(tmp_path, wheel=_tenuo_wheel())
    env = {
        **os.environ,
        "TENUO_PYTHON": str(python),
        "GITHUB_ACTION_PATH": str(action),
        "GITHUB_RUN_ID": "clean-runner",
        "RUNNER_TEMP": str(tmp_path / "runner"),
        "INPUT_GATEWAY_URL": "http://127.0.0.1:9",
        "INPUT_EXCHANGE_URL": "http://127.0.0.1:9",
        "INPUT_AUDIENCE": "tenuo:org/acme",
        "INPUT_TTL": "900",
        "PYTHONPATH": "",
    }
    invoked = subprocess.run(
        [node, str(action / "index.mjs")],
        cwd=str(action),
        env=env,
        capture_output=True,
        text=True,
    )
    combined = invoked.stdout + invoked.stderr
    assert "No module named 'tenuo'" not in combined
    assert "No module named tenuo" not in combined
    imported = _import_tenuo(python, action_path=str(action))
    assert imported.returncode == 0, imported.stderr or combined
    assert invoked.returncode != 0


def test_clean_runner_refuses_to_start_without_tenuo_wheel(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to invoke the GitHub Action entrypoint")
    python = _venv_python(tmp_path)
    action = _stage_action(tmp_path, wheel=None)
    invoked = subprocess.run(
        [node, str(action / "install-runtime.mjs")],
        cwd=str(action),
        env={
            **os.environ,
            "TENUO_PYTHON": str(python),
            "GITHUB_ACTION_PATH": str(action),
            "PYTHONPATH": "",
        },
        capture_output=True,
        text=True,
    )
    assert invoked.returncode != 0
    assert "Tenuo runtime wheel is missing" in invoked.stderr
    assert _import_tenuo(python).returncode != 0
