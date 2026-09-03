"""Install the packaged action into a pristine venv with no repository PYTHONPATH."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ACTION_ROOT = Path(__file__).resolve().parents[1]


def _vendor_wheels() -> list[Path]:
    return sorted((ACTION_ROOT / "vendor").glob("tenuo-*.whl"))


def _copy_assembled_action(tmp_path: Path, *, include_wheel: bool) -> Path:
    dest = tmp_path / "action"
    dest.mkdir()
    for name in ("requirements.lock", "install-runtime.mjs", "index.mjs", "cleanup.mjs", "action.yml"):
        shutil.copy2(ACTION_ROOT / name, dest / name)
    shutil.copytree(ACTION_ROOT / "tenuo_gha", dest / "tenuo_gha")
    vendor = dest / "vendor"
    vendor.mkdir()
    if include_wheel:
        wheels = _vendor_wheels()
        if not wheels:
            pytest.skip("action is not packaged; run github-actions/package_runtime.py after maturin build")
        for wheel in wheels:
            shutil.copy2(wheel, vendor / wheel.name)
    return dest


def _venv_python(tmp_path: Path) -> Path:
    dest = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(dest)], check=True)
    return dest / "bin" / "python"


def _pristine_env(python: Path, action: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "TENUO_WHEEL"}
    }
    env["TENUO_PYTHON"] = str(python)
    env["GITHUB_ACTION_PATH"] = str(action)
    env["PYTHONPATH"] = ""
    return env


def _import_tenuo(python: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(python), "-c", "import tenuo"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": ""},
        cwd=str(Path(python).parent),
    )


def test_clean_runner_installs_tenuo_from_packaged_vendor(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to invoke the GitHub Action entrypoint")
    if sys.platform != "linux":
        pytest.skip("clean-runner packaging is asserted on Ubuntu")
    if not _vendor_wheels():
        pytest.skip("action is not packaged; run github-actions/package_runtime.py after maturin build")
    python = _venv_python(tmp_path)
    assert _import_tenuo(python).returncode != 0
    action = _copy_assembled_action(tmp_path, include_wheel=True)
    invoked = subprocess.run(
        [node, str(action / "install-runtime.mjs")],
        cwd=str(action),
        env=_pristine_env(python, action),
        capture_output=True,
        text=True,
    )
    assert invoked.returncode == 0, invoked.stdout + invoked.stderr
    imported = _import_tenuo(python)
    assert imported.returncode == 0, imported.stderr
    assert "github-actions" not in (imported.stdout + imported.stderr)


def test_clean_runner_refuses_to_start_without_tenuo_wheel(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required to invoke the GitHub Action entrypoint")
    python = _venv_python(tmp_path)
    action = _copy_assembled_action(tmp_path, include_wheel=False)
    invoked = subprocess.run(
        [node, str(action / "install-runtime.mjs")],
        cwd=str(action),
        env=_pristine_env(python, action),
        capture_output=True,
        text=True,
    )
    assert invoked.returncode != 0
    assert "Tenuo runtime wheel is missing" in invoked.stderr
    assert _import_tenuo(python).returncode != 0
