"""
Smoke-test Temporal example scripts against an in-process Temporal server.

The scripts under ``examples/temporal/`` assume ``temporal server start-dev`` on
``localhost:7233``.  CI and contributors without a local server would not catch
breakage from SDK refactors.  These tests load each example module and run
``main()`` while redirecting ``Client.connect`` to
:class:`temporalio.testing.WorkflowEnvironment` — the same pattern as
``test_temporal_live.py``, but executing the published example code paths.

MCP layering examples are optional: they require the MCP SDK and spawn an MCP
subprocess; see ``test_temporal_mcp_examples_smoke``.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

pytest.importorskip("temporalio")

from temporalio.client import Client as TemporalClient  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402

EXAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "temporal"

# Examples that use only the Temporal SDK + Tenuo (no MCP subprocess).
CORE_TEMPORAL_SCRIPTS = ("demo.py", "delegation.py", "multi_warrant.py")

MCP_LAYERING_SCRIPTS = ("temporal_mcp_layering.py", "cloud_iam_layering.py")


def _load_example_module(script_name: str):
    """Import ``examples/temporal/<stem>.py`` as a real package module.

    Dynamic ``spec_from_file_location`` names do not survive Temporal's workflow
    sandbox importer (see ``workflow_sandbox._importer``).  Package imports resolve
    the same as ``python -m`` / pytest from ``tenuo-python/``.
    """
    path = EXAMPLES_DIR / script_name
    if not path.is_file():
        pytest.fail(f"missing example script: {path}")
    stem = path.stem
    return importlib.import_module(f"examples.temporal.{stem}")


def _patch_example_client_connect(
    mod: object,
    monkeypatch: pytest.MonkeyPatch,
    target_host: str,
) -> None:
    """Redirect ``mod.Client.connect(address, ...)`` to the test server's host.

    ``Client.connect`` is a classmethod; the bound method only accepts
    ``target_host`` plus keyword args — do not pass ``cls`` through to the real
    implementation.
    """
    real_connect = TemporalClient.connect

    async def _redirect_connect(_cls, _address: str, **kwargs):  # type: ignore[no-untyped-def]
        return await real_connect(target_host, **kwargs)

    monkeypatch.setattr(mod.Client, "connect", classmethod(_redirect_connect))


@pytest.mark.temporal_live
@pytest.mark.asyncio
@pytest.mark.parametrize("script", CORE_TEMPORAL_SCRIPTS)
async def test_core_temporal_example_main_runs(script: str, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load_example_module(script)

    async with await WorkflowEnvironment.start_local() as env:
        target_host = env.client.service_client.config.target_host
        _patch_example_client_connect(mod, monkeypatch, target_host)

        await mod.main()


@pytest.mark.temporal_live
@pytest.mark.asyncio
@pytest.mark.parametrize("script", MCP_LAYERING_SCRIPTS)
async def test_temporal_mcp_examples_smoke(script: str, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("mcp")

    mod = _load_example_module(script)
    if not getattr(mod, "MCP_AVAILABLE", False):
        pytest.skip("tenuo MCP extras not available (install mcp / tenuo[mcp])")

    monkeypatch.setenv("TENUO_DEMO_DRY_RUN", "1")

    async with await WorkflowEnvironment.start_local() as env:
        target_host = env.client.service_client.config.target_host
        _patch_example_client_connect(mod, monkeypatch, target_host)

        await mod.main()
