"""
Test transparent PoP computation in the outbound workflow interceptor.

This test suite verifies that the TenuoInterceptor correctly computes PoP
inline during start_activity() calls, eliminating the need for queue machinery.

Key aspects tested:
1. Backward compatibility - sign() accepts both 3-arg and 4-arg forms
2. Parameter name resolution consistency between outbound/inbound
3. Transparent PoP injection for standard workflow.execute_activity()
4. Deterministic timestamp usage for Temporal replay safety
5. Fail-closed behavior when PoP computation fails

Design Decision: timestamp parameter is OPTIONAL
  - For Temporal: TenuoInterceptor always provides it (workflow.now())
  - For non-Temporal: None → wall-clock time (correct behavior)
  - Users should NEVER call warrant.sign() directly in Temporal workflows
  - The transparent interceptor architecture ensures correct usage
"""

import asyncio
import time
import base64
import os
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

# Temporal imports
try:
    from temporalio import activity, workflow
    from temporalio.client import Client
    from temporalio.common import RetryPolicy
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker
    TEMPORAL_AVAILABLE = True
except ImportError:
    TEMPORAL_AVAILABLE = False

# Tenuo imports
from tenuo import SigningKey, Warrant
from tenuo_core import Subpath
from tenuo.temporal import (
    TenuoInterceptor,
    TenuoInterceptorConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    tenuo_headers,
)


# =============================================================================
# Test sign() backward compatibility
# =============================================================================

def test_sign_backward_compatibility():
    """Verify sign() requires 4-arg form with mandatory timestamp."""
    key = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(key.public_key)
        .capability("test_tool", path=Subpath("/data"))
        .ttl(3600)
        .mint(key)
    )

    # Old 3-arg form should fail (timestamp is now mandatory)
    try:
        warrant.sign(key, "test_tool", {"path": "/data"})
        assert False, "Expected 3-arg form to fail, but it succeeded"
    except TypeError:
        pass  # Expected - timestamp is now mandatory

    # New 4-arg positional form (correct usage)
    now = int(time.time())
    sig_new = warrant.sign(key, "test_tool", {"path": "/data"}, now)
    assert len(sig_new) == 64, "PoP signature should be 64 bytes"

    # Keyword argument form with same timestamp
    sig_kw = warrant.sign(key, "test_tool", {"path": "/data"}, timestamp=now)
    assert len(sig_kw) == 64, "PoP signature should be 64 bytes"

    # Signatures with same timestamp should be identical
    assert sig_new == sig_kw, "Same timestamp should produce same signature"

    # Different timestamps should produce different signatures
    sig_diff = warrant.sign(key, "test_tool", {"path": "/data"}, timestamp=now + 100)
    assert sig_diff != sig_new, "Different timestamps should produce different signatures"


def test_sign_deterministic_timestamps():
    """Verify that deterministic timestamps produce consistent signatures."""
    key = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(key.public_key)
        .capability("test_tool", path=Subpath("/data"))
        .ttl(3600)
        .mint(key)
    )

    # Same timestamp should always produce the same signature
    ts = 1234567890
    sig1 = warrant.sign(key, "test_tool", {"path": "/data"}, timestamp=ts)
    sig2 = warrant.sign(key, "test_tool", {"path": "/data"}, timestamp=ts)
    assert sig1 == sig2, "Same timestamp must produce identical signatures (replay safety)"

    # Timestamps within the same 30-second window should produce same signature
    # (This is the POP_TIMESTAMP_WINDOW_SECS behavior)
    ts_window_start = 1234567890
    ts_window_end = ts_window_start + 29  # Still in same 30-sec window
    sig_start = warrant.sign(key, "test_tool", {"path": "/data"}, timestamp=ts_window_start)
    sig_end = warrant.sign(key, "test_tool", {"path": "/data"}, timestamp=ts_window_end)
    assert sig_start == sig_end, "Timestamps in same 30-sec window should match"


# =============================================================================
# Temporal integration tests (require embedded Temporal server)
# =============================================================================

if TEMPORAL_AVAILABLE:
    # Test activities
    @activity.defn
    async def read_file(path: str) -> str:
        """Test activity: read a file."""
        return Path(path).read_text()

    @activity.defn
    async def write_file(path: str, content: str) -> str:
        """Test activity: write a file."""
        Path(path).write_text(content)
        return f"Wrote {len(content)} bytes"

    @activity.defn
    async def list_files(path: str) -> list:
        """Test activity: list files in directory."""
        return [str(p) for p in Path(path).iterdir()]

    # Test workflow using standard Temporal API (no tenuo imports!)
    @workflow.defn
    class TransparentWorkflow:
        """Test workflow using standard workflow.execute_activity()."""

        @workflow.run
        async def run(self, test_dir: str) -> str:
            files = await workflow.execute_activity(
                list_files,
                args=[test_dir],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )

            content = await workflow.execute_activity(
                read_file,
                args=[files[0]],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )

            return f"Read {len(content)} chars from {len(files)} files"

    @workflow.defn
    class ParallelWorkflow:
        """Test parallel activities via asyncio.gather."""

        @workflow.run
        async def run(self, test_dir: str) -> str:
            contents = await asyncio.gather(
                workflow.execute_activity(
                    read_file,
                    args=[f"{test_dir}/file1.txt"],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                ),
                workflow.execute_activity(
                    read_file,
                    args=[f"{test_dir}/file2.txt"],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                ),
                workflow.execute_activity(
                    read_file,
                    args=[f"{test_dir}/file3.txt"],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                ),
            )
            return f"Read {len(contents)} files in parallel"

    @pytest.mark.asyncio
    @pytest.mark.temporal_live
    @pytest.mark.skipif(not TEMPORAL_AVAILABLE, reason="Temporal not installed")
    async def test_transparent_interceptor_basic():
        """Test transparent PoP computation with standard Temporal API."""
        test_dir = Path("/tmp/tenuo-test-transparent")
        test_dir.mkdir(exist_ok=True)
        (test_dir / "test.txt").write_text("Test content")

        try:
            async with await WorkflowEnvironment.start_local() as env:
                client_interceptor = TenuoClientInterceptor()
                client = await Client.connect(
                    env.client.service_client.config.target_host,
                    interceptors=[client_interceptor],
                )

                control_key = SigningKey.generate()
                agent_key = SigningKey.generate()

                os.environ["TENUO_KEY_agent1"] = base64.b64encode(
                    agent_key.secret_key_bytes()
                ).decode()

                warrant = (
                    Warrant.mint_builder()
                    .holder(agent_key.public_key)
                    .capability("read_file", path=Subpath(str(test_dir)))
                    .capability("list_files", path=Subpath(str(test_dir)))
                    .ttl(3600)
                    .mint(control_key)
                )

                task_queue = f"test-transparent-{uuid.uuid4().hex[:8]}"

                activities = [read_file, write_file, list_files]
                worker_interceptor = TenuoInterceptor(
                    TenuoInterceptorConfig(
                        key_resolver=EnvKeyResolver(),
                        on_denial="raise",
                        trusted_roots=[control_key.public_key],
                        activity_fns=activities,
                    )
                )

                from temporalio.worker.workflow_sandbox import (
                    SandboxedWorkflowRunner,
                    SandboxRestrictions,
                )
                sandbox_runner = SandboxedWorkflowRunner(
                    restrictions=SandboxRestrictions.default.with_passthrough_modules(
                        "tenuo", "tenuo_core",
                    )
                )

                async with Worker(
                    client,
                    task_queue=task_queue,
                    workflows=[TransparentWorkflow],
                    activities=activities,
                    interceptors=[worker_interceptor],
                    workflow_runner=sandbox_runner,
                ):
                    client_interceptor.set_headers(
                        tenuo_headers(warrant, "agent1", agent_key)
                    )

                    result = await client.execute_workflow(
                        TransparentWorkflow.run,
                        args=[str(test_dir)],
                        id=f"test-{uuid.uuid4().hex[:8]}",
                        task_queue=task_queue,
                    )

                    assert "Read" in result
                    assert "chars" in result

        finally:
            if test_dir.exists():
                for f in test_dir.iterdir():
                    f.unlink()
                test_dir.rmdir()

    @pytest.mark.asyncio
    @pytest.mark.temporal_live
    @pytest.mark.skipif(not TEMPORAL_AVAILABLE, reason="Temporal not installed")
    async def test_transparent_interceptor_parallel():
        """Test parallel activities each get their own PoP signature."""
        test_dir = Path("/tmp/tenuo-test-parallel")
        test_dir.mkdir(exist_ok=True)
        (test_dir / "file1.txt").write_text("Content 1")
        (test_dir / "file2.txt").write_text("Content 2")
        (test_dir / "file3.txt").write_text("Content 3")

        try:
            async with await WorkflowEnvironment.start_local() as env:
                client_interceptor = TenuoClientInterceptor()
                client = await Client.connect(
                    env.client.service_client.config.target_host,
                    interceptors=[client_interceptor],
                )

                control_key = SigningKey.generate()
                agent_key = SigningKey.generate()

                os.environ["TENUO_KEY_agent1"] = base64.b64encode(
                    agent_key.secret_key_bytes()
                ).decode()

                warrant = (
                    Warrant.mint_builder()
                    .holder(agent_key.public_key)
                    .capability("read_file", path=Subpath(str(test_dir)))
                    .ttl(3600)
                    .mint(control_key)
                )

                task_queue = f"test-parallel-{uuid.uuid4().hex[:8]}"

                parallel_activities = [read_file]
                worker_interceptor = TenuoInterceptor(
                    TenuoInterceptorConfig(
                        key_resolver=EnvKeyResolver(),
                        on_denial="raise",
                        trusted_roots=[control_key.public_key],
                        activity_fns=parallel_activities,
                    )
                )

                from temporalio.worker.workflow_sandbox import (
                    SandboxedWorkflowRunner,
                    SandboxRestrictions,
                )
                sandbox_runner = SandboxedWorkflowRunner(
                    restrictions=SandboxRestrictions.default.with_passthrough_modules(
                        "tenuo", "tenuo_core",
                    )
                )

                async with Worker(
                    client,
                    task_queue=task_queue,
                    workflows=[ParallelWorkflow],
                    activities=[read_file],
                    interceptors=[worker_interceptor],
                    workflow_runner=sandbox_runner,
                ):
                    client_interceptor.set_headers(
                        tenuo_headers(warrant, "agent1", agent_key)
                    )

                    result = await client.execute_workflow(
                        ParallelWorkflow.run,
                        args=[str(test_dir)],
                        id=f"test-parallel-{uuid.uuid4().hex[:8]}",
                        task_queue=task_queue,
                    )

                    assert "3 files" in result

        finally:
            if test_dir.exists():
                for f in test_dir.iterdir():
                    f.unlink()
                test_dir.rmdir()


# =============================================================================
# Parameter name resolution tests
# =============================================================================

def test_parameter_name_resolution_consistency():
    """Verify outbound and inbound interceptors use same arg resolution strategy."""
    from tenuo.temporal import TenuoActivityInboundInterceptor, _TenuoWorkflowOutboundInterceptor
    import inspect

    outbound_source = inspect.getsource(_TenuoWorkflowOutboundInterceptor.start_activity)
    inbound_source = inspect.getsource(TenuoActivityInboundInterceptor._extract_arguments)

    assert "inspect.signature" in outbound_source, "Outbound should use inspect.signature"
    assert "inspect.signature" in inbound_source, "Inbound should use inspect.signature"

    assert "arg{i}" in outbound_source or 'f"arg{i}"' in outbound_source
    assert "arg{i}" in inbound_source or 'f"arg{i}"' in inbound_source

    assert "activity_fn" in outbound_source
    assert "activity_fn" in inbound_source


def test_fail_closed_warning():
    """Verify that PoP computation failures log at WARNING level."""
    from tenuo.temporal import _TenuoWorkflowOutboundInterceptor
    import inspect

    source = inspect.getsource(_TenuoWorkflowOutboundInterceptor.start_activity)

    assert "logger.warning" in source, "Should log PoP failures at WARNING level"
    assert "except Exception" in source, "Should catch exceptions"
