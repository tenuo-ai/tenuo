"""ControlPlaneClient.shutdown must not panic outside the Tokio runtime (#806)."""

import subprocess
import sys
import textwrap

from tenuo.control_plane import ControlPlaneClient


def _client(name: str) -> ControlPlaneClient:
    return ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name=name)


def test_shutdown_from_python_thread_does_not_panic():
    _client("shutdown-direct").shutdown(timeout_secs=0)


def test_shutdown_is_idempotent():
    client = _client("shutdown-twice")
    client.shutdown(timeout_secs=0)
    client.shutdown(timeout_secs=0)


def test_atexit_shutdown_prints_no_panic():
    script = textwrap.dedent(
        """
        from tenuo.control_plane import connect
        connect(url="http://127.0.0.1:1", api_key="k", authorizer_name="shutdown-atexit")
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert "panicked" not in proc.stderr
    assert "no reactor running" not in proc.stderr
