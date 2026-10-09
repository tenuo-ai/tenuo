"""ControlPlaneClient.shutdown stops the background task without panicking (#806)."""

import socket
import subprocess
import sys
import textwrap
import threading
import time

import pytest

tenuo_core = pytest.importorskip("tenuo_core")
if not hasattr(tenuo_core, "ControlPlaneClient"):
    pytest.skip("tenuo_core built without python-server", allow_module_level=True)

from tenuo.control_plane import ControlPlaneClient  # noqa: E402

# Nothing listens on port 1, so registration fails fast and retries.
UNREACHABLE = "http://127.0.0.1:1"


def _client(name: str, url: str = UNREACHABLE) -> ControlPlaneClient:
    return ControlPlaneClient(url=url, api_key="k", authorizer_name=name)


def test_shutdown_from_python_thread_does_not_panic():
    _client("shutdown-direct").shutdown(timeout_secs=0)


def test_shutdown_is_idempotent():
    client = _client("shutdown-twice")
    client.shutdown(timeout_secs=0)
    client.shutdown(timeout_secs=0)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -1.0])
def test_shutdown_accepts_any_float_timeout(timeout):
    _client("shutdown-odd-timeout").shutdown(timeout_secs=timeout)


def test_shutdown_stops_task_without_waiting_out_timeout():
    # Returning well before the timeout means the stop signal reached the
    # registration retry loop and the task was joined, not slept past.
    client = _client("shutdown-fast")
    start = time.monotonic()
    client.shutdown(timeout_secs=10)
    assert time.monotonic() - start < 3


def test_shutdown_releases_gil_while_waiting():
    # A server that accepts but never answers keeps registration in flight,
    # so shutdown waits out its timeout. Python threads must keep running.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    try:
        client = _client("shutdown-gil", url=f"http://127.0.0.1:{port}")
        time.sleep(0.2)  # let registration connect and block
        worker = threading.Thread(target=client.shutdown, kwargs={"timeout_secs": 1})
        worker.start()
        ticks = 0
        while worker.is_alive():
            ticks += 1
            time.sleep(0.01)
        worker.join()
        assert ticks >= 20, f"main thread only ran {ticks} times during shutdown"
    finally:
        server.close()


def test_dropped_client_does_not_warn_about_registration():
    script = textwrap.dedent(
        """
        import gc, time
        from tenuo.control_plane import ControlPlaneClient
        c = ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="dropped")
        del c
        gc.collect()
        time.sleep(0.5)
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert "control plane loop exited" not in proc.stderr


def test_atexit_shutdown_is_quiet_and_fast():
    script = textwrap.dedent(
        """
        from tenuo.control_plane import connect
        connect(url="http://127.0.0.1:1", api_key="k", authorizer_name="shutdown-atexit")
        """
    )
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, proc.stderr
    assert "panicked" not in proc.stderr
    assert "no reactor running" not in proc.stderr
    # Shutdown is not a crash; the "loop exited" warning is for real failures.
    assert "control plane loop exited" not in proc.stderr
    # The atexit hook waits up to 2s; with nothing to flush it should not.
    assert elapsed < 10, f"exit took {elapsed:.1f}s"
