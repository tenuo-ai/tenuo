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
    # A server that accepts but never answers keeps registration in flight.
    # Synchronize on accept so this exercises the timeout path rather than
    # relying on scheduler timing to infer that registration has started.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    accepted = threading.Event()
    release_server = threading.Event()

    def hold_connection():
        conn, _ = server.accept()
        accepted.set()
        release_server.wait(timeout=5)
        conn.close()

    server_thread = threading.Thread(target=hold_connection, daemon=True)
    server_thread.start()
    try:
        client = _client("shutdown-gil", url=f"http://127.0.0.1:{port}")
        assert accepted.wait(timeout=5), "registration never connected"

        # The marker needs the GIL to read the clock. If shutdown held the GIL,
        # it would run only as shutdown returns (the GIL can switch before the
        # caller reads `end`), so require it well inside the wait.
        ran_at = []

        def mark_progress():
            time.sleep(0.05)
            ran_at.append(time.monotonic())

        marker = threading.Thread(target=mark_progress)
        marker.start()
        start = time.monotonic()
        client.shutdown(timeout_secs=1)
        end = time.monotonic()
        marker.join(timeout=1)

        assert end - start >= 0.5, "shutdown did not exercise the in-flight timeout path"
        assert ran_at, "marker thread never ran"
        assert ran_at[0] - start < (end - start) / 2, (
            "another Python thread could not run during shutdown"
        )
    finally:
        release_server.set()
        server.close()
        server_thread.join(timeout=1)


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


def _deny(client: ControlPlaneClient) -> None:
    client._inner.emit_deny("w", "t", "denied", None, 1, None, None, 0, "r", None)


def test_status_reports_outage_without_io():
    client = _client("status-outage")
    try:
        status = client.status
        assert set(status) == {"state", "last_error", "buffered", "flushed", "dropped"}
        assert status["state"] == "registering"
        for _ in range(3):
            _deny(client)
        deadline = time.monotonic() + 5
        while client.status["buffered"] < 3 or client.status["last_error"] is None:
            assert time.monotonic() < deadline, client.status
            time.sleep(0.05)
        assert client.status["dropped"] == 0
    finally:
        client.shutdown(timeout_secs=5)
    # Never registered, so buffered events could not be sent.
    assert client.status["state"] == "stopped"
    assert client.status["dropped"] == 3


def test_events_after_shutdown_are_counted_as_dropped():
    client = _client("status-after-shutdown")
    client.shutdown(timeout_secs=5)
    before = client.status["dropped"]
    _deny(client)
    assert client.status["dropped"] == before + 1


def test_unreachable_control_plane_warns_once():
    script = textwrap.dedent(
        """
        import time
        from tenuo.control_plane import connect
        connect(url="http://127.0.0.1:1", api_key="k", authorizer_name="warn-once")
        time.sleep(4)  # long enough for several registration retries
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr.count("cannot reach control plane") == 1, proc.stderr
    assert "registration attempt" not in proc.stderr


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
