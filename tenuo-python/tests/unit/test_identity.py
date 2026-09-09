"""HolderIdentity: derivation, persistence, redaction."""

from __future__ import annotations

import multiprocessing
import os
import pickle
import stat
import threading
import time
from pathlib import Path

import pytest
from tenuo_core import SigningKey

from tenuo import HolderIdentity
from tenuo.exceptions import ConfigurationError


def test_generate_and_from_signing_key_derive_public_key():
    generated = HolderIdentity.generate()
    imported = HolderIdentity(generated.signing_key)
    assert generated.public_key == imported.public_key
    assert generated.public_key == generated.signing_key.public_key


def test_from_bytes_matches_signing_key():
    key = SigningKey.generate()
    identity = HolderIdentity.from_bytes(bytes(key.secret_key_bytes()))
    assert identity.public_key == key.public_key


def test_rejects_wrong_length_secret():
    with pytest.raises(ConfigurationError, match="32-byte"):
        HolderIdentity(b"\x00" * 16)


def test_repr_and_str_never_include_secret():
    key = SigningKey.generate()
    secret_hex = bytes(key.secret_key_bytes()).hex()
    identity = HolderIdentity(key)
    for rendered in (repr(identity), str(identity)):
        assert secret_hex not in rendered
        assert "HolderIdentity" in rendered
    with pytest.raises(TypeError):
        pickle.dumps(identity)


def test_load_or_create_reuses_same_key_and_sets_permissions(tmp_path):
    path = tmp_path / "nested" / "agent" / "holder.key"
    first = HolderIdentity.load_or_create(path)
    second = HolderIdentity.load_or_create(path)
    assert first.public_key == second.public_key
    assert path.exists()
    assert first.path == path
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600


def test_load_or_create_rejects_corrupt_file(tmp_path):
    path = tmp_path / "holder.key"
    path.write_text("not-hex\n", encoding="ascii")
    with pytest.raises(ConfigurationError, match="hex"):
        HolderIdentity.load_or_create(path)
    assert path.read_text(encoding="ascii") == "not-hex\n"


def test_load_or_create_rejects_wrong_length(tmp_path):
    path = tmp_path / "holder.key"
    path.write_text("aa\n", encoding="ascii")
    with pytest.raises(ConfigurationError, match="32 bytes"):
        HolderIdentity.load_or_create(path)


def test_load_or_create_rejects_empty_file(tmp_path):
    path = tmp_path / "holder.key"
    path.write_text("\n", encoding="ascii")
    with pytest.raises(ConfigurationError, match="empty"):
        HolderIdentity.load_or_create(path)


def test_load_or_create_race_returns_persisted_winner(tmp_path):
    path = tmp_path / "holder.key"
    results = []
    errors = []

    def worker():
        try:
            results.append(HolderIdentity.load_or_create(path).public_key)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(results) == 16
    persisted = HolderIdentity.load_or_create(path)
    assert all(key == persisted.public_key for key in results)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def _mp_load_or_create(path_str: str, queue: multiprocessing.Queue) -> None:
    from tenuo import HolderIdentity

    try:
        identity = HolderIdentity.load_or_create(path_str)
        queue.put(("ok", bytes(identity.public_key.to_bytes()).hex()))
    except Exception as exc:  # noqa: BLE001
        queue.put(("err", type(exc).__name__, str(exc)))


def _mp_paused_create(path_str: str, signal_path: str, queue: multiprocessing.Queue) -> None:
    os.environ["TENUO_IDENTITY_TEST_PAUSE_BEFORE_CLAIM"] = "0.5"
    os.environ["TENUO_IDENTITY_TEST_PAUSE_SIGNAL"] = signal_path
    _mp_load_or_create(path_str, queue)


def _mp_watch_for_partial(path_str: str, started: multiprocessing.Event, queue: multiprocessing.Queue) -> None:
    started.wait(5)
    dest = Path(path_str)
    deadline = time.monotonic() + 0.4
    while time.monotonic() < deadline:
        if dest.exists():
            data = dest.read_bytes()
            queue.put(len(data.strip()))
            return
        time.sleep(0.01)
    queue.put(-1)


def test_multiprocess_load_or_create_same_winner(tmp_path):
    path = tmp_path / "holder.key"
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    procs = [ctx.Process(target=_mp_load_or_create, args=(str(path), queue)) for _ in range(8)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(10)
        assert proc.exitcode == 0
    results = [queue.get_nowait() for _ in procs]
    assert all(item[0] == "ok" for item in results), results
    keys = {item[1] for item in results}
    assert len(keys) == 1
    persisted = HolderIdentity.load_or_create(path)
    assert bytes(persisted.public_key.to_bytes()).hex() == keys.pop()
    leftovers = list(path.parent.glob(path.name + ".tmp.*"))
    assert leftovers == []


def test_multiprocess_paused_writer_never_publishes_partial_key(tmp_path):
    path = tmp_path / "holder.key"
    signal = tmp_path / "pause-ready"
    ctx = multiprocessing.get_context("spawn")
    started = ctx.Event()
    paused_q = ctx.Queue()
    peer_q = ctx.Queue()
    watch_q = ctx.Queue()
    paused = ctx.Process(target=_mp_paused_create, args=(str(path), str(signal), paused_q))
    watcher = ctx.Process(target=_mp_watch_for_partial, args=(str(path), started, watch_q))
    peer = ctx.Process(target=_mp_load_or_create, args=(str(path), peer_q))
    paused.start()
    deadline = time.monotonic() + 5
    while not signal.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert signal.exists(), "paused writer never reached the pre-claim pause"
    assert not path.exists(), "destination appeared before the complete key was claimed"
    started.set()
    watcher.start()
    peer.start()
    for proc in (paused, peer, watcher):
        proc.join(10)
        assert proc.exitcode == 0
    observed = watch_q.get_nowait()
    assert observed == -1 or observed == 64, observed
    paused_result = paused_q.get_nowait()
    peer_result = peer_q.get_nowait()
    assert paused_result[0] == "ok", paused_result
    assert peer_result[0] == "ok", peer_result
    assert paused_result[1] == peer_result[1]
    leftovers = list(path.parent.glob(path.name + ".tmp.*"))
    assert leftovers == []
