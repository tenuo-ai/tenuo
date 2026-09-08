"""Holder identity backed by ``SigningKey``.

The public key is always derived from the secret. Persistence is optional
and path-owned: this module does not choose a default file or read env vars.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional, Union

from tenuo_core import PublicKey, SigningKey

from .exceptions import ConfigurationError

__all__ = ["HolderIdentity"]

_PathLike = Union[str, Path]


class HolderIdentity:
    """Ed25519 holder keypair. The secret never appears in ``repr`` or ``str``."""

    __slots__ = ("_key", "_path")

    def __init__(self, key: Union[SigningKey, bytes, bytearray]) -> None:
        if isinstance(key, (bytes, bytearray)):
            if len(key) != 32:
                raise ConfigurationError(
                    "HolderIdentity requires a 32-byte Ed25519 secret or a SigningKey"
                )
            self._key = SigningKey.from_bytes(bytes(key))
        elif isinstance(key, SigningKey):
            self._key = key
        else:
            raise ConfigurationError(
                "HolderIdentity requires a SigningKey or 32-byte secret"
            )
        self._path: Optional[Path] = None

    @classmethod
    def generate(cls) -> "HolderIdentity":
        """Fresh holder identity. Does not touch the filesystem."""
        return cls(SigningKey.generate())

    @classmethod
    def from_signing_key(cls, key: SigningKey) -> "HolderIdentity":
        return cls(key)

    @classmethod
    def from_bytes(cls, secret: bytes) -> "HolderIdentity":
        return cls(secret)

    @classmethod
    def load_or_create(cls, path: _PathLike) -> "HolderIdentity":
        """Load a hex secret from ``path``, or generate and persist one.

        The file is hex-encoded secret-key bytes plus a trailing newline.
        Creation is exclusive (``O_CREAT|O_EXCL``) with mode ``0600`` so a
        concurrent caller loads the winner instead of overwriting it. A
        corrupt existing file is an error; it is never overwritten.
        """
        dest = Path(path)
        last_error: Optional[Exception] = None
        for _ in range(32):
            try:
                return cls._load_existing(dest)
            except FileNotFoundError:
                pass
            except ConfigurationError as exc:
                last_error = exc
                if dest.exists() and dest.stat().st_size == 0:
                    time.sleep(0.005)
                    continue
                raise
            identity = cls.generate()
            try:
                _create_exclusive(dest, identity._key)
            except FileExistsError:
                time.sleep(0.005)
                continue
            identity._path = dest
            return identity
        if last_error is not None:
            raise last_error
        return cls._load_existing(dest)

    @classmethod
    def _load_existing(cls, dest: Path) -> "HolderIdentity":
        contents = dest.read_text(encoding="ascii")
        if not contents.strip():
            raise FileNotFoundError(dest)
        identity = cls._from_hex_file(dest, contents)
        identity._path = dest
        _set_owner_only(dest)
        return identity

    @staticmethod
    def _from_hex_file(path: Path, contents: str) -> "HolderIdentity":
        trimmed = contents.strip()
        try:
            raw = bytes.fromhex(trimmed)
        except ValueError as exc:
            raise ConfigurationError(
                f"holder identity at {path} is not hex-encoded"
            ) from exc
        if len(raw) != 32:
            raise ConfigurationError(
                f"holder identity at {path} must be 32 bytes, got {len(raw)}"
            )
        return HolderIdentity(raw)

    @property
    def public_key(self) -> PublicKey:
        return self._key.public_key

    @property
    def signing_key(self) -> SigningKey:
        return self._key

    @property
    def path(self) -> Optional[Path]:
        return self._path

    def __repr__(self) -> str:
        pk = bytes(self.public_key.to_bytes())
        return f"HolderIdentity(public_key={pk[:4].hex()}…)"

    def __str__(self) -> str:
        return self.__repr__()

    def __getstate__(self) -> Any:
        raise TypeError("HolderIdentity cannot be pickled")

    def __setstate__(self, state: Any) -> None:
        raise TypeError("HolderIdentity cannot be pickled")


def _create_exclusive(path: Path, key: SigningKey) -> None:
    parent = path.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    secret = bytes(key.secret_key_bytes()).hex() + "\n"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(str(path), flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        view = memoryview(secret.encode("ascii"))
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(fd)


def _set_owner_only(path: Path) -> None:
    if os.name != "posix":
        return
    os.chmod(path, 0o600)
