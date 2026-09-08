"""Holder identity backed by ``SigningKey``.

The public key is always derived from the secret. Persistence is optional
and path-owned: this module does not choose a default file or read env vars.
"""

from __future__ import annotations

import os
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
        The write is ``*.tmp`` then rename. On Unix the file is ``0600``.
        A corrupt existing file is an error; it is never overwritten.
        """
        dest = Path(path)
        if dest.exists():
            contents = dest.read_text(encoding="ascii")
            identity = cls._from_hex_file(dest, contents)
            identity._path = dest
            _set_owner_only(dest)
            return identity

        identity = cls.generate()
        _persist_key(dest, identity._key)
        identity._path = dest
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


def _persist_key(path: Path, key: SigningKey) -> None:
    parent = path.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    secret = bytes(key.secret_key_bytes()).hex()
    try:
        tmp.write_text(secret + "\n", encoding="ascii")
        _set_owner_only(tmp)
        os.replace(tmp, path)
        _set_owner_only(path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _set_owner_only(path: Path) -> None:
    if os.name != "posix":
        return
    os.chmod(path, 0o600)
