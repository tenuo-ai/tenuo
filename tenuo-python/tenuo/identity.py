"""Holder identity backed by ``SigningKey``.

The public key is always derived from the secret. Persistence is optional
and path-owned: this module does not choose a default file or read env vars.
"""

from __future__ import annotations

import errno
import os
import secrets
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
        The complete key is written and fsynced to a unique ``0600`` temp
        file, then the destination is claimed atomically. A concurrent
        loser loads the winner. A corrupt existing file is an error; it
        is never overwritten.
        """
        dest = Path(path)
        for _ in range(32):
            try:
                return cls._load_existing(dest)
            except FileNotFoundError:
                pass
            identity = cls.generate()
            try:
                _persist_new(dest, identity._key)
            except FileExistsError:
                time.sleep(0.005)
                continue
            identity._path = dest
            return identity
        return cls._load_existing(dest)

    @classmethod
    def _load_existing(cls, dest: Path) -> "HolderIdentity":
        contents = dest.read_text(encoding="ascii")
        identity = cls._from_hex_file(dest, contents)
        identity._path = dest
        try:
            _set_owner_only(dest)
        except OSError as exc:
            if exc.errno not in (errno.EPERM, errno.EACCES):
                raise
        return identity

    @staticmethod
    def _from_hex_file(path: Path, contents: str) -> "HolderIdentity":
        trimmed = contents.strip()
        if not trimmed:
            raise ConfigurationError(f"holder identity at {path} is empty")
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


def _persist_new(dest: Path, key: SigningKey) -> None:
    parent = dest.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f"{dest.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
    _write_complete_0600(tmp, key)
    if not _claim_destination(tmp, dest):
        raise FileExistsError(dest)


def _write_complete_0600(path: Path, key: SigningKey) -> None:
    secret = bytearray((bytes(key.secret_key_bytes()).hex() + "\n").encode("ascii"))
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    # Owner-only holder key file (0600). Path is chosen by the caller, not from
    # unsanitized request input — CodeQL path-injection here is a false positive.
    fd = os.open(str(path), flags, 0o600)
    try:
        fchmod = getattr(os, "fchmod", None)
        if fchmod is not None:
            fchmod(fd, 0o600)
        view = memoryview(secret)
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
    finally:
        secret[:] = b"\x00" * len(secret)


def _claim_destination(tmp: Path, dest: Path) -> bool:
    """Atomically publish ``tmp`` as ``dest``. ``tmp`` is always removed."""
    remove_tmp = True
    try:
        os.link(os.fspath(tmp), os.fspath(dest))
        return True
    except FileExistsError:
        return False
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            return False
        if os.name != "nt":
            raise
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            claim_fd = os.open(os.fspath(dest), flags, 0o600)
            os.close(claim_fd)
        except FileExistsError:
            return False
        except OSError as claim_exc:
            if claim_exc.errno == errno.EEXIST or getattr(claim_exc, "winerror", None) == 183:
                return False
            raise
        try:
            os.replace(os.fspath(tmp), os.fspath(dest))
            remove_tmp = False
            return True
        except FileExistsError:
            return False
        except OSError as rename_exc:
            if rename_exc.errno == errno.EEXIST or getattr(rename_exc, "winerror", None) == 183:
                return False
            raise
    finally:
        if remove_tmp:
            try:
                tmp.unlink()
            except OSError:
                pass


def _set_owner_only(path: Path) -> None:
    if os.name != "posix":
        return
    os.chmod(path, 0o600)
