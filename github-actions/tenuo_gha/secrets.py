"""Load keys from the Secret mount. Never log the bytes."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable, Optional

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from tenuo import SigningKey

from .config import ConfigError
from .github import SignAppJwt

_PEM_MARKERS = (b"BEGIN ", b"PRIVATE KEY")
_KEY_SUFFIXES = (".pem", ".key")


def resolve_secret_file(mount: Path, name: str) -> Path:
    """Return ``mount / name``. Refuse absolute paths and ``..``."""
    if not name or name != Path(name).name or Path(name).is_absolute():
        raise ConfigError(f"{name!r} must be a filename under the Secret mount")
    root = mount.expanduser().resolve()
    path = (root / name).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ConfigError(f"{name!r} is not under the Secret mount") from exc
    return path


def read_secret_file(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"could not read {path.name} from the Secret mount") from exc
    if not data.strip():
        raise ConfigError(f"{path.name} in the Secret mount is empty")
    return data


def load_signing_key(data: bytes) -> SigningKey:
    """Ed25519 issuer or receipt key. PEM, hex, base64, or raw 32 bytes."""
    text = data.strip()
    if b"BEGIN " in text:
        try:
            return SigningKey.from_pem(text.decode("utf-8"))
        except Exception as exc:
            raise ConfigError("Secret mount key is not a usable Ed25519 PEM") from exc
    try:
        raw = text.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        raw = ""
    try:
        return SigningKey.from_bytes(bytes.fromhex(raw))
    except Exception:
        pass
    try:
        import base64

        return SigningKey.from_bytes(base64.b64decode(raw))
    except Exception:
        pass
    if len(text) == 32:
        return SigningKey.from_bytes(text)
    raise ConfigError("Secret mount key is not a usable Ed25519 key")


def load_github_app_pem(data: bytes) -> bytes:
    """Validate an RSA App PEM and return the original bytes for JWT signing."""
    try:
        load_pem_private_key(data, password=None)
    except Exception as exc:
        raise ConfigError("github_app_key is not a usable RSA PEM") from exc
    return data


def sign_github_app_jwt(pem: bytes, app_id: str, *, now: Optional[int] = None) -> str:
    """RS256 App JWT. ``iat`` is 60s in the past; ``exp`` is 10 minutes after ``iat``."""
    issued = int(now if now is not None else time.time()) - 60
    try:
        return jwt.encode(
            {"iat": issued, "exp": issued + 600, "iss": app_id},
            pem,
            algorithm="RS256",
        )
    except Exception as exc:
        raise ConfigError("could not sign a GitHub App JWT") from exc


def signing_key_from_mount(mount: Path, name: str) -> SigningKey:
    return load_signing_key(read_secret_file(resolve_secret_file(mount, name)))


def app_jwt_signer_from_mount(mount: Path, name: str) -> SignAppJwt:
    return app_jwt_signer(read_secret_file(resolve_secret_file(mount, name)))


def app_jwt_signer(pem: bytes) -> SignAppJwt:
    material = load_github_app_pem(pem)

    def sign(app_id: str) -> str:
        return sign_github_app_jwt(material, app_id)

    sign(app_id="1")
    return sign


def _looks_like_private_key(path: Path) -> bool:
    if path.suffix.lower() in _KEY_SUFFIXES:
        try:
            sample = path.read_bytes()[:256]
        except OSError:
            return False
        return any(marker in sample for marker in _PEM_MARKERS)
    try:
        sample = path.read_bytes()[:256]
    except OSError:
        return False
    return any(marker in sample for marker in _PEM_MARKERS)


def assert_no_keys_outside_mount(mount: Path, scan_roots: Iterable[Path]) -> None:
    """A private key file next to the config (or otherwise outside the mount) is a startup error."""
    root = mount.expanduser().resolve()
    seen: set[Path] = set()
    for raw in scan_roots:
        directory = Path(raw).expanduser().resolve()
        if directory in seen or not directory.is_dir():
            continue
        seen.add(directory)
        if directory == root or root in directory.parents:
            continue
        try:
            children = list(directory.iterdir())
        except OSError:
            continue
        for path in children:
            if not path.is_file():
                continue
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved == root or root in resolved.parents:
                continue
            if _looks_like_private_key(path):
                raise ConfigError(
                    f"{path.name} is a private key outside the Secret mount"
                )
