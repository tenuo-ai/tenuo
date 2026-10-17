"""Shared local artifacts. Cryptographic operations remain in the SDK.

Key and SRL helpers follow the existing Temporal local workflow. New writers
publish atomically; SRL readers also accept its legacy base64 encoding.
"""

from __future__ import annotations

import base64
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

import yaml

MAX_BYTES = 4 * 1024 * 1024


class DocumentError(ValueError):
    """A local document cannot be interpreted safely."""


class Refused(DocumentError):
    """An explicit operation was refused without changing authority."""

    exit_code = 4


class StrictLoader(yaml.SafeLoader):
    # Keep unquoted ISO timestamps as strings, as required by the file schema.
    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in rules if tag != "tag:yaml.org,2002:timestamp"]
        for key, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def compose_node(self, parent, index):
        event = self.peek_event()
        if self.check_event(yaml.AliasEvent) or getattr(event, "anchor", None):
            raise DocumentError("YAML anchors and aliases are not supported")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or not key.strip():
                raise DocumentError("mapping keys must be nonempty strings")
            if key in result:
                raise DocumentError(f"duplicate field: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def read_bytes(path):
    with Path(path).expanduser().open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise DocumentError(f"{path}: file exceeds 4 MiB")
    return raw


def load_yaml(path):
    try:
        data = yaml.load(read_bytes(path), Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise DocumentError(f"{path}: invalid YAML") from exc
    if not isinstance(data, dict):
        raise DocumentError(f"{path}: expected a YAML mapping")
    return data


def fields(data, allowed, required=(), where="document"):
    if not isinstance(data, dict):
        raise DocumentError(f"{where}: expected a mapping")
    if any(not isinstance(key, str) or not key.strip() for key in data):
        raise DocumentError(f"{where}: keys must be nonempty strings")
    extra, missing = set(data) - set(allowed), set(required) - set(data)
    if extra:
        raise DocumentError(f"{where}: unknown fields: {', '.join(sorted(extra))}")
    if missing:
        raise DocumentError(f"{where}: missing fields: {', '.join(sorted(missing))}")


def publish(path, data, *, replace=False):
    """Publish complete bytes with mode 0600; never clobber by default."""
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            if path.is_symlink():
                raise DocumentError(f"{path}: refusing to replace a symlink")
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_yaml(path, data, *, replace=False):
    publish(path, yaml.safe_dump(data, sort_keys=False).encode(), replace=replace)


def name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise DocumentError("name must contain letters, numbers, dots, underscores or hyphens")
    return value


def fingerprint(key):
    return bytes(key.to_bytes()).hex()[:16]


def keygen(base):
    from tenuo import SigningKey

    base = Path(base)
    private, public = base.with_name(base.name + ".key"), base.with_name(base.name + ".pub")
    if private.exists() or public.exists() or private.is_symlink() or public.is_symlink():
        raise FileExistsError(f"{base}: key already exists; not overwriting")
    key = SigningKey.generate()
    publish(private, base64.b64encode(bytes(key.secret_key_bytes())) + b"\n")
    publish(public, base64.b64encode(bytes(key.public_key.to_bytes())) + b"\n")
    return private, public, key.public_key


def load_signing_key(path):
    from tenuo import SigningKey
    from tenuo.keys import load_signing_key_from_file

    resolved = Path(path).expanduser().resolve(strict=True)
    if resolved.suffix.lower() == ".pub":
        raise DocumentError("signing key input points to a public .pub file; use its private .key file")
    raw = read_bytes(resolved)
    if raw.startswith(b"-----BEGIN PUBLIC KEY-----"):
        raise DocumentError("public-key PEM cannot be used as signing key input")
    if raw.startswith(b"-----BEGIN"):
        return SigningKey.from_pem(raw.decode())
    return load_signing_key_from_file(str(resolved))


def load_public_key(path):
    from tenuo import PublicKey

    resolved = Path(path).expanduser().resolve(strict=True)
    if resolved.suffix.lower() == ".key":
        raise DocumentError("public key input points to a private .key file; use its .pub file")
    text = read_bytes(resolved).decode().strip()
    if text and "PRIVATE KEY" in text.splitlines()[0]:
        raise DocumentError("private-key PEM cannot be used as public key input")
    if resolved.suffix.lower() != ".pub" and not text.startswith("-----BEGIN PUBLIC KEY-----"):
        raise DocumentError("untagged public keys must use a .pub filename; public-key PEM is also supported")
    for decode in (
        lambda: PublicKey.from_bytes(base64.b64decode(text, validate=True)),
        lambda: PublicKey.from_bytes(bytes.fromhex(text)),
        lambda: PublicKey.from_pem(text),
    ):
        try:
            return decode()
        except Exception:
            continue
    raise DocumentError(f"{path}: expected a public key in base64, hex or PEM")


def check_public_material(signing_key, public_keys):
    """Do not serialize the signer's secret through a mislabeled public field."""
    import hmac

    secret = bytes(signing_key.secret_key_bytes())
    if any(hmac.compare_digest(secret, bytes(public.to_bytes())) for public in public_keys):
        raise DocumentError("public warrant fields contain private signing material; use the corresponding public key")


def read_revocation_list(path):
    from tenuo import SignedRevocationList

    raw = read_bytes(path)
    try:
        return SignedRevocationList.from_bytes(raw)
    except Exception:
        try:
            return SignedRevocationList.from_bytes(base64.b64decode(raw.strip(), validate=True))
        except Exception:
            raise DocumentError(f"{path}: invalid signed revocation list") from None


@contextmanager
def operator_lock(directory):
    """Serialize read/modify/publish operations by concurrent tenuo-cli processes."""
    if os.name != "posix":
        raise DocumentError("local workspace updates currently require macOS or Linux")
    import fcntl

    directory = Path(directory)
    fd = os.open(directory / ".controller.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def update_revocations(path, issuer, ids=(), *, create=False, trusted_roots=None):
    from tenuo import SrlBuilder

    path = Path(path)
    with operator_lock(path.parent):
        if create:
            if path.exists():
                raise FileExistsError(f"{path}: list already exists")
            builder = SrlBuilder().version(1)
        else:
            previous = read_revocation_list(path)
            if trusted_roots is None:
                previous.verify(issuer.public_key)
            else:
                from tenuo import Authorizer

                roots = list(trusted_roots)
                Authorizer(trusted_roots=roots).set_revocation_list(previous)
                if not any(bytes(root.to_bytes()) == bytes(issuer.public_key.to_bytes()) for root in roots):
                    raise Refused("add the new issuer public key to trust before rotating the revocation signer")
            builder = SrlBuilder().from_existing(previous).version(previous.version + 1)
        signed = builder.revoke_all(list(ids)).build(issuer)
        publish(path, bytes(signed.to_bytes()), replace=not create)
        return signed
