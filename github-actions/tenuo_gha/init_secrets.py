"""Create the Secret mount. Never prints a private key."""

from __future__ import annotations

import argparse
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from tenuo import SigningKey

from .config import ConfigError
from .secrets import load_github_app_pem, resolve_secret_file


@dataclass
class InitResult:
    mount: Path
    created: List[str]
    skipped: List[str]
    receipt_public_key: Optional[str] = None
    issuer_public_key: Optional[str] = None


def _write_ed25519(path: Path) -> SigningKey:
    key = SigningKey.generate()
    path.write_text(key.to_pem(), encoding="utf-8")
    path.chmod(0o600)
    return key


def init_secrets(
    mount: Path,
    *,
    app_pem: Optional[Path] = None,
    issuer: bool = False,
    force: bool = False,
) -> InitResult:
    """Write ``receipt.pem`` (and optional issuer / copied App PEM) under ``mount``."""
    root = mount.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    created: List[str] = []
    skipped: List[str] = []

    receipt_path = resolve_secret_file(root, "receipt.pem")
    receipt_public = None
    if receipt_path.exists() and not force:
        skipped.append("receipt.pem")
        existing = SigningKey.from_pem(receipt_path.read_text(encoding="utf-8"))
        receipt_public = existing.public_key.to_bytes().hex()
    else:
        receipt_public = _write_ed25519(receipt_path).public_key.to_bytes().hex()
        created.append("receipt.pem")

    issuer_public = None
    if issuer:
        issuer_path = resolve_secret_file(root, "issuer.pem")
        if issuer_path.exists() and not force:
            skipped.append("issuer.pem")
            existing = SigningKey.from_pem(issuer_path.read_text(encoding="utf-8"))
            issuer_public = existing.public_key.to_bytes().hex()
        else:
            issuer_public = _write_ed25519(issuer_path).public_key.to_bytes().hex()
            created.append("issuer.pem")

    if app_pem is not None:
        source = Path(app_pem).expanduser().resolve()
        if not source.is_file():
            raise ConfigError("app PEM path is not a readable file")
        load_github_app_pem(source.read_bytes())
        dest = resolve_secret_file(root, "app.pem")
        if dest.exists() and not force:
            skipped.append("app.pem")
        else:
            shutil.copyfile(source, dest)
            dest.chmod(0o600)
            created.append("app.pem")

    return InitResult(
        mount=root,
        created=created,
        skipped=skipped,
        receipt_public_key=receipt_public,
        issuer_public_key=issuer_public,
    )


def format_report(result: InitResult) -> str:
    lines = [f"mount {result.mount}"]
    if result.created:
        lines.append("created " + ", ".join(result.created))
    if result.skipped:
        lines.append("kept " + ", ".join(result.skipped))
    if result.receipt_public_key:
        lines.append(f"receipt_public_key {result.receipt_public_key}")
    if result.issuer_public_key:
        lines.append(f"issuer_public_key {result.issuer_public_key}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a Secret mount for the gateway")
    parser.add_argument("--mount", default="github-actions/examples/secrets")
    parser.add_argument("--app-pem", default="", help="Copy this App PEM to app.pem in the mount")
    parser.add_argument("--issuer", action="store_true", help="Also write issuer.pem (self-hosted exchange)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files in the mount")
    args = parser.parse_args()
    result = init_secrets(
        Path(args.mount),
        app_pem=Path(args.app_pem) if args.app_pem else None,
        issuer=args.issuer,
        force=args.force,
    )
    print(format_report(result))
