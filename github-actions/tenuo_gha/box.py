"""Load the concierge config and Secret mount. Fail before compose if keys cannot sign."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path
from typing import Optional

from .app import Gateway
from .config import ConfigError, GatewayConfig


def check_box(config: GatewayConfig, *, mount: Optional[Path] = None) -> Gateway:
    """Construct the gateway. Startup refusals and the sign self-test run here."""
    if config.role != "gateway":
        raise ConfigError("box check expects TENUO_ROLE=gateway")
    if mount is not None:
        config.secret_mount = mount.expanduser().resolve()
    # Compose writes /state; box only needs a writable path for the self-test.
    if not os.access(config.receipt_path.parent, os.W_OK):
        config.receipt_path = Path(tempfile.mkdtemp(prefix="tenuo-box-")) / "receipts.jsonl"
    return Gateway(config)


def format_ok(config: GatewayConfig) -> str:
    packs = ",".join(config.packs) or "none"
    repos = ",".join(config.repositories) or "installation set"
    app = config.github_app_id or "unset"
    lines = [
        "box ready",
        f"role {config.role}",
        f"signing {config.signing_provider}",
        f"app_id {app}",
        f"packs {packs}",
        f"repositories {repos}",
        "doctor --gateway-url URL --gateway-only",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check the concierge gateway config and Secret mount")
    parser.add_argument(
        "--config",
        default=os.environ.get("TENUO_GATEWAY_CONFIG", "github-actions/examples/gateway-secret.yaml"),
    )
    parser.add_argument(
        "--mount",
        default=os.environ.get("TENUO_SECRET_MOUNT", ""),
        help="Local Secret directory. Overrides signing.secret.mount so the compose YAML works before Docker.",
    )
    args = parser.parse_args()
    path = Path(args.config)
    try:
        config = GatewayConfig.from_yaml(path)
        check_box(config, mount=Path(args.mount) if args.mount else None)
    except (ConfigError, OSError) as exc:
        print(f"box not ready: {exc}")
        raise SystemExit(1) from exc
    print(format_ok(config))
