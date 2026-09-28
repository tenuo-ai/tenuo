# /// script
# requires-python = ">=3.9"
# dependencies = ["tenuo==0.3.1"]
# ///
"""Demo key, warrant, and PoP helper for the Tenuo Envoy/Istio quickstarts.

DEMO ONLY. Keys are written unencrypted to ./.tenuo-demo/ (or $TENUO_DEMO_DIR).
Never reuse these keys or this script outside the quickstart.

Run with uv (installs the SDK on the fly):

    uv run demo_warrant.py init            # create demo root + agent keys
    uv run demo_warrant.py root-pubkey     # hex public key for TENUO_TRUSTED_KEYS
    uv run demo_warrant.py mint            # mint a warrant for the demo routes
    uv run demo_warrant.py pop httpbin_read endpoint=get

or with pip: `pip install tenuo==0.3.1 && python3 demo_warrant.py ...`.

The demo gateway.yaml maps requests to tools like this:

    GET  /<endpoint>  -> tool httpbin_read,  arg endpoint=<endpoint>
    POST /post        -> tool httpbin_write, arg message=<JSON body .message>

A PoP signature covers (warrant, tool, args, 30s time window), so compute it
right before each request with the same tool and args the authorizer will
extract.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
import time
from pathlib import Path

from tenuo import Exact, Pattern, SigningKey, Warrant

DEMO_DIR = Path(os.environ.get("TENUO_DEMO_DIR", ".tenuo-demo"))


def _key_path(name: str) -> Path:
    return DEMO_DIR / f"{name}.key"


def _load_key(name: str) -> SigningKey:
    path = _key_path(name)
    if not path.exists():
        sys.exit(f"{path} not found; run `demo_warrant.py init` first")
    return SigningKey.from_bytes(bytes.fromhex(path.read_text().strip()))


def _write_key(name: str, force: bool) -> SigningKey:
    path = _key_path(name)
    if path.exists() and not force:
        return _load_key(name)
    key = SigningKey.generate()
    path.write_text(bytes(key.secret_key_bytes()).hex() + "\n")
    path.chmod(0o600)
    return key


def cmd_init(args: argparse.Namespace) -> None:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("root", "agent", "untrusted-root"):
        _write_key(name, args.force)
    print(_pubkey_hex(_load_key("root")))


def _pubkey_hex(key: SigningKey) -> str:
    return bytes(key.public_key_bytes()).hex()


def cmd_root_pubkey(_: argparse.Namespace) -> None:
    print(_pubkey_hex(_load_key("root")))


def cmd_mint(args: argparse.Namespace) -> None:
    issuer = _load_key("untrusted-root" if args.untrusted else "root")
    agent = _load_key("agent")
    builder = (
        Warrant.mint_builder()
        .capability("httpbin_read", endpoint=Exact(args.endpoint))
        .holder(agent.public_key)
        .ttl(args.ttl)
    )
    if not args.read_only:
        builder = builder.capability("httpbin_write", message=Pattern(args.message))
    warrant = builder.mint(issuer)
    print(warrant.to_base64())


def cmd_pop(args: argparse.Namespace) -> None:
    agent = _load_key("agent")
    warrant_b64 = args.warrant or os.environ.get("WARRANT")
    if not warrant_b64:
        sys.exit("pass --warrant or set $WARRANT")
    warrant = Warrant.from_base64(warrant_b64)
    tool_args = {}
    for pair in args.args:
        key, sep, value = pair.partition("=")
        if not sep:
            sys.exit(f"argument {pair!r} must be key=value")
        tool_args[key] = value
    # Sign even when the args are outside the warrant, so the demo can show
    # the authorizer (not the client) rejecting them.
    signature = warrant.sign(agent, args.tool, tool_args, int(time.time()))
    print(base64.b64encode(bytes(signature)).decode())


def cmd_tamper(args: argparse.Namespace) -> None:
    """Flip one bit in the warrant's trailing signature byte (for negative tests)."""
    raw = bytearray(base64.urlsafe_b64decode(args.warrant + "=" * (-len(args.warrant) % 4)))
    raw[-1] ^= 0x01
    print(base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create demo keys; prints the root public key (hex)")
    p.add_argument("--force", action="store_true", help="overwrite existing demo keys")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("root-pubkey", help="print the demo root public key (hex)")
    p.set_defaults(func=cmd_root_pubkey)

    p = sub.add_parser("mint", help="mint a demo warrant held by the demo agent key")
    p.add_argument("--ttl", type=int, default=3600, help="lifetime in seconds (default 3600)")
    p.add_argument("--endpoint", default="get", help="httpbin_read endpoint allowed (default: get)")
    p.add_argument("--message", default="hello*", help="httpbin_write message pattern (default: hello*)")
    p.add_argument("--read-only", action="store_true", help="omit the httpbin_write capability")
    p.add_argument("--untrusted", action="store_true", help="sign with a root the authorizer does not trust")
    p.set_defaults(func=cmd_mint)

    p = sub.add_parser("pop", help="print a PoP signature for one request")
    p.add_argument("tool")
    p.add_argument("args", nargs="*", help="key=value tool arguments, as the gateway extracts them")
    p.add_argument("--warrant", help="warrant (base64); defaults to $WARRANT")
    p.set_defaults(func=cmd_pop)

    p = sub.add_parser("tamper", help="print a copy of a warrant with a corrupted signature")
    p.add_argument("warrant")
    p.set_defaults(func=cmd_tamper)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
