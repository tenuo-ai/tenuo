"""Thin argparse interface over local controller operations."""

from __future__ import annotations

import argparse
import base64
import json
import sys

import yaml

from .files import (
    DocumentError,
    fingerprint,
    keygen,
    load_public_key,
    name,
    publish,
    read_revocation_list,
    update_revocations,
)
from .workspace import Workspace


def parser():
    root = argparse.ArgumentParser(prog="tenuo-cli", description="Authorize agents locally from readable files.")
    root.add_argument("--home", help="Local workspace (default: TENUO_HOME or .tenuo)")
    root.add_argument("--json", action="store_true", help="Print one JSON object to stdout")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Prepare local files; --dev also prepares development identities")
    init.add_argument("--dev", action="store_true")
    key = commands.add_parser("key").add_subparsers(dest="action", required=True)
    key.add_parser("list")
    create = key.add_parser("new")
    create.add_argument("name", type=name)
    trust = commands.add_parser("trust").add_subparsers(dest="action", required=True)
    trust.add_parser("list")
    add = trust.add_parser("add")
    add.add_argument("--file", required=True)
    add.add_argument("--name", type=name)
    srl = commands.add_parser("revocations").add_subparsers(dest="action", required=True)
    for action in ("create", "add", "show"):
        sub = srl.add_parser(action)
        sub.add_argument("--file")
        if action != "show":
            sub.add_argument("--key", help="Controller key name or path")
        if action == "add":
            sub.add_argument("--id", required=True, action="append")
    commands.add_parser("doctor")
    return root


def execute(opts, workspace):
    if opts.command == "init":
        workspace.initialize(dev=opts.dev)
        return {
            "home": str(workspace.path),
            "message": "Local files ready. Next: issue a warrant from a YAML template.",
            "development": opts.dev,
        }
    workspace.config
    if opts.command == "key":
        if opts.action == "list":
            return {"keys": workspace.key_inventory()}
        private, public, key = keygen(workspace.path / "keys" / opts.name)
        return {"private_file": str(private), "public_file": str(public), "fingerprint": fingerprint(key)}
    if opts.command == "trust":
        if opts.action == "list":
            return {
                "roots": [
                    {"name": p.stem, "fingerprint": fingerprint(load_public_key(p))}
                    for p in sorted((workspace.path / "trust").glob("*.pub"))
                ]
            }
        key = load_public_key(opts.file)
        destination = workspace.path / "trust" / ((opts.name or fingerprint(key)) + ".pub")
        publish(destination, base64.b64encode(bytes(key.to_bytes())) + b"\n")
        return {"file": str(destination), "fingerprint": fingerprint(key)}
    if opts.command == "revocations":
        path = opts.file or workspace.path / "revocations.srl"
        if opts.action == "show":
            signed = read_revocation_list(path)
        else:
            signed = update_revocations(
                path,
                workspace.signing_key(opts.key or workspace.config["issuer"]),
                getattr(opts, "id", []),
                create=opts.action == "create",
            )
        return {
            "version": signed.version,
            "issuer": fingerprint(signed.issuer),
            "revoked_ids": list(signed.revoked_ids),
        }
    if opts.command == "doctor":
        return {"checks": workspace.diagnostics()}
    raise DocumentError("unknown command")


def main(argv=None):
    opts = parser().parse_args(argv)
    try:
        result = execute(opts, Workspace(opts.home))
        status = 1 if any(c["status"] == "error" for c in result.get("checks", [])) else 0
    except Exception as exc:
        # Parse/key errors may include input bytes in third-party messages. Keep
        # the CLI error bounded to our own safe messages or the exception type.
        message = (
            str(exc) if isinstance(exc, (DocumentError, FileExistsError, FileNotFoundError)) else type(exc).__name__
        )
        result, status = {"error": message}, 1
    if opts.json:
        print(json.dumps(result, allow_nan=False))
    else:
        print(yaml.safe_dump(result, sort_keys=False).rstrip(), file=sys.stderr)
    return status
