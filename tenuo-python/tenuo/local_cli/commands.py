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
    templates = commands.add_parser("template").add_subparsers(dest="action", required=True)
    create = templates.add_parser("new")
    create.add_argument("--out", required=True)
    for action in ("validate", "show"):
        template = templates.add_parser(action)
        template.add_argument("--file", required=True)
        if action == "show":
            template.add_argument("--expanded", action="store_true")
    warrants = commands.add_parser("warrant").add_subparsers(dest="action", required=True)
    issue = warrants.add_parser("issue")
    source = issue.add_mutually_exclusive_group(required=True)
    source.add_argument("--template")
    source.add_argument("--request")
    issue.add_argument("--holder")
    issue.add_argument("--from", dest="parent")
    issue.add_argument("--key")
    for action in ("show", "verify", "reissue"):
        sub = warrants.add_parser(action)
        source = sub.add_mutually_exclusive_group(required=True)
        source.add_argument("--file")
        source.add_argument("--id", type=name)
        if action == "reissue":
            sub.add_argument("--ttl", required=True)
            sub.add_argument("--holder")
            sub.add_argument("--key")
        if action != "reissue":
            continue
        sub.add_argument("--out")
        sub.add_argument("--no-store", action="store_true")
    issue.add_argument("--out")
    issue.add_argument("--no-store", action="store_true")
    warrants.add_parser("list")
    approvals = commands.add_parser("approval").add_subparsers(dest="action", required=True)
    for action in ("show", "approve", "deny"):
        sub = approvals.add_parser(action)
        sub.add_argument("--file", required=True)
        if action == "show":
            continue
        sub.add_argument("--key", default="approver")
        sub.add_argument("--ttl")
        sub.add_argument("--out")
        sub.add_argument("--yes", action="store_true")
        if action == "deny":
            sub.add_argument("--reason", required=True)
    return root


def execute(opts, workspace):
    if opts.command == "approval":
        from .approvals import read_request, sign_response
        from .files import write_yaml
        from tenuo.warrant_template import duration

        document = read_request(opts.file, workspace.authorizer())
        if opts.action == "show":
            return {"request": document, "verified": True}
        if not opts.yes:
            if not sys.stdin.isatty():
                return {"error": "Review with approval show, then pass --yes to sign noninteractively", "exit_code": 2}
            print(yaml.safe_dump(document, sort_keys=False), file=sys.stderr)
            if input("Sign this decision? [y/N] ").strip().lower() not in ("y", "yes"):
                return {"error": "No decision signed", "exit_code": 4}
        response = sign_response(
            document,
            workspace.authorizer(),
            workspace.signing_key(opts.key),
            ttl=duration(opts.ttl or workspace.config["approvals"]["ttl"]),
            reason=opts.reason if opts.action == "deny" else None,
        )
        path = opts.out or workspace.path / "approvals" / (document["request_hash"] + ".yaml")
        write_yaml(path, response)
        return {"file": str(path), "decision": "approved" if opts.action == "approve" else "denied"}
    if opts.command == "warrant":
        return warrant_command(opts, workspace)
    if opts.command == "template":
        from tenuo.warrant_template import WarrantTemplate
        from .files import write_yaml

        if opts.action == "new":
            data = {
                "version": 2,
                "name": "order-lookup",
                "ttl": "30m",
                "capabilities": {"get_order": {"order_id": "A-1001"}},
            }
            write_yaml(opts.out, data)
            return {"file": opts.out, "message": "Edit the tool and argument names to match your application."}
        template = WarrantTemplate.load(opts.file)
        if opts.action == "validate":
            return {"valid": True, "file": opts.file}
        return {"template": template.expanded() if opts.expanded else template.document, "signed": False}
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


def warrant_command(opts, workspace):
    from pathlib import Path
    from tenuo.warrant_template import WarrantTemplate, duration
    from .warrants import decode_chain, describe, issue, load_chain, reissue, save

    if opts.action == "issue":
        path = Path(opts.template or opts.request).expanduser()
        template = WarrantTemplate.load(path)
        data = template.document
        if opts.request:
            if data.get("kind") != "warrant-request" or opts.holder:
                raise DocumentError("--request needs kind: warrant-request with its own holder; do not pass --holder")
            holder = data["holder"]
        else:
            if data.get("kind") or not opts.holder:
                raise DocumentError("--template needs --holder and a template without kind: warrant-request")
            holder = opts.holder
        if "/" in holder or "\\" in holder or holder.endswith(".pub"):
            public_path = Path(holder).expanduser()
            holder = str(public_path if public_path.is_absolute() else path.parent / public_path)
        chain = issue(
            workspace,
            template,
            workspace.public_key(holder),
            issuer=opts.key,
            parent=load_chain(opts.parent) if opts.parent else None,
        )
        return {"warrant": describe(chain), "files": save(workspace, chain, out=opts.out, store=not opts.no_store)}
    if opts.action == "list":
        entries, errors = [], []
        for path in sorted((workspace.path / "warrants").glob("*.warrant")):
            try:
                row = describe(load_chain(path))
                try:
                    workspace.authorizer().verify_chain(load_chain(path))
                    row["verified"] = True
                except Exception:
                    row["verification_error"] = "Not valid against current local trust, expiry or revocations"
                entries.append(row)
            except Exception:
                errors.append({"file": str(path), "error": "Could not decode warrant"})
        return {"warrants": entries, "errors": errors}
    path = getattr(opts, "file", None) or workspace.path / "warrants" / (opts.id + ".warrant")
    if opts.action == "show" and str(path).endswith((".yaml", ".yml")):
        return {"request": WarrantTemplate.load(path).document, "signed": False}
    chain = decode_chain(sys.stdin.read(4 * 1024 * 1024 + 1)) if str(path) == "-" else load_chain(path)
    if opts.action == "show":
        return {"warrant": describe(chain)}
    if opts.action == "verify":
        try:
            workspace.authorizer().verify_chain(chain)
        except Exception:
            return {
                "valid": False,
                "id": str(chain[-1].id),
                "error": "Warrant verification failed. Check trust, full chain, expiry and revocations.",
                "exit_code": 3,
            }
        return {"valid": True, "id": str(chain[-1].id)}
    chain = reissue(
        chain,
        workspace.signing_key(opts.key or workspace.config["issuer"]),
        duration(opts.ttl),
        holder=workspace.public_key(opts.holder) if opts.holder else None,
    )
    return {"warrant": describe(chain), "files": save(workspace, chain, out=opts.out, store=not opts.no_store)}


def main(argv=None):
    opts = parser().parse_args(argv)
    try:
        result = execute(opts, Workspace(opts.home))
        status = result.pop("exit_code", 1 if any(c["status"] == "error" for c in result.get("checks", [])) else 0)
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
