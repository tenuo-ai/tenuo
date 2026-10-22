"""Thin argparse interface over local workspace operations."""

from __future__ import annotations

import argparse
import base64
import json
import os
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

# Integrations add a command group under their own name, the way kubectl and gh
# take plugins: a package registers a `tenuo.cli` entry point whose function
# receives the rest of the command line. The global options reach it as
# TENUO_HOME and TENUO_JSON=1. Known ones get an install hint.
KNOWN_INTEGRATIONS = {"hermes": "hermes-tenuo"}


def integrations():
    from importlib.metadata import entry_points

    found = entry_points()
    # Python 3.9 returns a dict of groups; 3.10+ selects by keyword.
    group = found.select(group="tenuo.cli") if hasattr(found, "select") else found.get("tenuo.cli", ())
    return {entry.name: entry for entry in group}


def split_integration(argv, builtins):
    """``[--home DIR] [--json] NAME rest…`` → (globals, NAME, rest) when NAME is an
    integration, so its own options (``hermes --help``) reach it untouched."""
    i = 0
    while i < len(argv):
        if argv[i] == "--json" or argv[i].startswith("--home="):
            i += 1
        elif argv[i] == "--home":
            i += 2
        else:
            break
    if i < len(argv) and argv[i] not in builtins and argv[i] in set(integrations()) | set(KNOWN_INTEGRATIONS):
        return argv[:i], argv[i], argv[i + 1:]
    return None


def parser():
    root = argparse.ArgumentParser(
        prog="tenuo-cli", description="Authorize agents locally from readable files.", allow_abbrev=False
    )
    root.add_argument("--home", help="Local workspace (default: TENUO_HOME or ~/.tenuo)")
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
            sub.add_argument("--key", help="Issuer key name or path")
        if action == "add":
            sub.add_argument("--id", required=True, action="append")
    commands.add_parser("doctor")
    mode = commands.add_parser("mode", help="Show or set enforce or observe for local adapters")
    mode.add_argument("value", nargs="?", choices=("enforce", "observe"))
    calls = commands.add_parser("calls", help="Calls recorded in observe mode").add_subparsers(
        dest="action", required=True
    )
    for action in ("list", "summary"):
        sub = calls.add_parser(action)
        sub.add_argument("--file")
        sub.add_argument("--tool")
        if action == "list":
            sub.add_argument("--limit", type=int, default=100)
    audit = commands.add_parser("audit").add_subparsers(dest="action", required=True)
    for action in ("list", "verify"):
        sub = audit.add_parser(action)
        sub.add_argument("--file")
        sub.add_argument("--authorizer", action="append")
        if action == "list":
            sub.add_argument("--warrant", type=name)
            sub.add_argument("--denied", action="store_true")
            sub.add_argument("--since")
            sub.add_argument("--limit", type=int, default=100)
    templates = commands.add_parser("template").add_subparsers(dest="action", required=True)
    create = templates.add_parser("new")
    create.add_argument("--out", required=True)
    for action in ("validate", "show"):
        template = templates.add_parser(action)
        template.add_argument("--file", required=True)
        template.add_argument("--set", action="append", metavar="NAME=VALUE", help="a value for one of the template's vars; [a, b] is a list, \"00123\" stays a string")
        if action == "show":
            template.add_argument("--expanded", action="store_true")
    warrants = commands.add_parser("warrant").add_subparsers(dest="action", required=True)
    issue = warrants.add_parser("issue")
    source = issue.add_mutually_exclusive_group(required=True)
    source.add_argument("--template")
    source.add_argument("--request")
    issue.add_argument("--holder")
    issue.add_argument("--set", action="append", metavar="NAME=VALUE", help="a value for one of the template's vars; [a, b] is a list, \"00123\" stays a string")
    issue.add_argument("--from", dest="parent")
    issue.add_argument("--key")
    for action in ("show", "verify", "reissue", "review"):
        help = "Explain what a warrant or YAML template allows, and what gets through" if action == "review" else None
        sub = warrants.add_parser(action, help=help)
        source = sub.add_mutually_exclusive_group(required=True)
        source.add_argument("--file")
        source.add_argument("--id", type=name)
        if action in ("show", "review"):
            sub.add_argument("--set", action="append", metavar="NAME=VALUE", help="a value for one of the template's vars; [a, b] is a list, \"00123\" stays a string")
        if action == "reissue":
            sub.add_argument("--ttl", required=True)
            sub.add_argument("--holder")
            sub.add_argument("--key")
        if action != "reissue":
            continue
        sub.add_argument("--out")
        sub.add_argument("--no-store", action="store_true")
        sub.add_argument("--replace", action="store_true", help="swap an existing --out file")
    issue.add_argument("--out")
    issue.add_argument("--no-store", action="store_true")
    issue.add_argument("--replace", action="store_true", help="swap an existing --out file")
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
    root.builtins = set(commands.choices)
    for integration in sorted(set(integrations()) | set(KNOWN_INTEGRATIONS)):
        if integration in root.builtins:
            continue
        sub = commands.add_parser(integration, add_help=False, help=f"Commands from {KNOWN_INTEGRATIONS.get(integration, integration)}")
        sub.add_argument("args", nargs=argparse.REMAINDER)
    return root


def run_integration(opts):
    entry = integrations().get(opts.command)
    if entry is None:
        package = KNOWN_INTEGRATIONS[opts.command]
        print(f"tenuo-cli {opts.command} comes with {package}: pip install {package}", file=sys.stderr)
        return 2
    if opts.home:
        os.environ["TENUO_HOME"] = opts.home
    if opts.json:
        os.environ["TENUO_JSON"] = "1"
    return entry.load()(opts.args) or 0


def execute(opts, workspace):
    if opts.command == "audit":
        from .audit import inspect_audit

        return inspect_audit(workspace, path=opts.file, verify=opts.action == "verify",
                             authorizers=opts.authorizer, warrant=getattr(opts, "warrant", None),
                             denied=getattr(opts, "denied", False), since=getattr(opts, "since", None),
                             limit=getattr(opts, "limit", 100))
    if opts.command == "approval":
        from .approvals import read_request, sign_response
        from .warrants import decode_chain
        from .files import write_yaml
        from tenuo.warrant_template import duration

        document = read_request(opts.file, workspace.authorizer())
        chain = decode_chain(document["warrant"])
        review = {"tool": document["tool"], "arguments": document["arguments"],
                  "warrant_id": str(chain[-1].id), "expires_at": document["expires_at"],
                  "issuer": fingerprint(chain[0].issuer),
                  "authorized_approvers": [fingerprint(key) for key in chain[-1].required_approvers()]}
        if opts.action == "show":
            return {"request": review, "verified": True,
                    **({"raw_request": document} if opts.json else {})}
        if not opts.yes:
            if not sys.stdin.isatty():
                return {"error": "Review with approval show, then pass --yes to sign noninteractively", "exit_code": 2}
            print(yaml.safe_dump(review, sort_keys=False), file=sys.stderr)
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
        from tenuo.warrant_template import WarrantTemplate, parse_set
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
        template = WarrantTemplate.load(opts.file, parse_set(opts.set))
        if opts.action == "validate":
            from .review import brief, review_template

            return {"valid": True, "file": opts.file, "review": brief(review_template(template), opts.file, opts.set or ())}
        return {"template": template.expanded() if opts.expanded else template.document, "signed": False}
    if opts.command == "init":
        workspace.initialize(dev=opts.dev)
        return {
            "home": str(workspace.path),
            "message": (
                "Local files ready. Next: tenuo-cli mode observe, run your agent, then tenuo-cli calls summary."
                if opts.dev
                else "Local files ready. Next: add an issuer with tenuo-cli trust add, then tenuo-cli mode observe."
            ),
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
        refuse_workspace_secret(workspace, opts.file, key)
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
                trusted_roots=workspace.trusted_roots() if opts.action != "create" else None,
            )
        return {
            "version": signed.version,
            "issuer": fingerprint(signed.issuer),
            "revoked_ids": list(signed.revoked_ids),
        }
    if opts.command == "doctor":
        return {"checks": workspace.diagnostics()}
    if opts.command == "mode":
        if opts.value is None:
            return {"mode": workspace.config["mode"]}
        workspace.set_mode(opts.value)
        message = (
            "Local adapters now record calls and block nothing. Review them with tenuo-cli calls summary."
            if opts.value == "observe"
            else "Local adapters enforce warrants from their next call. Temporal workers pick this up when restarted."
        )
        return {"mode": opts.value, "message": message}
    if opts.command == "calls":
        from .observations import list_calls, summarize_calls

        if opts.action == "list":
            return list_calls(workspace, path=opts.file, tool=opts.tool, limit=opts.limit)
        return summarize_calls(workspace, path=opts.file, tool=opts.tool)
    raise DocumentError("unknown command")


def refuse_workspace_secret(workspace, path, key):
    """Trust files are shared as public data; never publish a workspace private key through one."""
    import os

    from .files import check_public_material, load_signing_key

    source = os.stat(os.path.expanduser(path))
    for private in sorted((workspace.path / "keys").glob("*.key")):
        if os.path.samefile(path, private) or (source.st_ino, source.st_dev) == (
            os.stat(private).st_ino,
            os.stat(private).st_dev,
        ):
            raise DocumentError("trust input is a workspace private key; use its .pub file")
        check_public_material(load_signing_key(private), [key])


def warrant_command(opts, workspace):
    from pathlib import Path
    from tenuo.warrant_template import WarrantTemplate, duration, parse_set
    from .review import brief, review_chain, review_template
    from .warrants import check, decode_chain, describe, issue, load_chain, reissue, save

    if opts.action not in ("show", "review"):
        workspace.config

    if opts.action == "issue":
        path = Path(opts.template or opts.request).expanduser()
        template = WarrantTemplate.load(path, parse_set(opts.set))
        data = template.document
        if opts.request:
            if data.get("kind") != "warrant-request" or opts.holder:
                raise DocumentError("--request needs kind: warrant-request with its own holder; do not pass --holder")
            holder = data["holder"]
            # A request names its holder relative to the request file; --holder is relative to the current directory.
            if "/" in holder or "\\" in holder or holder.endswith(".pub"):
                public_path = Path(holder).expanduser()
                holder = str(public_path if public_path.is_absolute() else path.parent / public_path)
        else:
            if data.get("kind") or not opts.holder:
                raise DocumentError("--template needs --holder and a template without kind: warrant-request")
            holder = opts.holder
        chain = issue(
            workspace,
            template,
            workspace.public_key(holder),
            issuer=opts.key,
            parent=load_chain(opts.parent) if opts.parent else None,
        )
        files = save(workspace, chain, out=opts.out, store=not opts.no_store, replace=opts.replace)
        return {
            "warrant": {**describe(chain), **check(workspace, chain)},
            "files": files,
            "review": brief(review_chain(chain), files[-1]),
        }
    if opts.action == "list":
        entries, errors = [], []
        for path in sorted((workspace.path / "warrants").glob("*.warrant")):
            try:
                chain = load_chain(path)
                entries.append({**describe(chain), **check(workspace, chain)})
            except Exception:
                errors.append({"file": str(path), "error": "Could not decode warrant"})
        return {"warrants": entries, "errors": errors}
    path = getattr(opts, "file", None) or workspace.path / "warrants" / (opts.id + ".warrant")
    if opts.action == "review" and str(path).endswith((".yaml", ".yml")):
        return {"review": review_template(WarrantTemplate.load(path, parse_set(getattr(opts, "set", None))))}
    if opts.action == "show" and str(path).endswith((".yaml", ".yml")):
        return {"request": WarrantTemplate.load(path, parse_set(getattr(opts, "set", None))).document, "signed": False}
    if getattr(opts, "set", None):
        raise DocumentError("--set applies to a YAML template or request, not a signed warrant")
    chain = decode_chain(sys.stdin.read(4 * 1024 * 1024 + 1)) if str(path) == "-" else load_chain(path)
    if opts.action == "show":
        return {"warrant": describe(chain)}
    if opts.action == "review":
        return {"review": review_chain(chain)}
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
        workspace,
        chain,
        duration(opts.ttl),
        issuer=opts.key,
        holder=workspace.public_key(opts.holder) if opts.holder else None,
    )
    return {
        "warrant": {**describe(chain), **check(workspace, chain)},
        "files": save(workspace, chain, out=opts.out, store=not opts.no_store, replace=opts.replace),
    }


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    root = parser()
    split = split_integration(argv, root.builtins)
    if split is not None:
        options, name, rest = split
        opts = root.parse_args([*options, name])
        opts.args = rest
        return run_integration(opts)
    opts = root.parse_args(argv)
    if hasattr(opts, "args"):
        return run_integration(opts)
    try:
        result = execute(opts, Workspace(opts.home))
        status = result.pop("exit_code", 1 if any(c["status"] == "error" for c in result.get("checks", [])) else 0)
    except Exception as exc:
        # Parse/key errors may include input bytes in third-party messages. Keep
        # the CLI error bounded to our own safe messages or the exception type.
        message = (
            str(exc) if isinstance(exc, (DocumentError, FileExistsError, FileNotFoundError)) else type(exc).__name__
        )
        result, status = {"error": message}, getattr(exc, "exit_code", 1)
    if opts.json:
        print(json.dumps(result, allow_nan=False))
    else:
        if "warrant" in result and isinstance(result["warrant"], dict):
            opaque = result["warrant"].pop("extensions_base64", {})
            if opaque:
                result["warrant"]["additional_signed_extensions"] = list(opaque)
        print(yaml.safe_dump(result, sort_keys=False).rstrip(), file=sys.stderr)
    return status
