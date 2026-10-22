"""Issue and inspect native root-first warrant stacks."""

from __future__ import annotations

import base64
from pathlib import Path

from .files import DocumentError, check_public_material, fingerprint, name, publish, read_bytes


def decode_chain(text):
    from tenuo import Warrant
    from tenuo_core import decode_warrant_stack_base64

    try:
        chain = list(decode_warrant_stack_base64(text.strip()))
    except Exception:
        try:
            chain = [Warrant.from_base64(text.strip())]
        except Exception:
            raise DocumentError("expected a native warrant stack or a legacy base64 warrant") from None
    if not chain:
        raise DocumentError("warrant chain is empty")
    return chain


def load_chain(path):
    return decode_chain(read_bytes(path).decode())


def encode_chain(chain):
    from tenuo_core import encode_warrant_stack

    encoded = encode_warrant_stack(list(chain))
    if not encoded:
        raise DocumentError("could not encode a nonempty warrant chain")
    return encoded


def describe(chain):
    from tenuo.warrant_template import constraint_document

    leaf = chain[-1]
    gates = {}
    for tool in leaf.capabilities:
        inspection = leaf.inspect_approval_gate(tool)
        if inspection.is_gated():
            gates[tool] = {"kind": inspection.kind, "arguments": inspection.arguments, "message": inspection.message}
    return {
        "id": str(leaf.id),
        "holder": fingerprint(leaf.holder_key),
        "issuer": fingerprint(chain[0].issuer),
        "expires_at": leaf.expires_at(),
        "expired": leaf.is_expired(),
        "chain": [str(w.id) for w in chain],
        "capabilities": {
            tool: {arg: constraint_document(c) for arg, c in args.items()} for tool, args in leaf.capabilities.items()
        },
        "approval_gates": gates,
        "approvers": [fingerprint(k) for k in (leaf.required_approvers() or [])],
        "required_signatures": leaf.approval_threshold(),
        "extensions_base64": {k: base64.b64encode(v).decode() for k, v in leaf.extensions().items()},
        "warrant_type": str(leaf.warrant_type).rsplit(".", 1)[-1].lower(),
        "session_id": leaf.session_id,
        "terminal": leaf.terminal,
        "max_depth": leaf.max_depth,
        "clearance": str(leaf.clearance) if leaf.clearance is not None else None,
        "agent_id": leaf.agent_id(),
        "issuable_tools": leaf.issuable_tools,
        "max_issue_depth": leaf.max_issue_depth,
        "constraint_bounds": repr(leaf.constraint_bounds_dict()) if leaf.constraint_bounds_dict() is not None else None,
    }


def check(workspace, chain):
    """Whether the chain is valid against this workspace's trust, expiry and revocations right now.

    ``describe`` only decodes, so it never claims validity; callers that ran the
    check add this to their output.
    """
    from tenuo.exceptions import ExpiredError, RevokedError, UntrustedRoot

    try:
        workspace.authorizer().verify_chain(chain)
    except ExpiredError:
        return {"verified": False, "verification_error": "expired"}
    except RevokedError:
        return {"verified": False, "verification_error": "revoked"}
    except UntrustedRoot:
        return {"verified": False, "verification_error": "issuer not in local trust"}
    except Exception:
        return {"verified": False, "verification_error": "not valid against local trust, expiry or revocations"}
    return {"verified": True}


def issue(workspace, template, holder, *, issuer=None, parent=None):
    """Issue using a recipient's public key; delegate through native attenuation."""
    if parent is None:
        return [template.mint(workspace.signing_key(issuer or workspace.config["issuer"]), holder)]
    workspace.authorizer().verify_chain(parent)
    key = workspace.signing_key(issuer or "agent")
    check_public_material(key, [holder, *template._approvers])
    if bytes(key.public_key.to_bytes()) != bytes(parent[-1].holder_key.to_bytes()):
        raise DocumentError("delegation needs the parent holder's key")
    builder = parent[-1].grant_builder().holder(holder).ttl(template.ttl_seconds)
    for tool, constraints in template._capabilities.items():
        builder = builder.capability(tool, **constraints)
    if template._gates:
        builder = builder.approval_gates(template._gates).required_approvers(template._approvers).min_approvals(1)
    child = builder.grant(key)
    chain = [*parent, child]
    workspace.authorizer().verify_chain(chain)
    return chain


def save(workspace, chain, *, out=None, store=True, replace=False):
    """Write the chain to the workspace store and/or ``out``.

    ``replace`` lets ``out`` swap an existing warrant file atomically: adapters
    reading that file use the new warrant on their next call. The workspace
    copy, named by warrant ID, is never replaced.
    """
    encoded = (encode_chain(chain) + "\n").encode()
    destination = workspace.path / "warrants" / (name(str(chain[-1].id)) + ".warrant")
    out = Path(out).expanduser() if out else None
    targets = ([destination] if store else []) + ([out] if out else [])
    targets = list(dict.fromkeys(targets))
    if not targets:
        raise DocumentError("--no-store requires --out")
    for path in targets:
        if path == out and replace and not path.is_symlink():
            continue
        if path.exists() or path.is_symlink():
            hint = "; pass --replace to swap it in for agents reading it" if path == out else ""
            raise DocumentError(f"{path}: already exists{hint}")
    for path in targets:
        publish(path, encoded, replace=replace and path == out)
    return [str(p) for p in targets]


def reissue(workspace, previous, ttl, *, issuer=None, holder=None):
    """Copy a simple root grant, refusing claims that cannot be preserved exactly."""
    from tenuo import Warrant
    from tenuo_core import WarrantType

    if len(previous) != 1 or previous[0].depth != 0 or previous[0].parent_hash is not None:
        raise DocumentError("reissue a delegated warrant from its valid parent using warrant issue --from")
    old = previous[0]
    # A reissued warrant is a new root, so revoking the old ID would no longer cover it. Expiry is not checked:
    # renewing an expired grant is what reissue is for.
    if str(old.id) in workspace.authorizer().installed_revocation_list().revoked_ids:
        raise DocumentError(f"{old.id} is revoked; reissuing it would undo the revocation")
    key = workspace.signing_key(issuer or workspace.config["issuer"])
    check_public_material(key, [holder or old.holder_key, *(old.required_approvers() or [])])
    if bytes(old.issuer.to_bytes()) != bytes(key.public_key.to_bytes()) or not old.verify(key.public_key.to_bytes()):
        raise DocumentError("issuer key does not match the previous warrant")
    if (
        old.warrant_type != WarrantType.Execution
        or old.extensions()
        or old.terminal
        or old.agent_id() is not None
        or old.clearance is not None
        or old.constraint_bounds_dict() is not None
        or old.max_issue_depth is not None
        or old.issuable_tools is not None
        or old.max_depth != 64
    ):
        raise DocumentError(
            "this warrant has claims reissue cannot copy exactly; issue explicitly from its reviewed YAML template"
        )
    builder = Warrant.mint_builder().holder(holder or old.holder_key).ttl(ttl)
    for tool, constraints in old.capabilities.items():
        builder = builder.capability(tool, **constraints)
    if old.required_approvers():
        builder = builder.required_approvers(list(old.required_approvers()))
    if old.min_approvals() is not None:
        builder = builder.min_approvals(old.min_approvals())
    if old.session_id is not None:
        builder = builder.session_id(old.session_id)
    return [builder.mint(key)]
