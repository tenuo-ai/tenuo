"""Portable approval files around native request hashing and SignedApproval."""

from __future__ import annotations

import base64
import hashlib
import time
from datetime import datetime

from .files import DocumentError, Refused, fields, load_yaml
from .warrants import decode_chain, encode_chain


def denial_hash(request_hash, reason):
    # A refusal cannot be replayed as an approval for the original call.
    return hashlib.sha256(
        b"tenuo.local.denial.v1\x00" + request_hash + hashlib.sha256(reason.encode()).digest()
    ).digest()


def request_document(chain, tool, arguments):
    from tenuo_core import py_compute_request_hash

    leaf = chain[-1]
    digest = bytes(py_compute_request_hash(leaf.id, tool, arguments, leaf.holder_key))
    return {
        "version": 1,
        "kind": "approval-request",
        "tool": tool,
        "arguments": arguments,
        "warrant": encode_chain(chain),
        "request_hash": digest.hex(),
        "expires_at": leaf.expires_at(),
    }


def checked_request(document, authorizer):
    from tenuo.approval import ApprovalRequest
    from tenuo_core import py_compute_request_hash

    fields(
        document,
        ["version", "kind", "tool", "arguments", "warrant", "request_hash", "expires_at"],
        ["version", "kind", "tool", "arguments", "warrant", "request_hash", "expires_at"],
    )
    if type(document["version"]) is not int or document["version"] != 1 or document["kind"] != "approval-request":
        raise DocumentError("expected version: 1 and kind: approval-request")
    if not isinstance(document["tool"], str) or not document["tool"] or not isinstance(document["arguments"], dict):
        raise DocumentError("approval request needs a tool and argument mapping")
    if not isinstance(document["warrant"], str):
        raise DocumentError("approval request needs an encoded warrant chain")
    chain = decode_chain(document["warrant"])
    authorizer.verify_chain(chain)
    leaf = chain[-1]
    digest = bytes(py_compute_request_hash(leaf.id, document["tool"], document["arguments"], leaf.holder_key))
    if document["request_hash"] != digest.hex():
        raise DocumentError("request hash does not match the warrant, holder, tool and arguments shown")
    try:
        expires = datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00"))
        limit = datetime.fromisoformat(leaf.expires_at())
        if expires.tzinfo is None or expires > limit or expires.timestamp() <= time.time():
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise DocumentError(
            "request expiry must be an unexpired timezone-qualified timestamp within the warrant lifetime"
        ) from None
    requirement = leaf.approval_requirement(document["tool"], document["arguments"])
    # Gate inspection is not a substitute for the capability constraints.
    if leaf.check_constraints(document["tool"], document["arguments"]) is not None:
        raise DocumentError("call exceeds the warrant; an approval cannot expand its authority")
    if not requirement.requires_approval() or not leaf.required_approvers():
        raise DocumentError("this call does not have a satisfiable signed approval gate")
    request = ApprovalRequest.for_warrant_gate(
        document["tool"], document["arguments"], leaf, digest, holder_key=leaf.holder_key
    )
    return chain, request, int(expires.timestamp())


def sign_response(document, authorizer, key, *, ttl=300, reason=None):
    from tenuo.approval import ApprovalRequest, sign_approval

    chain, request, expires = checked_request(document, authorizer)
    leaf = chain[-1]
    if not any(bytes(key.public_key.to_bytes()) == bytes(k.to_bytes()) for k in leaf.required_approvers()):
        raise Refused("your key is not an approver in the signed warrant")
    remaining = min(expires, request.warrant_expires_at_unix) - int(time.time())
    ttl = min(ttl, remaining)
    if ttl <= 0:
        raise DocumentError("request has expired; ask for new authority")
    if reason is not None:
        if not isinstance(reason, str) or not reason.strip():
            raise DocumentError("a refusal needs a nonempty reason")
        request = ApprovalRequest(
            tool=request.tool,
            arguments=request.arguments,
            warrant_id=request.warrant_id,
            request_hash=denial_hash(request.request_hash, reason),
            holder_key=leaf.holder_key,
        )
    signed = sign_approval(request, key, ttl_seconds=ttl)
    response = dict(document)
    encoded = base64.b64encode(bytes(signed.to_bytes())).decode()
    if reason is None:
        response["approval"] = encoded
    else:
        response["denial"] = {"reason": reason, "signature": encoded}
    return response


def response_approval(document, response, authorizer):
    """Validate a transported approval or refusal against the exact pending call."""
    from tenuo.approval import ApprovalDenied
    from tenuo_core import SignedApproval, verify_approvals

    fields(response, [*document, "approval", "denial"], document)
    if any(response.get(key) != value for key, value in document.items()):
        raise DocumentError("response does not match the exact approval request")
    if ("approval" in response) == ("denial" in response):
        raise DocumentError("response must contain exactly one approval or denial")
    chain, request, expires = checked_request(document, authorizer)
    leaf = chain[-1]
    digest = request.request_hash
    if "denial" in response:
        fields(response["denial"], ["reason", "signature"], ["reason", "signature"], "denial")
        reason = response["denial"]["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise DocumentError("refusal needs a nonempty reason")
        digest = denial_hash(digest, reason)
        encoded = response["denial"]["signature"]
    else:
        encoded = response["approval"]
    signed = SignedApproval.from_bytes(base64.b64decode(encoded, validate=True))
    payloads = verify_approvals(digest, [signed], leaf.required_approvers(), 1, 0)
    if payloads[0].expires_at > min(expires, request.warrant_expires_at_unix):
        raise DocumentError("approval expires after its request or warrant")
    if "denial" in response:
        raise ApprovalDenied(request, reason=response["denial"]["reason"])
    return signed


def read_request(path, authorizer):
    document = load_yaml(path)
    checked_request(document, authorizer)
    return document
