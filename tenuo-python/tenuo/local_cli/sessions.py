"""Operator-controlled session attachments; attaching never grants authority."""

from __future__ import annotations

import hashlib

from .files import DocumentError, fields, load_yaml, name, operator_lock, publish, write_yaml
from .warrants import encode_chain, load_chain


def session_path(workspace, session_id):
    if not isinstance(session_id, str) or not session_id.strip() or len(session_id) > 1024:
        raise DocumentError("session ID must be a nonempty string of at most 1024 characters")
    return workspace.path / "sessions" / (hashlib.sha256(session_id.encode()).hexdigest() + ".yaml")


def read_session(workspace, session_id):
    document = load_yaml(session_path(workspace, session_id))
    fields(document, ["version", "session_id", "warrants"], ["version", "session_id", "warrants"], "session")
    if type(document["version"]) is not int or document["version"] != 1 or document["session_id"] != session_id:
        raise DocumentError("session manifest identity or version does not match")
    ids = document["warrants"]
    if not isinstance(ids, list) or len(ids) > 64 or len(set(ids)) != len(ids):
        raise DocumentError("session must contain at most 64 distinct warrant IDs")
    for wid in ids:
        name(wid)
    return document


def attach(workspace, session_id, chain, *, holder="agent"):
    workspace.authorizer().verify_chain(chain)
    if bytes(workspace.public_key(holder).to_bytes()) != bytes(chain[-1].holder_key.to_bytes()):
        raise DocumentError("warrant holder does not match the selected agent public key")
    if chain[-1].session_id is not None and chain[-1].session_id != session_id:
        raise DocumentError("warrant is bound to a different session")
    path = session_path(workspace, session_id)
    wid = name(str(chain[-1].id))
    warrant_path = workspace.path / "warrants" / (wid + ".warrant")
    with operator_lock(workspace.path):
        if warrant_path.exists():
            existing = load_chain(warrant_path)
            if [w.to_bytes() for w in existing] != [w.to_bytes() for w in chain]:
                raise DocumentError("stored warrant ID already has different chain bytes")
        else:
            publish(warrant_path, (encode_chain(chain) + "\n").encode())
        document = (
            read_session(workspace, session_id)
            if path.exists()
            else {"version": 1, "session_id": session_id, "warrants": []}
        )
        if wid not in document["warrants"]:
            if len(document["warrants"]) >= 64:
                raise DocumentError("session already has 64 warrants; detach an unused one first")
            document["warrants"].append(wid)
        write_yaml(path, document, replace=path.exists())
    return document


def detach(workspace, session_id, warrant_id):
    path = session_path(workspace, session_id)
    with operator_lock(workspace.path):
        document = read_session(workspace, session_id)
        document["warrants"] = [wid for wid in document["warrants"] if wid != warrant_id]
        write_yaml(path, document, replace=True)
    return document


def list_sessions(workspace):
    result = []
    for path in sorted((workspace.path / "sessions").glob("*.yaml")):
        document = load_yaml(path)
        session_id = document.get("session_id")
        if path != session_path(workspace, session_id):
            raise DocumentError("session filename does not match its identity")
        result.append(read_session(workspace, session_id))
    return result
