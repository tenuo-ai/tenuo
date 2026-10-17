"""Inspect native signed receipts, reusing the existing SDK verifier."""

from __future__ import annotations

import io
import tempfile
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from .files import DocumentError, load_public_key

MAX_AUDIT_BYTES = 64 * 1024 * 1024


def read_audit(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_AUDIT_BYTES + 1)
    if len(raw) > MAX_AUDIT_BYTES:
        raise DocumentError("audit exceeds 64 MiB; inspect a rotated file with --file")
    return raw


def records(raw):
    from tenuo import parse_strict_json
    from tenuo_core import decode_warrant_stack_base64, verify_receipt

    result = []
    for line in raw.decode().splitlines():
        if not line.strip():
            continue
        document = parse_strict_json(line)
        if not isinstance(document, dict) or set(document) != {"receipt"}:
            raise DocumentError("expected native FileReceiptSink JSONL records")
        payload = verify_receipt(document["receipt"])
        chain = list(decode_warrant_stack_base64(payload.warrant_chain))
        result.append(
            (
                payload,
                {
                    "decision": payload.outcome.upper(),
                    "tool": payload.action,
                    "warrant_id": str(chain[-1].id) if chain else None,
                    "decided_at": datetime.fromtimestamp(payload.timestamp, timezone.utc).isoformat(),
                    "reason": payload.decision_code,
                    "signer": payload.signer_key[:16],
                    "previous_receipt": payload.prev_receipt_hash,
                    "revocation_version": payload.srl_version,
                },
            )
        )
    return result


def inspect_audit(
    workspace, *, path=None, verify=False, authorizers=None, warrant=None, denied=False, since=None, limit=100
):
    path = path or workspace.path / workspace.config["audit"]["receipts"]
    raw = read_audit(path)
    try:
        decoded = records(raw)
    except Exception:
        if verify:
            return {
                "valid": False,
                "error": "Receipt stream is malformed or a signature does not verify",
                "exit_code": 3,
            }
        raise
    keys = (
        [workspace.public_key(value) for value in authorizers]
        if authorizers
        else [load_public_key(p) for p in sorted((workspace.path / "keys").glob("*.pub"))]
    )
    known = {bytes(key.to_bytes()).hex() for key in keys}
    if verify:
        from tenuo.cli import verify_receipt_chain

        if not known:
            raise DocumentError("no recognized receipt signer; supply --authorizer NAME_OR_PUBLIC_KEY_FILE")
        # Verify one stable snapshot through the existing SDK chain helper.
        with tempfile.NamedTemporaryFile() as snapshot, redirect_stdout(io.StringIO()) as output:
            snapshot.write(raw)
            snapshot.flush()
            valid = verify_receipt_chain(snapshot.name, authorizers=sorted(known))
        return {
            "valid": valid,
            "receipts": len(decoded),
            "unlinked_receipts": sum(payload.prev_receipt_hash is None for payload, _ in decoded),
            "history_completeness": "not proven",
            "message": "Checks signed decisions and any recorded links, not completed effects or an undeleted history",
            "details": output.getvalue().strip(),
            "exit_code": 0 if valid else 3,
        }
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise DocumentError("limit must be between 1 and 10000")
    if since is not None:
        try:
            since = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if since.tzinfo is None:
                raise ValueError
        except ValueError:
            raise DocumentError("--since needs a timezone-qualified ISO timestamp") from None
    rows = []
    for payload, row in decoded:
        if warrant and row["warrant_id"] != warrant:
            continue
        if denied and row["decision"] != "DENY":
            continue
        if since and payload.timestamp < since.timestamp():
            continue
        row["signer_recognized"] = payload.signer_key.lower() in known
        rows.append(row)
    return {"decisions": rows[-limit:], "matching_decisions": len(rows)}
