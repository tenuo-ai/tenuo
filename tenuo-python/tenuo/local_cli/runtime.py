"""Read local authority before each protected call, without a signing service."""

from __future__ import annotations

import sys
import threading
import logging
from contextlib import contextmanager
from dataclasses import dataclass

from .files import DocumentError, load_yaml, publish, read_revocation_list, write_yaml
from .workspace import Workspace


@dataclass
class Snapshot:
    roots: list
    srl: object
    authorizer: object
    chain: list
    key: object


class LocalAuthority:
    """One explicit warrant file, independent public trust, and an agent key.

    The issuer's and approver's private keys are never read here. A malformed
    configured file denies the current call rather than retaining old authority.
    """

    def __init__(self, *, path=None, warrant=None, key="agent", announce=True):
        from pathlib import Path

        self.workspace = Workspace(path)
        self.warrant = Path(warrant).expanduser() if warrant is not None else None
        self.key_name = key
        self._last_srl = None
        self._lock = threading.Lock()
        snapshot = self.snapshot()
        label = str(snapshot.chain[-1].id) if snapshot.chain else "inbound verification"
        dev = " (development identities)" if self.workspace.config["dev_roots"] else ""
        if announce:
            print(
                f"Tenuo: enforce · {label} · trusts {len(snapshot.roots)} root(s){dev} · revocations v{snapshot.srl.version}",
                file=sys.stderr,
            )

    def snapshot(self):
        from tenuo import Authorizer
        from .warrants import load_chain

        config = self.workspace.config
        if config["mode"] != "enforce":
            raise DocumentError("local file adapters currently require mode: enforce")
        with self._lock:
            roots = self.workspace.trusted_roots()
            candidate = read_revocation_list(self.workspace.path / "revocations.srl")
            authorizer = Authorizer(trusted_roots=roots)
            authorizer.set_clock_tolerance(0)
            authorizer.set_revocation_list(candidate)
            if self._last_srl is not None:
                # The cached issuer may have been rotated out. It is used only
                # to check the version floor, never as a live warrant root.
                floor = Authorizer(trusted_roots=[*roots, self._last_srl.issuer])
                floor.set_revocation_list(self._last_srl)
                floor.set_revocation_list(candidate)
            self._last_srl = candidate
        chain = load_chain(self.warrant) if self.warrant is not None else []
        if chain:
            authorizer.verify_chain(chain)
        key = self.workspace.signing_key(self.key_name) if self.key_name is not None else None
        if chain and (key is None or bytes(key.public_key.to_bytes()) != bytes(chain[-1].holder_key.to_bytes())):
            raise DocumentError("selected warrant does not match the configured agent key")
        return Snapshot(roots, candidate, authorizer, chain, key)

    def approval_handler(self, snapshot):
        def collect(request):
            return self.collect_file_approval(snapshot.chain, request)

        return collect

    def collect_file_approval(self, chain, request):
        """Return the signed approval for this exact call, or write its request file."""
        from .approvals import request_document, response_approval

        # Verify against current trust and revocations even after a wait.
        current = self.snapshot()
        current.authorizer.verify_chain(list(chain))
        document = request_document(chain, request.tool, request.arguments)
        digest = document["request_hash"]
        if digest != bytes(request.request_hash).hex():
            raise DocumentError("approval request does not match the warrant chain it carries")
        response = self.workspace.path / "approvals" / (digest + ".yaml")
        if response.exists():
            return response_approval(document, load_yaml(response), current.authorizer)
        path = self.workspace.path / "requests" / (digest + ".yaml")
        try:
            write_yaml(path, document)
        except FileExistsError:
            if load_yaml(path) != document:
                raise DocumentError("existing approval request does not match this call") from None
        _pending(
            request,
            f"Approval required for {request.tool}. Review with tenuo-cli approval show --file {path}; "
            f"return the signed response to {response}, then retry.",
        )

    @contextmanager
    def scope(self, snapshot=None):
        from tenuo import HolderIdentity, Runtime
        from tenuo.receipts import FileReceiptSink

        snapshot = self.snapshot() if snapshot is None else snapshot
        if snapshot.key is None:
            yield snapshot, None, None
            return
        runtime = Runtime(
            HolderIdentity(snapshot.key), trusted_roots=snapshot.roots, revocation_list=snapshot.srl, receipts="collect"
        )
        receipt_path = self.workspace.path / self.workspace.config["audit"]["receipts"]
        if not receipt_path.exists():
            try:
                publish(receipt_path, b"")
            except FileExistsError:
                pass
        sink = FileReceiptSink(receipt_path)
        try:
            with runtime.bind():
                if snapshot.chain:
                    with runtime.session_from_wire(snapshot.chain) as session:
                        yield snapshot, session, self.approval_handler(snapshot)
                else:
                    yield snapshot, None, None
        finally:
            receipts = runtime.drain_receipts()
            try:
                for receipt in receipts:
                    sink.handle(receipt)
            except Exception:
                # Never turn a completed effect into a retry because audit I/O
                # failed, or mask an original authorization/tool exception.
                logging.getLogger(__name__).warning("Local receipt persistence failed", exc_info=True)
            else:
                runtime.acknowledge_receipts(len(receipts))


def _pending(request, message):
    from tenuo.approval import ApprovalRequired

    try:
        from temporalio import activity
        from temporalio.exceptions import ApplicationError

        in_activity = activity.in_activity()
    except ImportError:
        in_activity = False
    if in_activity:
        # Temporal retries the activity until the response file exists or the
        # warrant expires; no worker slot is held while a person decides.
        raise ApplicationError(message, type="ApprovalPending", non_retryable=False)
    pending = ApprovalRequired(request)
    pending.args = (message,)
    raise pending


def file_approval_handler(path=None):
    """An approval handler that exchanges approval files in a local workspace.

    The handler writes ``requests/<hash>.yaml`` for a gated call and returns the
    signed approval once ``approvals/<hash>.yaml`` holds a response from an
    approver the warrant names (``tenuo-cli approval approve --file ...``). The
    chain travels with each request, so one handler serves every warrant; it is
    checked against the workspace's current trust and revocations. The handler
    reads no private keys.

    While waiting it raises ``ApprovalRequired``, or inside a Temporal activity a
    retryable ``ApplicationError`` of type ``ApprovalPending``.
    """
    authority = LocalAuthority(path=path, key=None, announce=False)

    def handler(request):
        chain = getattr(request, "warrant_chain", None)
        if not chain:
            raise DocumentError("approval request carries no warrant chain, so an approver cannot verify it")
        return authority.collect_file_approval(list(chain), request)

    return handler
