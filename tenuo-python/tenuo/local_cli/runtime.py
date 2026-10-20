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

    The controller's and approver's private keys are never read here. A malformed
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
            if self._last_srl is not None:
                authorizer.set_revocation_list(self._last_srl)
            authorizer.set_revocation_list(candidate)
            self._last_srl = candidate
        chain = load_chain(self.warrant) if self.warrant is not None else []
        if chain:
            authorizer.verify_chain(chain)
        key = self.workspace.signing_key(self.key_name) if self.key_name is not None else None
        if chain and (key is None or bytes(key.public_key.to_bytes()) != bytes(chain[-1].holder_key.to_bytes())):
            raise DocumentError("selected warrant does not match the configured agent key")
        return Snapshot(roots, candidate, authorizer, chain, key)

    def approval_handler(self, snapshot):
        from tenuo.approval import ApprovalRequired
        from .approvals import request_document, response_approval

        def collect(request):
            # Verify against current trust and revocations even after a wait.
            current = self.snapshot()
            document = request_document(snapshot.chain, request.tool, request.arguments)
            digest = document["request_hash"]
            response = self.workspace.path / "approvals" / (digest + ".yaml")
            if response.exists():
                return response_approval(document, load_yaml(response), current.authorizer)
            path = self.workspace.path / "requests" / (digest + ".yaml")
            try:
                write_yaml(path, document)
            except FileExistsError:
                if load_yaml(path) != document:
                    raise DocumentError("existing approval request does not match this call") from None
            pending = ApprovalRequired(request)
            pending.args = (
                f"Approval required for {request.tool}. Review with tenuo-cli approval show --file {path}; "
                f"return the signed response to {response}, then retry.",
            )
            raise pending

        return collect

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
