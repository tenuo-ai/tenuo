"""What every single-request warrant exchange shares, whatever proved who is asking.

Internal. A caller presents a credential (a JWT-SVID, a header from a trusted
proxy, an OAuth access token) and a statement signed by its holder key. The
modules for each kind of credential turn the credential into an identity.
Everything after that is the same and lives here: checking the holder's
statement, refusing a replay, asking the application's policy, minting a
warrant that ends no later than the credential, and the audit record.

:mod:`tenuo.spiffe`, :mod:`tenuo.spiffe_jwt`, :mod:`tenuo.spiffe_forwarded`
and :mod:`tenuo.oauth` are built on this, so their limits and failure
behaviour cannot drift apart.
"""

from __future__ import annotations

import hashlib
import heapq
import logging
import math
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Tuple, Type

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tenuo import Authorizer, PublicKey, SigningKey, Warrant

PROOF_SECONDS = 60  # Accepted distance between a proof's timestamp and the issuer's clock.
PROOF_MEMORY = 16384  # Default number of live proofs remembered to refuse an exact replay.
NONCE_BYTES = 16
MAX_TASK_ID = 256


class IssuanceError(ValueError):
    """A request was refused. Each credential family raises its own subclass."""


class IssuanceBusy(IssuanceError):
    """A limit was reached or a dependency is unavailable. The request may be tried again."""


class _CallbackFailed(Exception):
    """A policy or audit callback raised. The cause is chained."""


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _seconds(name: str, value: Any) -> float:
    """A positive, finite number of seconds. NaN and infinity would switch a limit off without saying so."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return float(value)


def _run_callback(callback: Callable[..., Any], *arguments: Any) -> Any:
    """Call a policy or audit callback, marking whatever it raises as the callback's own failure.

    The exception still reaches a direct caller unchanged. The bundled
    endpoints read the mark: a callback may raise anything, a refusal type
    included, and that is the issuer failing, not the caller being refused.
    """
    try:
        return callback(*arguments)
    except Exception as exc:
        try:
            exc._tenuo_callback_failure = True  # type: ignore[attr-defined]
        except AttributeError:
            raise _CallbackFailed() from exc  # An exception type that takes no attributes.
        raise


def _from_callback(exc: BaseException) -> bool:
    return getattr(exc, "_tenuo_callback_failure", False) is True


def _consume_result(work: Any) -> None:
    """Retrieve a shielded result nobody awaited, so it is not logged as unhandled."""
    if not work.cancelled():
        work.exception()


@dataclass(frozen=True)
class HolderProof:
    """A holder key's signed statement for one single-request exchange."""

    timestamp: int
    nonce: bytes
    signature: bytes


def _checked_warrant(
    encoded: Any, trusted: List[PublicKey], holder_key: SigningKey, error: Type[IssuanceError] = IssuanceError
) -> Warrant:
    """Accept an issuer's reply only if it is a current warrant from a trusted key for this holder."""
    if not isinstance(encoded, str):
        raise error("Invalid warrant response")
    try:
        warrant = Warrant.from_base64(encoded)
        Authorizer(trusted_roots=trusted).verify(warrant)
    except Exception as exc:
        raise error("Issued warrant failed verification") from exc
    if warrant.authorized_holder != holder_key.public_key:
        raise error("Issued warrant is bound to a different holder")
    return warrant


# -- remembering proofs -------------------------------------------------------

CLAIMED, USED, TOO_OLD, FULL, OWNER_FULL = "claimed", "used", "too old", "full", "owner full"


class ProofStore(Protocol):
    """Remembers holder proofs, so the same signed request cannot be served twice.

    ``claim`` reserves ``key`` for ``owner`` until the wall clock passes
    ``keep_until`` and returns one of ``CLAIMED``, ``USED`` (already there),
    ``TOO_OLD`` (it would already have been forgotten, which only happens when
    the clock was set back), ``FULL`` or ``OWNER_FULL``. It must be atomic
    across everything that shares the store. ``release`` forgets a proof whose
    request did not end in a warrant, so a denied or failed request leaves
    nothing behind and can be retried.
    """

    def claim(self, key: str, keep_until: float, owner: str) -> str: ...

    def release(self, key: str) -> None: ...


def _share(capacity: int, per_owner: Optional[int]) -> int:
    if not _positive_int(capacity) or capacity < 1:
        raise ValueError("capacity must be a positive integer")
    if per_owner is None:
        return max(1, capacity // 4)
    if not _positive_int(per_owner) or not 1 <= per_owner <= capacity:
        raise ValueError("the share of one identity must be a positive integer, at most the capacity")
    return per_owner


class MemoryProofStore:
    """Proofs remembered by one process. Replicas each keep their own."""

    def __init__(self, capacity: int = PROOF_MEMORY, per_owner: Optional[int] = None):
        self.per_owner = _share(capacity, per_owner)
        self.capacity = capacity
        # Each proof: until when it is kept, and whose it is. The heap orders them by
        # that time; one released early stays in the heap until it is skipped.
        self._entries: Dict[str, Tuple[float, str]] = {}
        self._order: List[Tuple[float, str]] = []
        self._held: Dict[str, int] = {}
        self._forgotten_to = float("-inf")
        self._lock = threading.Lock()

    def _forget(self, key: str) -> None:
        entry = self._entries.pop(key, None)
        if entry is None:
            return
        held = self._held[entry[1]] - 1
        if held:
            self._held[entry[1]] = held
        else:
            del self._held[entry[1]]

    def claim(self, key: str, keep_until: float, owner: str) -> str:
        with self._lock:
            now, order = time.time(), self._order
            self._forgotten_to = max(self._forgotten_to, now)
            while order and order[0][0] <= now:
                until, expired = heapq.heappop(order)
                entry = self._entries.get(expired)
                if entry is not None and entry[0] == until:
                    self._forget(expired)
            if len(order) > 2 * len(self._entries) + 1024:  # Mostly entries released early: rebuild.
                self._order = [(until, name) for name, (until, _) in self._entries.items()]
                heapq.heapify(self._order)
            if keep_until <= self._forgotten_to:
                return TOO_OLD
            if key in self._entries:
                return USED
            if len(self._entries) >= self.capacity:
                return FULL
            if self._held.get(owner, 0) >= self.per_owner:
                return OWNER_FULL
            self._entries[key] = (keep_until, owner)
            self._held[owner] = self._held.get(owner, 0) + 1
            heapq.heappush(self._order, (keep_until, key))
            return CLAIMED

    def release(self, key: str) -> None:
        with self._lock:
            self._forget(key)


class SQLiteProofStore:
    """Proofs remembered in a file, shared by the processes on one host and kept across restarts.

    Not for a network filesystem. Issuers on several hosts need a store of
    their own that claims atomically across all of them.
    """

    def __init__(self, path: str, *, capacity: int = 100000, per_owner: Optional[int] = None):
        if path == ":memory:":
            raise ValueError("The proof store needs a file")
        self.per_owner = _share(capacity, per_owner)
        self.capacity, self.path = capacity, str(Path(path))
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS proofs (key TEXT PRIMARY KEY, expires REAL NOT NULL, owner TEXT)")
            db.execute("CREATE INDEX IF NOT EXISTS proofs_owner ON proofs (owner)")
            # Each claim removes what has expired while it holds the write lock: found by index, not by a scan.
            db.execute("CREATE INDEX IF NOT EXISTS proofs_expires ON proofs (expires)")
            db.execute("CREATE TABLE IF NOT EXISTS forgotten (one INTEGER PRIMARY KEY CHECK (one = 1), until REAL)")
            db.execute("INSERT OR IGNORE INTO forgotten VALUES (1, 0)")

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        """One connection for one transaction: committed or rolled back, then closed."""
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def claim(self, key: str, keep_until: float, owner: str) -> str:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            now = time.time()
            db.execute("UPDATE forgotten SET until = MAX(until, ?)", (now,))
            db.execute("DELETE FROM proofs WHERE expires <= ?", (now,))
            if keep_until <= db.execute("SELECT until FROM forgotten").fetchone()[0]:
                return TOO_OLD
            if db.execute("SELECT 1 FROM proofs WHERE key = ?", (key,)).fetchone():
                return USED
            if db.execute("SELECT COUNT(*) FROM proofs").fetchone()[0] >= self.capacity:
                return FULL
            if db.execute("SELECT COUNT(*) FROM proofs WHERE owner = ?", (owner,)).fetchone()[0] >= self.per_owner:
                return OWNER_FULL
            db.execute("INSERT INTO proofs VALUES (?, ?, ?)", (key, keep_until, owner))
        return CLAIMED

    def release(self, key: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM proofs WHERE key = ?", (key,))


# -- the exchange itself ------------------------------------------------------


@dataclass(frozen=True)
class Wording:
    """The refusals whose words depend on what kind of caller this is."""

    denied: str = "Not authorized for this task"
    ends_too_soon: str = "The credential expires too soon to issue a warrant"
    outlives: str = "Warrant would outlive the credential it was issued for"
    who: str = "caller"


class SingleRequestIssuer:
    """Holder proof, replay memory, policy, mint and audit for one credential family.

    ``refused`` and ``busy`` are the family's own exception types, so its
    callers catch what its guide names. ``validate`` checks what the policy
    returned and gives back an object with ``capabilities``, ``ttl_seconds``,
    ``max_depth`` and optionally ``expires_at``. ``record`` builds the audit
    record from (identity, task ID, holder key in hex, warrant, grant).
    """

    def __init__(
        self,
        *,
        signing_key: SigningKey,
        policy: Callable[[Any, str], Any],
        audit: Optional[Callable[[Any], None]],
        store: ProofStore,
        refused: Type[IssuanceError],
        busy: Type[IssuanceError],
        validate: Callable[[Any], Any],
        record: Callable[[Any, str, str, Warrant, Any], Any],
        wording: Wording = Wording(),
        max_ttl_seconds: Optional[int] = None,
        logger: Optional[logging.Logger] = None,
        unusable_grant_is_issuer_fault: bool = False,
    ):
        # A grant the policy returned that cannot be used: with this set, the
        # endpoints answer as for a callback that raised (the caller can do
        # nothing about it). Without it, the caller is told the reason, which
        # is what the SPIFFE endpoints have always done.
        self._grant_fault = unusable_grant_is_issuer_fault
        self.signing_key, self.policy, self.audit, self.store = signing_key, policy, audit, store
        self._refused, self._busy, self._validate, self._record = refused, busy, validate, record
        self._wording, self._max_ttl = wording, max_ttl_seconds
        self._log = logger or logging.getLogger("tenuo.issuance")

    def grant(self, identity: Any, owner: str, task_id: str) -> Any:
        """Ask the policy. Its answer is validated before anything is built on it."""
        grant = _run_callback(self.policy, identity, task_id)
        if grant is None:
            raise self._refused(self._wording.denied)
        try:
            return self._validate(grant)
        except IssuanceError as exc:
            self._log.warning("Invalid policy grant for %s task %r: %s", owner, task_id, exc)
            if self._grant_fault:
                exc._tenuo_callback_failure = True  # type: ignore[attr-defined]
            raise

    def check_request(self, holder: Any, task_id: Any) -> None:
        if not isinstance(task_id, str) or not task_id or len(task_id) > MAX_TASK_ID:
            raise self._refused(f"task_id must contain 1–{MAX_TASK_ID} characters")
        try:
            task_id.encode("utf-8")
        except UnicodeEncodeError:  # A lone surrogate, which JSON can carry and no signed statement can.
            raise self._refused("task_id must be valid Unicode text") from None
        if not isinstance(holder, PublicKey):
            raise self._refused("holder must be a Tenuo PublicKey")

    def issue(
        self,
        identity: Any,
        *,
        owner: str,
        expires_at: float,
        holder: PublicKey,
        task_id: str,
        proof: Any,
        statement: Callable[[bytes, int, bytes], bytes],
    ) -> Warrant:
        """Check the holder's signed statement, then policy, then mint."""
        refused = self._refused
        self.check_request(holder, task_id)
        if not isinstance(proof, HolderProof):
            raise refused("Invalid holder proof")
        timestamp, nonce, signature = proof.timestamp, proof.nonce, proof.signature
        if not _positive_int(timestamp) or not 0 <= timestamp < 2**40 or abs(time.time() - timestamp) > PROOF_SECONDS:
            raise refused("Holder proof is too old or from the future; check the clocks on both sides")
        if (
            not isinstance(nonce, bytes)
            or len(nonce) != NONCE_BYTES
            or not isinstance(signature, bytes)
            or len(signature) != 64
        ):
            raise refused("Invalid holder proof")
        key = bytes(holder.to_bytes())
        message = statement(key, timestamp, nonce)
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        except (InvalidSignature, ValueError) as exc:
            raise refused("Invalid holder proof") from exc
        # Refuse an exact replay. The proof is reserved while the request runs and
        # kept only if a warrant is issued, so a denied or failed request leaves
        # nothing behind and can be retried. It is named by what was signed, and
        # kept until the wall clock passes the last moment its timestamp is
        # acceptable: the same clock that judged freshness above.
        claimed = hashlib.sha256(message).hexdigest()
        outcome = self.store.claim(claimed, float(timestamp + PROOF_SECONDS + 1), owner)
        if outcome == TOO_OLD:
            raise refused("Holder proof is too old or from the future; check the clocks on both sides")
        if outcome == USED:
            raise refused("This holder proof was already used; sign a new one")
        if outcome == FULL:
            raise self._busy("Issuer is at its limit for recent single-request exchanges; retry shortly")
        if outcome == OWNER_FULL:
            raise self._busy(
                f"This {self._wording.who} is at its limit for recent single-request exchanges; retry shortly"
            )
        try:
            return self.mint(identity, owner, expires_at, key, task_id, self.grant(identity, owner, task_id))
        except BaseException:
            self.store.release(claimed)
            raise

    def mint(self, identity: Any, owner: str, expires_at: float, holder: bytes, task_id: str, grant: Any) -> Warrant:
        """Mint a validated grant for a proven holder key, ending no later than the credential or the approval."""
        approval = getattr(grant, "expires_at", None)
        ends = expires_at if approval is None else min(expires_at, approval)
        ttl = min(grant.ttl_seconds, int(ends - time.time()) - 1, self._max_ttl or grant.ttl_seconds)
        if ttl < 1:
            raise self._refused(self._wording.ends_too_soon)
        builder = Warrant.mint_builder().holder(PublicKey.from_bytes(holder)).ttl(ttl).max_depth(grant.max_depth)
        for tool, constraints in grant.capabilities.items():
            builder.capability(tool, dict(constraints))
        warrant = builder.mint(self.signing_key)
        if datetime.fromisoformat(warrant.expires_at()).timestamp() > ends:
            raise self._refused(self._wording.outlives)
        if self.audit is not None:
            _run_callback(self.audit, self._record(identity, task_id, holder.hex(), warrant, grant))
        self._log.info("Issued warrant %s to %s for task %r", warrant.id, owner, task_id)
        return warrant
