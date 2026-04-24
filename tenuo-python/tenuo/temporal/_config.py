"""TenuoPluginConfig — worker-level configuration for Tenuo-Temporal authorization."""

from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence

from tenuo.temporal._observability import TemporalAuditEvent, TenuoMetrics
from tenuo.temporal._resolvers import KeyResolver
from tenuo.temporal._dedup import PopDedupStore

logger = logging.getLogger("tenuo.temporal")


def _build_activity_registry(
    activity_fns: Optional[List[Callable]],
) -> Dict[str, Callable]:
    """Map Temporal activity-type name -> callable for a list of activities.

    Prefers the ``__temporal_activity_definition.name`` attached by
    ``@activity.defn``, falling back to ``fn.__name__``. Empty / ``None``
    input returns an empty dict.
    """
    registry: Dict[str, Callable] = {}
    if not activity_fns:
        return registry
    for fn in activity_fns:
        defn = getattr(fn, "__temporal_activity_definition", None)
        if defn is not None and hasattr(defn, "name"):
            registry[defn.name] = fn
        else:
            registry[getattr(fn, "__name__", str(fn))] = fn
    return registry


@dataclass
class TenuoPluginConfig:
    """Configuration for TenuoTemporalPlugin / TenuoWorkerInterceptor."""

    key_resolver: Optional[KeyResolver] = None
    """Optional — required for outbound PoP signing (most workers). Omit for
    data-plane/read-only workers that only verify inbound warrants.

    Resolves key IDs to signing keys. Used by ``tenuo_execute_activity()`` and
    the outbound workflow interceptor to reconstruct signing keys for PoP
    generation. If ``None``, the outbound interceptor raises
    ``TenuoContextError`` when PoP signing is attempted; inbound verification
    continues to work normally using ``trusted_roots`` alone.

    Provide this **or** :attr:`signing_key` (a static worker key). When both are
    set, ``key_resolver`` takes precedence.
    """

    signing_key: Optional[Any] = None
    """Optional static ``tenuo_core.SigningKey`` for single-key workers.

    When set and :attr:`key_resolver` is ``None``, a trivial resolver is
    synthesized so you do not need a custom ``KeyResolver`` subclass.
    """

    control_plane: Optional[Any] = None
    """
    Optional ControlPlaneClient for emitting authorization check results
    back to the control plane.
    """

    on_denial: Literal["raise", "log", "skip"] = "raise"
    """
    Behavior when authorization fails:
    - "raise": Raise TemporalConstraintViolation (default)
    - "log": Log denial, continue execution
    - "skip": Silent denial, return None
    """

    dry_run: bool = False
    """
    Shadow mode for integration evaluation. When True, authorization denials
    are NOT enforced: Tenuo emits denial audit/log signals but allows activity
    execution to continue. This setting is for staging and rollout validation
    only and must not be used in production.
    """

    tool_mappings: Dict[str, str] = field(default_factory=dict)
    """
    Optional explicit activity-type → warrant tool name mappings.
    Example: {"fetch_document": "read_file"} when the Temporal activity type
    differs from the tool name used in the warrant and in PoP.

    The outbound workflow interceptor applies the same mapping when signing
    PoP so verification matches the activity inbound interceptor.
    """

    audit_callback: Optional[Callable[[TemporalAuditEvent], None]] = None
    """Optional callback for authorization audit events."""

    audit_allow: bool = True
    """Whether to emit audit events for allowed actions."""

    audit_deny: bool = True
    """Whether to emit audit events for denied actions."""

    @classmethod
    def from_env(cls, **overrides: Any) -> "TenuoPluginConfig":
        """Create config from environment variables.

        Resolves ``TENUO_SIGNING_KEY`` (base64 Ed25519) for PoP generation and
        auto-connects to the control plane via ``TENUO_CONNECT_TOKEN`` (or
        ``TENUO_CONTROL_PLANE_URL`` + ``TENUO_API_KEY`` + ``TENUO_AUTHORIZER_NAME``).

        Any keyword argument overrides the env-derived value::

            config = TenuoPluginConfig.from_env(on_denial="log", dry_run=True)
        """
        import os as _os

        signing_key = overrides.pop("signing_key", None)
        if signing_key is None:
            raw = _os.environ.get("TENUO_SIGNING_KEY")
            if raw:
                from tenuo_core import SigningKey as _SK
                signing_key = _SK.from_base64(raw)

        cp = overrides.pop("control_plane", None)
        if cp is None:
            from tenuo.control_plane import get_or_create
            cp = get_or_create()

        return cls(signing_key=signing_key, control_plane=cp, **overrides)

    max_chain_depth: int = 10
    """Maximum warrant chain depth to accept."""

    block_local_activities: bool = True
    """
    Block protected activities from being used as local activities.
    Local activities bypass the worker interceptor, so protected
    activities must be marked @unprotected to run locally.
    """

    metrics: Optional["TenuoMetrics"] = None
    """
    Optional metrics collector for Prometheus.
    Pass a TenuoMetrics instance to enable metrics.
    """

    require_warrant: bool = True
    """
    Require a warrant for all activities (fail-closed).

    ``True`` (default): activities without a warrant header are denied.
    ``False``: activities without a warrant pass through without authorization.

    Setting this to ``False`` is intended only for **incremental migration**
    scenarios where some task queues or activity types have not yet been
    warranted.  Unauthenticated executions are logged at WARNING level and
    appear in audit events with ``warrant_id="none"``.  Never use in steady-state
    production — the fail-closed guarantee is the core security property.
    """

    redact_args_in_logs: bool = True
    """
    Redact argument values in logs and audit events.
    When True, argument values are replaced with "[REDACTED]".
    Prevents leaking sensitive data like passwords, tokens, etc.
    Default: True (secure by default).
    """

    trusted_roots: Optional[List[Any]] = None
    """
    Trusted issuer public keys for warrant chain-of-trust and PoP verification.

    **Required** unless you use ``trusted_roots_provider`` instead: pass at least
    one root (for example ``[control_key.public_key]`` for warrants minted by that
    key), or set global roots via ``tenuo.configure(trusted_roots=[...])``
    before building the config (empty ``trusted_roots`` falls back to global
    configuration).

    For delegated warrants, include the original root's public key so the full
    chain can be validated.

    Do not set both ``trusted_roots`` and ``trusted_roots_provider``.
    """

    trusted_roots_provider: Optional[Callable[[], Sequence[Any]]] = None
    """
    Callable that returns the current trusted issuer public keys.

    Use with ``trusted_roots_refresh_interval_secs`` to rotate roots without
    redeploying workers: return **overlapping** old + new issuer keys during
    the rotation window so in-flight warrants still verify.

    Mutually exclusive with an explicit non-empty ``trusted_roots`` list (and
    with relying on ``tenuo.configure(trusted_roots=...)`` alone — pass a
    provider that reads the same source of truth if you need refresh).
    """

    trusted_roots_refresh_interval_secs: Optional[float] = None
    """
    When set with ``trusted_roots_provider``, the activity interceptor rebuilds
    the ``Authorizer`` from the provider at most once per this interval
    (monotonic clock). ``None`` means roots are fixed after config construction
    (provider is still called once in ``__post_init__``).
    """

    pop_dedup_store: Optional[PopDedupStore] = None
    """
    Optional ``PopDedupStore`` for fleet-wide PoP deduplication.

    ``None`` uses the shared in-memory default (process-local only). For
    horizontal workers, supply e.g. a Redis-backed implementation of
    ``PopDedupStore``.
    """

    authorized_signals: Optional[List[str]] = None
    """
    When set, only signals whose name is in this list are accepted.
    Unrecognized signals are denied and logged. When None (default),
    all signals pass through (backward compatible).
    """

    authorized_updates: Optional[List[str]] = None
    """
    When set, only workflow updates whose name is in this list are
    accepted.  Unrecognized updates are rejected at the validator
    stage.  When None (default), all updates pass through.
    """

    activity_fns: Optional[List[Callable]] = None
    """
    Activity functions registered with the Worker.  When provided,
    the outbound workflow interceptor can resolve parameter names
    for transparent PoP signing even when using plain
    ``workflow.execute_activity()``.

    **Why this exists:** PoP signs ``(warrant_id, tool, sorted_args_dict, time)``.
    Warrants with **named field constraints** (e.g. ``path=Subpath("/data")``)
    require ``args_dict`` keys to match those field names.  Resolution order for
    the callable used to build ``args_dict`` is:

    1. ``input.fn`` from the Temporal Python SDK (when present)
    2. Function reference set by ``tenuo_execute_activity()``
    3. This registry: activity type name → function (from ``activity_fns``)
    4. Fallback: ``arg0``, ``arg1``, …

    Without (1)–(3), step (4) is used.  That is valid for **tool-only**
    capabilities (no per-field constraints) because signing and verification
    both use the same ``argN`` keys.  It is **incorrect** for named
    constraints: verification expects e.g. ``path``, not ``arg0``.

    **Detection:** If (4) is used and the warrant has non-empty field
    constraints for that activity type, the worker logs a **warning**; with
    ``strict_mode=True``, it raises ``TenuoContextError`` instead (fail-fast).

    **Required when:** Your warrant uses named constraints for tools you call
    with transparent ``execute_activity``, unless the SDK always provides
    ``input.fn`` in your environment (do not rely on that across versions).

    Pass the **same** list you give to ``Worker(activities=...)``.
    """

    approval_handler: Optional[Callable] = None
    """
    Callback invoked when an approval gate fires and no pre-supplied
    approvals are available in activity headers.  Receives an
    ``ApprovalRequest`` and must return a ``SignedApproval`` (or list).
    Raise ``ApprovalDenied`` to reject.

    When ``None`` (default), approval-gate-triggered calls with no pre-supplied
    approvals are denied with ``ApprovalGateTriggered``.
    """

    strict_mode: bool = False
    """
    Fail-fast on ambiguous PoP signing (e.g. positional args when the warrant
    has named field constraints).  ``trusted_roots`` is **always** required
    for Temporal workers regardless of this flag; see ``trusted_roots``.
    """

    retry_pop_max_windows: Optional[int] = 40
    """
    PoP time-window count to use for Temporal activity **retries** (attempt > 1).

    **Background:** PoP is signed at workflow schedule time using
    ``workflow.now()`` (deterministic replay clock). When Temporal retries an
    activity, it reuses the headers from the original scheduling event in
    workflow history — it does **not** re-invoke the outbound interceptor.
    With the strict ``pop_max_windows=5`` (±60 s at the verifier), an activity
    retried more than ~90 s after its first scheduling will fail PoP
    verification.

    **Default ``40`` (±1200 s ≈ ±20 min)** is sized against Temporal's default
    retry policy (``initial_interval=1s``, ``backoff_coefficient=2``,
    ``max_interval=100s``), which places the Nth retry at roughly
    ``1 + 2 + 4 + … + min(2^(N-1), 100)`` seconds. Concretely: ten retries
    land at ~800 s and fifteen retries at ~1300 s, so 20 min of slack covers
    the long-tail of flaky-backend scenarios without giving an attacker an
    hour of replay headroom. A ``PopVerificationError`` on retry becomes
    non-retryable, so too-tight a window silently turns transient failures
    into permanent ones — that is precisely what this default prevents.

    Set higher to accommodate longer retry windows:

        # 120 × 30 s = 3600 s — covers up to 1 hour of Temporal retries
        retry_pop_max_windows=120

        # 480 × 30 s = 14400 s — covers up to 4 hours
        retry_pop_max_windows=480

    **Security trade-off:** A wider window means a captured PoP is valid for
    longer on retried tasks (already a lesser concern since dedup is also
    skipped for attempt > 1).  For most deployments the correct value is
    ``ceil(max_retry_window_seconds / 30)``.

    Set to ``None`` to use the same strict window for all attempts, which
    preserves the tightest security guarantee but will cause retry failures for
    activities that retry more than ~90 s after first scheduling.
    """

    clearance_requirements: Optional[Dict[str, Any]] = None
    """
    Per-tool clearance requirements enforced during inbound authorization.

    Mapping of tool name (or glob pattern) → ``Clearance`` level. Even if a
    warrant carries the tool in its capabilities, authorization will fail if the
    warrant's clearance is below the configured requirement for that tool.

    Supports the same patterns as ``Authorizer.require_clearance()``:
    - Exact match: ``"delete_database"``
    - Prefix wildcard: ``"admin_*"`` (matches ``admin_users``, ``admin_config``)
    - Default: ``"*"`` (applies to all tools without a specific rule)

    Example::

        from tenuo_core import Clearance
        TenuoPluginConfig(
            trusted_roots=[root_key],
            clearance_requirements={
                "*": Clearance.EXTERNAL,        # baseline for every tool
                "admin_*": Clearance.PRIVILEGED,
                "send_email": Clearance.CONFIDENTIAL,
            },
        )

    ``None`` (default) means no per-tool clearance policy is applied.
    """

    revocation_list: Optional[Any] = None
    """
    Optional ``SignedRevocationList`` to check warrants against during
    inbound authorization.  Warrants whose ID appears in the list are denied
    even when the chain is otherwise valid.

    Mutually exclusive with ``revocation_list_provider`` (raises
    ``ConfigurationError`` if both are set).

    ``None`` (default) means revocation list checking is skipped.
    """

    revocation_list_provider: Optional[Callable[[], Any]] = None
    """
    Callable that returns a fresh ``SignedRevocationList``.  Called once at
    config construction time and then again every
    ``revocation_refresh_secs`` seconds (monotonic clock) by the activity
    interceptor.

    Use this instead of ``revocation_list`` when you need periodic SRL
    refresh without redeploying workers.

    ``None`` (default) disables provider-based SRL refresh.
    """

    revocation_refresh_secs: Optional[int] = None
    """
    How often (in seconds) to refresh the SRL via ``revocation_list_provider``.
    ``None`` means the provider is called once at startup and not again.

    Requires ``revocation_list_provider`` to be set; ignored otherwise.
    """

    def __post_init__(self) -> None:
        if self.dry_run:
            logger.warning(
                "TenuoPluginConfig: dry_run=True enables shadow mode and "
                "does not enforce authorization denials. Do not use in production."
            )
            warnings.warn(
                "TenuoPluginConfig: dry_run=True — authorization denials will NOT be "
                "enforced. This is a shadow/staging mode; remove dry_run=True before "
                "deploying to production.",
                stacklevel=2,
            )

        if not self.require_warrant:
            logger.warning(
                "TenuoPluginConfig: require_warrant=False — activities without a warrant "
                "will be allowed through without any authorization check. This disables "
                "the fail-closed guarantee. Only use for opt-in migration scenarios."
            )
            warnings.warn(
                "TenuoPluginConfig: require_warrant=False — unwarranted activity "
                "executions will be allowed. Ensure this is intentional.",
                stacklevel=2,
            )

        # Trusted roots are mandatory: explicit list, provider, or global configure().
        if self.trusted_roots_provider is not None:
            if self.trusted_roots:
                from tenuo.exceptions import ConfigurationError
                raise ConfigurationError(
                    "TenuoPluginConfig: pass either trusted_roots= or "
                    "trusted_roots_provider=, not both."
                )
            roots = list(self.trusted_roots_provider())
        elif self.trusted_roots:
            roots = list(self.trusted_roots)
        else:
            from tenuo.config import resolve_trusted_roots as _resolve_tr
            _merged = _resolve_tr(None)
            roots = list(_merged) if _merged else []
        if not roots:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "TenuoPluginConfig requires trusted_roots (issuer public keys). "
                "Pass trusted_roots=[control_key.public_key], trusted_roots_provider=..., "
                "or call tenuo.configure(trusted_roots=[...]) at application startup."
            )
        self.trusted_roots = roots  # type: ignore[assignment]

        if self.signing_key is not None and self.key_resolver is None:

            class _StaticSigningKeyResolver(KeyResolver):
                def __init__(self, sk: Any) -> None:
                    self._sk = sk

                async def resolve(self, key_id: str) -> Any:  # noqa: ARG002
                    return self._sk

                def resolve_sync(self, key_id: str) -> Any:  # noqa: ARG002
                    return self._sk

            self.key_resolver = _StaticSigningKeyResolver(self.signing_key)

        if self.key_resolver is None:
            from tenuo.exceptions import ConfigurationError

            raise ConfigurationError(
                "TenuoPluginConfig requires key_resolver= or signing_key= (worker signing material)."
            )

        if self.approval_handler is not None:
            # Only bump for values at-or-below the field default (currently 40).
            # Users who explicitly set a larger value are respected. The bound
            # tracks the default so raising the default in the future does not
            # silently suppress this auto-widen.
            if self.retry_pop_max_windows is None or self.retry_pop_max_windows <= 40:
                logger.info(
                    "TenuoPluginConfig: approval_handler set — retry_pop_max_windows=%s is tight for "
                    "human-in-the-loop; using 240 (~2 h PoP slack on activity retries). "
                    "Set retry_pop_max_windows explicitly to override.",
                    self.retry_pop_max_windows,
                )
                self.retry_pop_max_windows = 240

        if self.trusted_roots_refresh_interval_secs is not None:
            if self.trusted_roots_refresh_interval_secs <= 0:
                from tenuo.exceptions import ConfigurationError
                raise ConfigurationError(
                    "trusted_roots_refresh_interval_secs must be positive when set."
                )
            if self.trusted_roots_provider is None:
                from tenuo.exceptions import ConfigurationError
                raise ConfigurationError(
                    "trusted_roots_refresh_interval_secs requires trusted_roots_provider."
                )

        # ``authorized_signals=[]`` / ``authorized_updates=[]`` would silently
        # deny every signal / update (the allowlist is enforced iff the field
        # is not ``None``, and nothing is "in []"). That's a UX footgun for
        # operators who pass ``[]`` to mean "no restriction" — make the
        # mistake impossible by rejecting it at config time. Use ``None`` to
        # disable the allowlist, or list the names you want to accept.
        if self.authorized_signals is not None and len(self.authorized_signals) == 0:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "authorized_signals=[] would deny every signal. Use "
                "authorized_signals=None to disable the allowlist, or list "
                "the signal names to accept."
            )
        if self.authorized_updates is not None and len(self.authorized_updates) == 0:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "authorized_updates=[] would deny every update. Use "
                "authorized_updates=None to disable the allowlist, or list "
                "the update names to accept."
            )

        self._activity_registry: Dict[str, Callable] = _build_activity_registry(
            self.activity_fns
        )
