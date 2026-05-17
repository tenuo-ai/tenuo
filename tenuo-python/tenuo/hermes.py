"""
Tenuo Hermes Agent Integration

Provides warrant-based authorization for Hermes Agent tool calls via the
Hermes plugin hook system.

Primary usage is through the hermes-tenuo plugin package (pip install hermes-tenuo).
HermesGuard can also be used directly for programmatic setups.

Architecture:
    Every Hermes tool call flows through handle_function_call() in model_tools.py,
    which fires pre_tool_call hooks before dispatch and post_tool_call hooks after.
    HermesGuard.pre_tool_call() enforces the warrant; post_tool_call() emits audit
    events to Tenuo Cloud.

Audit-first on-ramp:
    Set TENUO_CONNECT_TOKEN to start streaming tool calls to Cloud immediately.
    Enforcement activates once TENUO_WARRANT is set (or warrant= is passed directly).
    Cloud's warrant builder learns from real call patterns and generates tight warrants.

    Install:
        pip install hermes-tenuo

    Minimal config (~/.hermes/config.yaml):
        plugins:
          enabled:
            - hermes-tenuo
          entries:
            hermes-tenuo:
              connect_token: tc_live_...

Security invariants:
    - Agents are warrant consumers, never warrant requesters.
    - TENUO_WARRANT must not be set from within agent tool context.
    - Child warrants for delegate_task subagents are pre-registered by the
      plugin before delegate_task runs, keyed by (parent_session_id, task_index).
    - Children inherit the child_warrant config or an attenuated warrant —
      never the parent's root warrant.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from tenuo._version_compat import check_hermes_compat

check_hermes_compat()

logger = logging.getLogger("tenuo.hermes")


# ---------------------------------------------------------------------------
# Audit event
# ---------------------------------------------------------------------------

@dataclass
class HermesAuditEvent:
    """Record of a single authorization decision."""
    tool: str
    args: Dict[str, Any]
    decision: str           # "ALLOW" | "DENY" | "AUDIT"
    reason: str
    session_id: str = ""
    task_id: str = ""
    tool_call_id: str = ""
    duration_ms: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


AuditCallback = Callable[[HermesAuditEvent], None]


# ---------------------------------------------------------------------------
# HermesGuard
# ---------------------------------------------------------------------------

class HermesGuard:
    """
    Authorization guard for Hermes Agent tool calls.

    Wires into Hermes's pre_tool_call and post_tool_call plugin hooks.
    In audit-only mode (no warrant configured), every tool call is logged
    to Tenuo Cloud for warrant builder learning. Enforcement activates
    once a warrant is present.

    Session warrant registry supports per-session warrants for multi-user
    gateway deployments (different warrant per Telegram/Discord user).

    delegate_task interception: when tool_name == "delegate_task", the guard
    pre-registers attenuated child warrants keyed by (parent_session_id, task_index)
    so children never inherit the parent's root authority.
    """

    def __init__(
        self,
        warrant: Optional[Any] = None,
        signing_key: Optional[Any] = None,
        *,
        child_warrant: Optional[Any] = None,
        trusted_roots: Optional[List[Any]] = None,
        on_denial: str = "block",   # "block" | "log"
        audit_callback: Optional[AuditCallback] = None,
    ):
        self._static_warrant = warrant
        self._static_signing_key = signing_key
        self._child_warrant = child_warrant
        self._trusted_roots = trusted_roots
        self._on_denial = on_denial
        self._audit_callback = audit_callback

        # Session warrant registry: session_id → (warrant, signing_key)
        self._session_warrants: Dict[str, Tuple[Any, Optional[Any]]] = {}
        self._session_lock = threading.Lock()

        # Primary session tracking for child warrant heuristic
        # (on_session_start is not fired by Hermes — see _resolve_warrant)
        self._primary_session_id: Optional[str] = None
        self._primary_lock = threading.Lock()

        # Pending child warrants: (parent_session_id, task_index) → warrant
        self._pending_child_warrants: Dict[Tuple[str, int], Any] = {}
        self._pending_lock = threading.Lock()

        # Per-parent child counter for task_index assignment
        self._child_counters: Dict[str, int] = {}
        self._counter_lock = threading.Lock()

        # Connect to control plane (auto-discovers from env if not already connected)
        from tenuo.control_plane import get_or_create
        self._control_plane = get_or_create()

    @property
    def has_warrant(self) -> bool:
        return self._static_warrant is not None

    # ------------------------------------------------------------------
    # Session warrant management (gateway multi-user)
    # ------------------------------------------------------------------

    def set_session_warrant(
        self,
        session_id: str,
        warrant: Any,
        signing_key: Optional[Any] = None,
    ) -> None:
        with self._session_lock:
            self._session_warrants[session_id] = (warrant, signing_key)
        logger.debug("hermes-tenuo: registered warrant for session %s", session_id)

    def clear_session_warrant(self, session_id: str) -> None:
        with self._session_lock:
            self._session_warrants.pop(session_id, None)

    def _resolve_warrant(
        self, session_id: str
    ) -> Tuple[Optional[Any], Optional[Any]]:
        """Return (warrant, signing_key) for a session.

        Resolution order:
        1. Explicit session warrant (set via set_session_warrant — gateway use case)
        2. Child warrant fallback — if child_warrant is configured and session_id
           is not the primary session, treat as a subagent session. This works
           because on_session_start is not currently fired by Hermes (it is in
           VALID_HOOKS but has no invoke_hook call), so child warrants cannot be
           pre-injected per-session at start time. Instead we detect child sessions
           heuristically: the first session_id seen is treated as the primary session;
           all subsequent different session_ids are child sessions.
        3. Static warrant from plugin config (fallback for primary session)
        """
        with self._session_lock:
            entry = self._session_warrants.get(session_id)
        if entry is not None:
            return entry

        if self._child_warrant is not None:
            with self._primary_lock:
                if self._primary_session_id is None and session_id:
                    # First session seen — record as primary
                    self._primary_session_id = session_id
                elif self._primary_session_id != session_id and session_id:
                    # Different session_id → child/subagent session
                    return self._child_warrant, self._static_signing_key

        return self._static_warrant, self._static_signing_key

    # ------------------------------------------------------------------
    # delegate_task child warrant pre-registration
    # ------------------------------------------------------------------

    def _register_child_warrants(
        self, parent_session_id: str, task_count: int
    ) -> None:
        """Pre-register attenuated warrants for upcoming child sessions."""
        if not self._child_warrant:
            return
        with self._pending_lock:
            for i in range(task_count):
                key = (parent_session_id, i)
                self._pending_child_warrants[key] = self._child_warrant
        logger.debug(
            "hermes-tenuo: pre-registered %d child warrant(s) for session %s",
            task_count, parent_session_id,
        )

    def _claim_child_warrant(
        self, parent_session_id: str
    ) -> Optional[Any]:
        """Claim the next pending child warrant for this parent (FIFO by task_index)."""
        with self._counter_lock:
            idx = self._child_counters.get(parent_session_id, 0)
            self._child_counters[parent_session_id] = idx + 1
        with self._pending_lock:
            return self._pending_child_warrants.pop((parent_session_id, idx), None)

    # ------------------------------------------------------------------
    # Hook: on_session_start / on_session_end
    # ------------------------------------------------------------------

    def on_session_start(
        self,
        session_id: str,
        parent_session_id: Optional[str] = None,
        task_index: Optional[int] = None,
    ) -> None:
        """Called if Hermes fires on_session_start (currently not fired — kept for future compatibility)."""
        # on_session_start is in VALID_HOOKS but Hermes does not currently fire it.
        # Child warrant injection uses the heuristic in _resolve_warrant instead.
        # If a future Hermes version fires this with parent_session_id, the explicit
        # session warrant registration here will take precedence over the heuristic.
        if parent_session_id and self._child_warrant:
            child_warrant = self._claim_child_warrant(parent_session_id)
            warrant = child_warrant or self._child_warrant
            self.set_session_warrant(session_id, warrant, self._static_signing_key)
            logger.debug(
                "hermes-tenuo: on_session_start fired — child session %s registered (parent=%s)",
                session_id, parent_session_id,
            )

    def on_session_end(self, session_id: str) -> None:
        self.clear_session_warrant(session_id)
        with self._counter_lock:
            self._child_counters.pop(session_id, None)

    # ------------------------------------------------------------------
    # Hook: pre_tool_call
    # ------------------------------------------------------------------

    def pre_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        *,
        task_id: str = "",
        session_id: str = "",
        tool_call_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Returns {"action": "block", "message": "..."} to block the call,
        or None to allow it.
        """
        # Intercept delegate_task to pre-register child warrants
        if tool_name == "delegate_task" and self._child_warrant:
            tasks = args.get("tasks") or []
            task_count = len(tasks) if isinstance(tasks, list) else 1
            self._register_child_warrants(session_id, task_count)

        warrant, signing_key = self._resolve_warrant(session_id)

        # Audit-only mode: no warrant configured — pass through, emit later
        if warrant is None:
            return None

        # Enforcement requires a signing key for Proof-of-Possession.
        # If no key is configured, warn once and pass through.
        if signing_key is None:
            logger.warning(
                "hermes-tenuo: warrant is configured but no signing_key — "
                "enforcement requires TENUO_SIGNING_KEY for PoP. Passing through."
            )
            return None

        # Enforce
        try:
            from tenuo._enforcement import enforce_tool_call
            from tenuo.config import resolve_trusted_roots

            bound = warrant.bind(signing_key)
            result = enforce_tool_call(
                tool_name=tool_name,
                tool_args=args,
                bound_warrant=bound,
                trusted_roots=resolve_trusted_roots(self._trusted_roots),
            )
        except Exception as exc:
            logger.warning("hermes-tenuo: enforcement error for %s: %s", tool_name, exc)
            if self._on_denial == "block":
                return {"action": "block", "message": f"Authorization error: {exc}"}
            return None

        if self._control_plane is not None:
            try:
                self._control_plane.emit_for_enforcement(
                    result, chain_result=getattr(result, "chain_result", None)
                )
            except Exception:
                pass

        self._emit_audit(tool_name, args, result.allowed, result.denial_reason or "", session_id, task_id, tool_call_id)

        if not result.allowed:
            reason = result.denial_reason or f"Tool '{tool_name}' not authorized"
            if self._on_denial == "log":
                logger.warning("hermes-tenuo [BLOCKED-LOG] %s: %s", tool_name, reason)
                return None
            return {"action": "block", "message": reason}

        return None

    # ------------------------------------------------------------------
    # Hook: post_tool_call
    # ------------------------------------------------------------------

    def post_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        result: str,
        *,
        task_id: str = "",
        session_id: str = "",
        tool_call_id: str = "",
        duration_ms: int = 0,
    ) -> None:
        """Emit audit event to Cloud. Fires for every tool call, including audit-only mode."""
        warrant, _ = self._resolve_warrant(session_id)

        # In audit-only mode (no warrant), emit a passthrough audit event
        if warrant is None:
            if self._control_plane is not None:
                from tenuo._enforcement import EnforcementResult
                audit_result = EnforcementResult(
                    allowed=True,
                    tool=tool_name,
                    arguments=args,
                )
                try:
                    self._control_plane.emit_for_enforcement(audit_result)
                except Exception:
                    pass
            self._emit_audit(tool_name, args, True, "audit-only", session_id, task_id, tool_call_id, duration_ms)
            return

        # If enforcement ran in pre_tool_call, post_tool_call is observational only
        self._emit_audit(tool_name, args, True, "post-dispatch", session_id, task_id, tool_call_id, duration_ms)

    # ------------------------------------------------------------------
    # Internal: audit callback
    # ------------------------------------------------------------------

    def _emit_audit(
        self,
        tool: str,
        args: Dict[str, Any],
        allowed: bool,
        reason: str,
        session_id: str = "",
        task_id: str = "",
        tool_call_id: str = "",
        duration_ms: int = 0,
    ) -> None:
        if self._audit_callback is None:
            return
        event = HermesAuditEvent(
            tool=tool,
            args=args,
            decision="ALLOW" if allowed else "DENY",
            reason=reason,
            session_id=session_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            duration_ms=duration_ms,
        )
        try:
            self._audit_callback(event)
        except Exception as exc:
            logger.error("hermes-tenuo: audit callback failed: %s", exc, exc_info=True)


__all__ = ["HermesGuard", "HermesAuditEvent", "AuditCallback"]
