"""Workflow-facing API: activity execution, context accessors, AuthorizedWorkflow,
internal mint activity, scheduled workflows, and async activity completion.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from tenuo.temporal._constants import (
    TENUO_CHAIN_HEADER,
    TENUO_KEY_ID_HEADER,
    TENUO_TEMPORAL_PLUGIN_ID,
)
from tenuo.temporal._decorators import unprotected
from tenuo.temporal._headers import (
    _current_workflow_headers,
    _extract_key_id_from_headers,
    _extract_warrant_from_headers,
    tenuo_headers,
)
from tenuo.temporal._observability import _MintRequest
from tenuo.temporal._state import (
    _pending_activity_fn,
    _pending_child_headers,
    _pending_mint_capabilities,
    _store_lock,
    _workflow_config_store,
    _workflow_headers_store,
)
from tenuo.temporal._warrant_source import WarrantSource
from tenuo.temporal.exceptions import (
    TemporalConstraintViolation,
    TenuoContextError,
)

if TYPE_CHECKING:
    from temporalio.client import Client
    from tenuo import Warrant
    from tenuo.temporal._client import TenuoClientInterceptor
    from tenuo.temporal._config import TenuoPluginConfig

logger = logging.getLogger("tenuo.temporal")


# ── Context Accessors ────────────────────────────────────────────────────

def current_warrant() -> Any:
    """Get the warrant from the current workflow context.

    Must be called from within a workflow.

    Returns:
        The warrant attached to this workflow

    Raises:
        TenuoContextError: If no warrant in context
    """
    warrant = _extract_warrant_from_headers(_current_workflow_headers())
    if warrant is None:
        raise TenuoContextError("No Tenuo warrant in workflow context")
    return warrant


def current_key_id() -> str:
    """Get the key ID from the current workflow context.

    Must be called from within a workflow.

    Returns:
        The key ID for this workflow's holder

    Raises:
        TenuoContextError: If no key ID in context
    """
    key_id = _extract_key_id_from_headers(_current_workflow_headers())
    if key_id is None:
        raise TenuoContextError("No Tenuo key ID in workflow context")
    return key_id


# ── AuthorizedWorkflow ───────────────────────────────────────────────────

class AuthorizedWorkflow:
    """Convenience base class for Tenuo-authorized workflows.

    **What it provides:** validates that Tenuo warrant headers are present at
    workflow *start* (fail-fast), then exposes ``execute_authorized_activity()``
    as a named alias for ``workflow.execute_activity()``.

    **What it does not change:** TenuoPlugin enforces authorization on *every*
    activity regardless of which base class you use.  AuthorizedWorkflow adds no
    security guarantee beyond what the interceptor already provides — it only
    surfaces missing-header errors earlier (at workflow start vs at the first
    activity dispatch).

    Important: You must use @workflow.defn on your subclass!
        Temporal Python SDK uses decorators, not inheritance, to define workflows.

    Single Warrant Limitation:
        This class assumes all activities execute under the SAME warrant.
        For multi-warrant workflows (delegation chains), use
        tenuo_execute_activity() directly.

    Example:
        from temporalio import workflow
        from tenuo.temporal import AuthorizedWorkflow, tenuo_headers

        @workflow.defn
        class MyWorkflow(AuthorizedWorkflow):
            @workflow.run
            async def run(self, name: str) -> str:
                return await self.execute_authorized_activity(
                    my_activity,
                    args=[name],
                    start_to_close_timeout=timedelta(seconds=30),
                )

    Raises:
        TenuoContextError: If workflow is started without Tenuo headers
    """

    def __init__(self) -> None:
        """Validate Tenuo authorization at workflow start.

        Raises a **non-retryable** ``ApplicationError`` so that Temporal
        fails the workflow immediately instead of retrying forever.
        """
        try:
            current_warrant()
            current_key_id()
        except TenuoContextError as e:
            try:
                from temporalio.exceptions import ApplicationError  # type: ignore[import-not-found]
            except ImportError:
                raise e
            raise ApplicationError(
                f"AuthorizedWorkflow requires Tenuo headers: {e}",
                type="TenuoContextError",
                non_retryable=True,
            ) from e

    async def execute_authorized_activity(self, activity: Any, **kwargs: Any) -> Any:
        """Execute activity with automatic Tenuo authorization.

        Convenience wrapper around tenuo_execute_activity().
        """
        return await tenuo_execute_activity(activity, **kwargs)


# ── Workflow helpers ─────────────────────────────────────────────────────

async def tenuo_execute_activity(
    activity: Any,
    *,
    args: Optional[List[Any]] = None,
    start_to_close_timeout: Any = None,
    schedule_to_close_timeout: Any = None,
    schedule_to_start_timeout: Any = None,
    heartbeat_timeout: Any = None,
    retry_policy: Any = None,
    task_queue: Optional[str] = None,
    cancellation_type: Any = None,
    summary: Optional[str] = None,
) -> Any:
    """Execute an activity with automatic function-reference registration.

    This is a wrapper around ``workflow.execute_activity()`` with one
    additional behaviour: it stores the activity function reference in
    ``_pending_activity_fn`` before dispatch, so the outbound interceptor
    can resolve real Python parameter names for PoP signing.

    **When to use it:** if your warrant uses named field constraints
    (e.g. ``path=Subpath(...)``) and you have not set ``activity_fns``
    on ``TenuoPluginConfig``, call via ``tenuo_execute_activity()`` to
    ensure the interceptor signs with ``{"path": ...}`` instead of
    ``{"arg0": ...}``.  Setting ``activity_fns`` on the config is the
    simpler alternative for the same effect.

    Args:
        activity: The activity function to execute
        args: Arguments to pass to the activity
        start_to_close_timeout: Timeout for activity execution
        schedule_to_close_timeout: Timeout from schedule to completion
        schedule_to_start_timeout: Timeout from schedule to start
        heartbeat_timeout: Heartbeat timeout for long-running activities
        retry_policy: Retry policy for the activity
        task_queue: Optional task queue override
        cancellation_type: Cancellation behavior
        summary: Human-readable summary displayed in the Temporal Web UI.
            The outbound interceptor prefixes it with
            ``[tenuo.TenuoTemporalPlugin] <tool>``.  Keep under 200 bytes.

    Returns:
        The activity's return value

    Example:
        @workflow.defn
        class MyWorkflow:
            @workflow.run
            async def run(self) -> str:
                return await tenuo_execute_activity(
                    read_file,
                    args=["/data/report.txt"],
                    start_to_close_timeout=timedelta(seconds=30),
                    summary="read monthly report",
                )
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    activity_kwargs: Dict[str, Any] = {
        k: v for k, v in {
            "args": args,
            "start_to_close_timeout": start_to_close_timeout,
            "schedule_to_close_timeout": schedule_to_close_timeout,
            "schedule_to_start_timeout": schedule_to_start_timeout,
            "heartbeat_timeout": heartbeat_timeout,
            "retry_policy": retry_policy,
            "task_queue": task_queue,
            "cancellation_type": cancellation_type,
            "summary": summary,
        }.items() if v is not None
    }

    wf_id = workflow.info().workflow_id
    with _store_lock:
        _pending_activity_fn[wf_id] = activity

    try:
        return await workflow.execute_activity(activity, **activity_kwargs)
    finally:
        with _store_lock:
            _pending_activity_fn.pop(wf_id, None)


def set_activity_approvals(approvals: List[Any]) -> None:
    """Pre-supply signed approvals for the next activity execution.

    Call this from a workflow before ``workflow.execute_activity()`` when
    the warrant has guards that require approval.  The outbound interceptor
    encodes them into activity headers and the inbound interceptor uses
    them to satisfy the guard check.

    Approvals are consumed on the next activity dispatch (one-shot).

    Args:
        approvals: List of ``SignedApproval`` objects.

    Example::

        set_activity_approvals([signed_approval])
        await workflow.execute_activity(
            delete_file, args=["/etc/config"],
            start_to_close_timeout=timedelta(seconds=30),
        )
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available")

    from tenuo.temporal._state import _pending_activity_approvals

    wf_id = workflow.info().workflow_id
    with _store_lock:
        _pending_activity_approvals[wf_id] = list(approvals)


# ── Internal mint machinery ──────────────────────────────────────────────

async def _dispatch_mint_activity(
    *,
    kind: str,
    parent_warrant: Any,
    key_id: str,
    capabilities: Dict[str, Any],
    ttl_seconds: Optional[int],
) -> bytes:
    """Execute ``_tenuo_internal_mint_activity`` as a local activity.

    Centralises the boilerplate (RetryPolicy, timeout, non-retryable error types)
    shared by ``workflow_grant``, ``workflow_issue_execution``, and
    ``attenuated_headers``. Returns the raw child warrant bytes.

    Capabilities are stashed in a process-local dict rather than inlined in
    ``_MintRequest``, because PyO3 constraint types cannot survive Temporal's
    ``dataclasses.asdict()`` → ``copy.deepcopy()`` serialization path.
    """
    from datetime import timedelta

    from temporalio import workflow  # type: ignore[import-not-found]
    from temporalio.common import RetryPolicy as _RetryPolicy

    cap_ref = str(workflow.uuid4())
    with _store_lock:
        _pending_mint_capabilities[cap_ref] = capabilities

    req = _MintRequest(
        kind=kind,
        parent_warrant_bytes=parent_warrant.to_bytes(),
        key_id=key_id,
        capabilities_ref=cap_ref,
        ttl_seconds=ttl_seconds,
    )
    tools_label = ", ".join(sorted(capabilities.keys())[:3]) or "all"
    summary = f"[{TENUO_TEMPORAL_PLUGIN_ID}] {kind}({tools_label})"

    try:
        return await workflow.execute_local_activity(
            _tenuo_internal_mint_activity,
            req,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=_RetryPolicy(
                maximum_attempts=1,
                non_retryable_error_types=["TenuoContextError", "TemporalConstraintViolation"],
            ),
            summary=summary,
        )
    finally:
        with _store_lock:
            _pending_mint_capabilities.pop(cap_ref, None)


def _workflow_mint_context(purpose: str) -> tuple[str, "TenuoPluginConfig"]:
    """Look up the active workflow's key_id and config for a warrant-mint call."""
    from temporalio import workflow  # type: ignore[import-not-found]

    wf_id = workflow.info().workflow_id
    with _store_lock:
        raw_headers = _workflow_headers_store.get(wf_id, {})
        config_store_entry = _workflow_config_store.get(wf_id)

    if not raw_headers:
        raise TenuoContextError(
            "No Tenuo headers in store. Ensure TenuoPlugin is "
            "registered and tenuo_headers() was passed at workflow start."
        )
    if not config_store_entry:
        raise TenuoContextError(
            "No interceptor config found. Ensure TenuoPlugin is registered."
        )

    key_id = raw_headers.get(TENUO_KEY_ID_HEADER, b"").decode("utf-8")
    if not key_id:
        raise TenuoContextError(
            "No key_id found in workflow headers. Cannot issue attenuated grant."
        )
    if not config_store_entry.key_resolver:
        raise TenuoContextError(
            f"key_resolver not configured in TenuoPluginConfig. Required for {purpose}."
        )
    return key_id, config_store_entry


def _check_subpath_not_widened(
    tool: str,
    field: str,
    parent_val: Any,
    child_val: Any,
    warrant_id: str,
) -> None:
    """Raise TemporalConstraintViolation if child_val is a wider Subpath than parent_val."""
    try:
        from tenuo_core import Subpath as _Subpath  # type: ignore[import-not-found]
    except ImportError:
        return

    if not (isinstance(parent_val, _Subpath) and isinstance(child_val, _Subpath)):
        return

    parent_root: str = parent_val.root
    child_root: str = child_val.root

    if not child_root.startswith(parent_root):
        raise TemporalConstraintViolation(
            tool=tool,
            arguments={},
            constraint=(
                f"Constraint '{field}' would widen parent Subpath '{parent_root}' "
                f"to '{child_root}'. Child constraints must be equal or narrower."
            ),
            warrant_id=warrant_id,
        )


# ── Internal mint activity ───────────────────────────────────────────────

try:
    from temporalio import activity as _temporal_activity

    @_temporal_activity.defn(name="__tenuo_internal_mint")
    @unprotected
    async def _tenuo_internal_mint_activity(req: _MintRequest) -> bytes:
        """Internal Tenuo activity for replay-safe warrant minting.

        Called by workflow_grant() and tenuo_execute_child_workflow(constraints=...)
        via execute_local_activity. Result is recorded in Temporal history, making
        warrant bytes deterministic across workflow replays.

        Users never register or call this activity directly.
        """
        from tenuo_core import Warrant as _Warrant  # type: ignore

        from tenuo.temporal._state import _get_worker_config

        with _store_lock:
            capabilities = _pending_mint_capabilities.get(req.capabilities_ref, {})

        config = _get_worker_config()
        if config is None or config.key_resolver is None:
            raise TenuoContextError(
                "_tenuo_internal_mint_activity: no worker config or key_resolver. "
                "Ensure TenuoPlugin is registered with a key_resolver."
            )

        try:
            signer = config.key_resolver.resolve_sync(req.key_id)
        except Exception as e:
            raise TenuoContextError(
                f"_tenuo_internal_mint_activity: failed to resolve key '{req.key_id}': {e}"
            ) from e

        parent_warrant = _Warrant.from_bytes(req.parent_warrant_bytes)

        try:
            if req.kind == "attenuate":
                child = parent_warrant.attenuate(
                    capabilities=capabilities,
                    signing_key=signer,
                    ttl_seconds=req.ttl_seconds,
                )
            elif req.kind == "issue_execution":
                if not hasattr(parent_warrant, "issue_execution"):
                    raise TenuoContextError(
                        "Warrant.issue_execution() not available on this tenuo_core build. "
                        "Upgrade tenuo_core to a version that supports IssuerWarrant. "
                        "Silently falling back to attenuate() would widen the scope."
                    )
                else:
                    builder = parent_warrant.issue_execution()
                    for tool_name, tool_constraints in capabilities.items():
                        if tool_constraints:
                            builder.capability(tool_name, tool_constraints)
                        else:
                            builder.tool(tool_name)
                    if req.ttl_seconds is not None:
                        builder.ttl(req.ttl_seconds)
                    child = builder.build(signer)
            else:
                raise TenuoContextError(
                    f"_tenuo_internal_mint_activity: unknown kind '{req.kind}'"
                )
        except TenuoContextError:
            raise
        except Exception as e:
            raise TenuoContextError(
                f"_tenuo_internal_mint_activity: mint failed: {e}"
            ) from e

        return child.to_bytes()

except ImportError:
    _tenuo_internal_mint_activity = None  # type: ignore


# ── Public workflow functions ────────────────────────────────────────────

async def _bind_warrant_headers(
    *,
    caller: str,
    client_interceptor: "TenuoClientInterceptor",
    workflow_id: str,
    warrant: Any,
    key_id: str,
    warrant_source: Optional[WarrantSource],
    args: Optional[List[Any]],
    compress: bool,
    extra_kwargs: Dict[str, Any],
) -> None:
    """Resolve warrant source (if needed) and bind headers to the interceptor.

    Shared validation logic for ``execute_workflow_authorized`` and
    ``start_workflow_authorized``.
    """
    if warrant is not None and warrant_source is not None:
        raise TenuoContextError(
            f"{caller}: 'warrant' and 'warrant_source' are mutually exclusive. "
            "Pass one or the other, not both."
        )
    if warrant_source is not None:
        warrant, key_id = await warrant_source.resolve(*(args or []))
    elif warrant is None:
        raise TenuoContextError(
            f"{caller}: either 'warrant' or 'warrant_source' must be provided."
        )
    if "id" in extra_kwargs:
        raise ValueError(
            f"Pass workflow_id via {caller}(..., workflow_id=...). "
            "Do not also pass id= in the keyword arguments."
        )
    client_interceptor.set_headers_for_workflow(
        workflow_id,
        tenuo_headers(warrant, key_id, compress=compress),
    )


async def execute_workflow_authorized(
    *,
    client: Any,
    client_interceptor: "TenuoClientInterceptor",
    workflow_run_fn: Any,
    workflow_id: str,
    warrant: Any = None,
    key_id: str = "",
    warrant_source: Optional[WarrantSource] = None,
    args: Optional[List[Any]] = None,
    compress: bool = True,
    **execute_kwargs: Any,
) -> Any:
    """Execute a workflow with deterministic per-workflow header binding.

    This utility binds Tenuo headers to ``workflow_id`` using
    ``set_headers_for_workflow`` and immediately invokes
    ``client.execute_workflow``.

    Accepts either a pre-minted ``warrant`` + ``key_id`` pair, or a
    ``warrant_source`` that resolves the pair lazily at call time. The two
    are mutually exclusive — passing both raises ``TenuoContextError``.
    """
    await _bind_warrant_headers(
        caller="execute_workflow_authorized",
        client_interceptor=client_interceptor,
        workflow_id=workflow_id,
        warrant=warrant,
        key_id=key_id,
        warrant_source=warrant_source,
        args=args,
        compress=compress,
        extra_kwargs=execute_kwargs,
    )
    return await client.execute_workflow(
        workflow_run_fn,
        args=args or [],
        id=workflow_id,
        **execute_kwargs,
    )


async def start_workflow_authorized(
    *,
    client: Any,
    client_interceptor: "TenuoClientInterceptor",
    workflow_run_fn: Any,
    workflow_id: str,
    warrant: Any = None,
    key_id: str = "",
    warrant_source: Optional["WarrantSource"] = None,
    args: Optional[List[Any]] = None,
    compress: bool = True,
    **start_kwargs: Any,
) -> Any:
    """Start a workflow with Tenuo authorization headers, returning immediately.

    Use this for long-running workflows — human-in-the-loop gates, multi-day
    pipelines — where the caller should not block on the final result. The
    function returns a ``WorkflowHandle`` as soon as the workflow is accepted
    by the Temporal server.
    """
    await _bind_warrant_headers(
        caller="start_workflow_authorized",
        client_interceptor=client_interceptor,
        workflow_id=workflow_id,
        warrant=warrant,
        key_id=key_id,
        warrant_source=warrant_source,
        args=args,
        compress=compress,
        extra_kwargs=start_kwargs,
    )
    return await client.start_workflow(
        workflow_run_fn,
        args=args or [],
        id=workflow_id,
        **start_kwargs,
    )


async def attenuated_headers(
    *,
    tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Any]] = None,
    ttl_seconds: Optional[int] = None,
    child_key_id: Optional[str] = None,
    compress: bool = True,
) -> Dict[str, bytes]:
    """Create headers for a child workflow with attenuated scope.

    Must be called from within a workflow context.
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    parent_warrant = current_warrant()
    parent_key_id, _config_entry = _workflow_mint_context("child workflow delegation")

    wf_id = workflow.info().workflow_id
    with _store_lock:
        raw_headers = dict(_workflow_headers_store.get(wf_id, {}))

    parent_tools = set(parent_warrant.tools or [])
    if tools is not None:
        requested_tools = set(tools)
        if not requested_tools.issubset(parent_tools):
            excess = requested_tools - parent_tools
            raise TemporalConstraintViolation(
                tool=str(list(excess)[0]),
                arguments={},
                constraint=f"Cannot delegate tools not in parent: {excess}",
                warrant_id=parent_warrant.id,
            )
    else:
        tools = list(parent_tools)

    parent_caps = parent_warrant.capabilities or {}
    extra = constraints or {}
    capabilities = {}
    for tool_key in tools:
        base = dict(parent_caps.get(tool_key, {}))
        narrowing = extra.get(tool_key, {})
        unknown_keys = set(narrowing) - set(base)
        if unknown_keys:
            raise TemporalConstraintViolation(
                tool=tool_key,
                arguments={},
                constraint=(
                    f"Cannot introduce constraint keys not present in parent warrant: "
                    f"{sorted(unknown_keys)}.  Only existing constraint keys may be "
                    "narrowed in a child warrant."
                ),
                warrant_id=parent_warrant.id,
            )
        for field_name, new_val in narrowing.items():
            parent_val = base.get(field_name)
            _check_subpath_not_widened(tool_key, field_name, parent_val, new_val, parent_warrant.id)
        base.update(narrowing)
        capabilities[tool_key] = base

    key_id = child_key_id or parent_key_id

    child_warrant_bytes = await _dispatch_mint_activity(
        kind="attenuate",
        parent_warrant=parent_warrant,
        key_id=parent_key_id,
        capabilities=capabilities,
        ttl_seconds=ttl_seconds,
    )

    from tenuo_core import Warrant as _Warrant  # type: ignore

    child_warrant = _Warrant.from_bytes(child_warrant_bytes)

    hdrs = tenuo_headers(child_warrant, key_id, compress=compress)

    existing_chain_raw = raw_headers.get(TENUO_CHAIN_HEADER)
    from tenuo_core import decode_warrant_stack_base64 as _decode_stack
    from tenuo_core import encode_warrant_stack as _encode_stack

    if existing_chain_raw:
        existing_warrants = _decode_stack(existing_chain_raw.decode("utf-8"))
    else:
        existing_warrants = [parent_warrant]

    all_chain = existing_warrants + [child_warrant]
    hdrs[TENUO_CHAIN_HEADER] = _encode_stack(all_chain).encode("utf-8")

    return hdrs


async def tenuo_execute_child_workflow(
    workflow_fn: Any,
    *,
    args: Optional[List[Any]] = None,
    id: Optional[str] = None,
    tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Any]] = None,
    ttl_seconds: Optional[int] = None,
    child_key_id: Optional[str] = None,
    task_queue: Optional[str] = None,
    execution_timeout: Any = None,
    run_timeout: Any = None,
    task_timeout: Any = None,
    cancellation_type: Any = None,
    parent_close_policy: Any = None,
    retry_policy: Any = None,
    id_reuse_policy: Any = None,
    cron_schedule: str = "",
    memo: Any = None,
    search_attributes: Any = None,
) -> Any:
    """Execute a child workflow with an attenuated Tenuo warrant."""
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    hdrs = await attenuated_headers(
        tools=tools,
        constraints=constraints,
        ttl_seconds=ttl_seconds,
        child_key_id=child_key_id,
    )

    child_id = id or f"{workflow.info().workflow_id}-child-{workflow.uuid4()}"

    with _store_lock:
        _pending_child_headers[child_id] = hdrs

    kwargs: Dict[str, Any] = {"id": child_id}
    optional: Dict[str, Any] = {
        "args": args,
        "task_queue": task_queue,
        "execution_timeout": execution_timeout,
        "run_timeout": run_timeout,
        "task_timeout": task_timeout,
        "cancellation_type": cancellation_type,
        "parent_close_policy": parent_close_policy,
        "retry_policy": retry_policy,
        "id_reuse_policy": id_reuse_policy,
        "memo": memo,
        "search_attributes": search_attributes,
    }
    kwargs.update({k: v for k, v in optional.items() if v is not None})
    if cron_schedule:
        kwargs["cron_schedule"] = cron_schedule

    try:
        return await workflow.execute_child_workflow(workflow_fn, **kwargs)
    finally:
        with _store_lock:
            _pending_child_headers.pop(child_id, None)


async def workflow_grant(
    tool: str,
    constraints: Optional[Dict[str, Any]] = None,
    *,
    ttl_seconds: int = 300,
) -> Any:
    """Issue a scoped warrant for a single tool within a workflow."""
    try:
        from temporalio import workflow  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    parent_warrant = current_warrant()

    parent_tools = parent_warrant.tools or []
    if tool not in parent_tools:
        raise TemporalConstraintViolation(
            tool=tool,
            arguments={},
            constraint=f"Tool '{tool}' not in parent warrant capabilities",
            warrant_id=parent_warrant.id,
        )

    key_id, _config_entry = _workflow_mint_context("attenuated grants")

    parent_caps = parent_warrant.capabilities or {}
    base = dict(parent_caps.get(tool, {}))
    if constraints:
        base.update(constraints)

    result_bytes = await _dispatch_mint_activity(
        kind="attenuate",
        parent_warrant=parent_warrant,
        key_id=key_id,
        capabilities={tool: base},
        ttl_seconds=ttl_seconds,
    )
    from tenuo_core import Warrant as _Warrant  # type: ignore  # noqa: F401

    return _Warrant.from_bytes(result_bytes)


async def workflow_issue_execution(
    tool: str,
    constraints: Optional[Dict[str, Any]] = None,
    *,
    ttl_seconds: int = 300,
) -> Any:
    """Issue a per-execution warrant from an issuer warrant within a workflow."""
    try:
        from temporalio import workflow  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    parent_warrant = current_warrant()

    parent_tools = parent_warrant.tools or []
    if tool not in parent_tools:
        raise TemporalConstraintViolation(
            tool=tool,
            arguments={},
            constraint=f"Tool '{tool}' not in parent warrant capabilities",
            warrant_id=parent_warrant.id,
        )

    key_id, _config_entry = _workflow_mint_context("outbound PoP signing")

    result_bytes = await _dispatch_mint_activity(
        kind="issue_execution",
        parent_warrant=parent_warrant,
        key_id=key_id,
        capabilities={tool: dict(constraints) if constraints else {}},
        ttl_seconds=ttl_seconds,
    )
    from tenuo_core import Warrant as _Warrant  # type: ignore  # noqa: F401

    return _Warrant.from_bytes(result_bytes)


def tenuo_continue_as_new(
    *args: Any,
    tenuo_attenuation: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> None:
    """Continue-as-new with warrant inheritance.

    By default, the current workflow's warrant is inherited verbatim into the next
    execution via the CAN headers (propagated by the outbound interceptor's
    ``continue_as_new`` method).
    """
    try:
        from temporalio import workflow  # type: ignore[import-not-found]
    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")

    if tenuo_attenuation is not None:
        raise NotImplementedError(
            "tenuo_continue_as_new(tenuo_attenuation=...) is not yet implemented. "
            "Use tenuo_execute_child_workflow() for attenuated delegation."
        )

    workflow.continue_as_new(*args, **kwargs)


# ── Scheduled workflow + async activity helpers ──────────────────────────

async def create_scheduled_workflow_with_warrant(
    client: "Client",
    schedule_id: str,
    workflow: Any,
    warrant: "Warrant",
    key_id: str,
    schedule_spec: Any,
    *,
    workflow_args: Optional[list] = None,
    workflow_kwargs: Optional[dict] = None,
    task_queue: str = "default",
    **schedule_kwargs: Any,
) -> Any:
    """Create a Temporal Schedule that carries a Tenuo warrant in the schedule memo."""
    import base64 as _b64
    from temporalio.client import Schedule, ScheduleActionStartWorkflow

    warrant_bytes = warrant.to_bytes()
    memo = {
        "tenuo_warrant": _b64.b64encode(warrant_bytes).decode(),
        "tenuo_key_id": key_id,
    }

    action = ScheduleActionStartWorkflow(
        workflow,
        *(workflow_args or []),
        **(workflow_kwargs or {}),
        id=f"{schedule_id}-run",
        task_queue=task_queue,
        memo=memo,
    )

    schedule = Schedule(action=action, spec=schedule_spec)
    return await client.create_schedule(schedule_id, schedule, **schedule_kwargs)


async def tenuo_complete_async_activity(
    handle_or_task_token: Any,
    result: Any,
    warrant: "Warrant",
    key_id: str,
    *,
    client: Optional["Client"] = None,
) -> None:
    """Complete an async activity with Tenuo authorization headers."""
    import datetime as _datetime

    from tenuo.temporal._state import _get_worker_config

    now = _datetime.datetime.now(_datetime.timezone.utc)

    try:
        worker_cfg = _get_worker_config()
        if worker_cfg is not None and worker_cfg.key_resolver is not None:
            key = await worker_cfg.key_resolver.resolve(key_id)
            if key is not None:
                import json as _json
                payload_str = _json.dumps({"result": str(result), "ts": now.isoformat()})
                if hasattr(warrant, "sign_pop"):
                    warrant.sign_pop(payload_str.encode(), key)
    except Exception:
        logger.debug("PoP signing skipped for async activity completion", exc_info=True)

    if isinstance(handle_or_task_token, (bytes, bytearray)):
        if client is None:
            from tenuo.exceptions import ConfigurationError
            raise ConfigurationError(
                "client= is required when handle_or_task_token is a raw task token"
            )
        handle = client.get_async_activity_handle(task_token=bytes(handle_or_task_token))
    else:
        handle = handle_or_task_token

    await handle.complete(result)
