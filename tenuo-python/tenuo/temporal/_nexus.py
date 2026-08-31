"""Tenuo helpers for Temporal Nexus operation authorization.

Nexus carries headers as strings, while the existing Tenuo Temporal activity
wire format uses raw bytes. This module keeps the cryptographic payload format
the same and adds a small Nexus-specific base64 envelope for transport across
Nexus operation headers.
"""

from __future__ import annotations

import base64
import dataclasses as _dataclasses
import functools
import inspect
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from tenuo.temporal._constants import (
    TENUO_CHAIN_HEADER,
    TENUO_POP_HEADER,
)
from tenuo.temporal._headers import (
    _extract_key_id_from_headers,
    _extract_warrant_from_headers,
    _validate_chain_ends_with_warrant,
    tenuo_headers,
)
from tenuo.temporal._interceptors import _build_authorizer
from tenuo.temporal._pop import _normalize_args_for_pop
from tenuo.temporal._state import (
    _current_run_key,
    _store_lock,
    _workflow_config_store,
    _workflow_headers_store,
)
from tenuo.temporal.exceptions import (
    ChainValidationError,
    PopVerificationError,
    TemporalConstraintViolation,
    TenuoContextError,
)

TENUO_NEXUS_HEADER_ENCODING = "x-tenuo-nexus-header-encoding"
_TENUO_NEXUS_HEADER_ENCODING_V1 = "base64-v1"
_TENUO_NEXUS_WORKFLOW_ENVELOPE_VERSION = "tenuo-nexus-workflow-envelope/v1"
_UNSET = object()


@_dataclasses.dataclass(frozen=True)
class TenuoNexusWorkflowEnvelope:
    """Serializable Tenuo context for workflow-backed Nexus operations."""

    version: str
    headers: Dict[str, str]
    source_endpoint: Optional[str] = None
    source_service: Optional[str] = None
    source_operation: Optional[str] = None
    target_workflow_id: Optional[str] = None
    target_workflow_type: Optional[str] = None
    mode: str = "forwarded"


def nexus_tool_name(
    endpoint: str,
    operation: Any,
    *,
    service: Optional[str] = None,
) -> str:
    """Return the Tenuo tool name used for a Nexus operation."""
    op_name = _operation_name(operation)
    prefix = f"nexus:{endpoint}"
    if service:
        prefix = f"{prefix}:{service}"
    return f"{prefix}:{op_name}"


def nexus_input_args(input: Any) -> Dict[str, Any]:
    """Normalize a Nexus operation's single input into Tenuo argument fields.

    Dataclass and dict inputs expose their top-level fields as constraintable
    arguments. Other inputs are represented as ``{"input": value}``.
    """
    if _dataclasses.is_dataclass(input) and not isinstance(input, type):
        raw = _dataclasses.asdict(input)
    elif isinstance(input, Mapping):
        raw = dict(input)
    else:
        raw = {"input": input}
    return _normalize_args_for_pop(raw)


def tenuo_nexus_headers(
    warrant: Any,
    key_id: str,
    signer: Any,
    *,
    endpoint: str,
    operation: Any,
    input: Any,
    service: Optional[str] = None,
    warrant_chain: Optional[List[Any]] = None,
    compress: bool = True,
    timestamp: Optional[int] = None,
) -> Dict[str, str]:
    """Create Nexus string headers carrying a Tenuo warrant and PoP.

    This low-level helper is useful for tests and advanced wiring. Workflow
    code usually wants :func:`tenuo_execute_nexus_operation` or
    :func:`tenuo_start_nexus_operation`, which resolve the signer from the
    active ``TenuoPluginConfig``.
    """
    raw_headers = tenuo_headers(warrant, key_id, compress=compress)
    chain = list(warrant_chain) if warrant_chain is not None else [warrant]
    _validate_chain_ends_with_warrant(
        chain,
        warrant,
        operation="tenuo_nexus_headers",
    )
    if len(chain) > 1:
        from tenuo_core import encode_warrant_stack

        raw_headers[TENUO_CHAIN_HEADER] = encode_warrant_stack(chain).encode("utf-8")

    tool_name = nexus_tool_name(endpoint, operation, service=service)
    args = nexus_input_args(input)
    ts = int(time.time()) if timestamp is None else int(timestamp)
    pop_signature = warrant.sign(signer, tool_name, args, ts)
    raw_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop_signature))
    return _encode_nexus_headers(raw_headers)


async def tenuo_execute_nexus_operation(
    nexus_client: Any,
    operation: Any,
    input: Any,
    *,
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    warrant: Any = None,
    key_id: Optional[str] = None,
    warrant_chain: Optional[List[Any]] = None,
    compress: bool = True,
    output_type: Any = None,
    schedule_to_close_timeout: Any = None,
    cancellation_type: Any = None,
    headers: Optional[Mapping[str, str]] = None,
    summary: Optional[str] = None,
) -> Any:
    """Execute a Nexus operation with Tenuo authorization headers."""
    call_headers = _authorized_nexus_headers(
        nexus_client,
        operation,
        input,
        endpoint=endpoint,
        service=service,
        warrant=warrant,
        key_id=key_id,
        warrant_chain=warrant_chain,
        compress=compress,
        headers=headers,
    )
    kwargs = _nexus_operation_kwargs(
        output_type=output_type,
        schedule_to_close_timeout=schedule_to_close_timeout,
        cancellation_type=cancellation_type,
        headers=call_headers,
        summary=summary,
    )
    return await nexus_client.execute_operation(operation, input, **kwargs)


async def tenuo_start_nexus_operation(
    nexus_client: Any,
    operation: Any,
    input: Any,
    *,
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    warrant: Any = None,
    key_id: Optional[str] = None,
    warrant_chain: Optional[List[Any]] = None,
    compress: bool = True,
    output_type: Any = None,
    schedule_to_close_timeout: Any = None,
    cancellation_type: Any = None,
    headers: Optional[Mapping[str, str]] = None,
    summary: Optional[str] = None,
) -> Any:
    """Start a Nexus operation with Tenuo authorization headers."""
    call_headers = _authorized_nexus_headers(
        nexus_client,
        operation,
        input,
        endpoint=endpoint,
        service=service,
        warrant=warrant,
        key_id=key_id,
        warrant_chain=warrant_chain,
        compress=compress,
        headers=headers,
    )
    kwargs = _nexus_operation_kwargs(
        output_type=output_type,
        schedule_to_close_timeout=schedule_to_close_timeout,
        cancellation_type=cancellation_type,
        headers=call_headers,
        summary=summary,
    )
    return await nexus_client.start_operation(operation, input, **kwargs)


def verify_nexus_operation(
    ctx: Any,
    input: Any,
    config: Any,
    *,
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    operation: Optional[Any] = None,
    raise_nexus_error: bool = False,
) -> Any:
    """Verify Tenuo headers on a Nexus operation handler context.

    Returns the verified warrant. When ``raise_nexus_error=True``, failures are
    translated to a Nexus ``HandlerError`` with type ``UNAUTHORIZED``.
    """
    try:
        return _verify_nexus_operation(
            ctx,
            input,
            config,
            endpoint=endpoint,
            service=service,
            operation=operation,
        )
    except Exception as exc:
        if raise_nexus_error:
            raise _as_nexus_unauthorized(exc) from exc
        raise


def tenuo_nexus_operation(
    config: Any,
    *,
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    operation: Optional[Any] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that verifies a Nexus operation before handler code runs."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(
                self: Any,
                ctx: Any,
                input: Any,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                verify_nexus_operation(
                    ctx,
                    input,
                    config,
                    endpoint=endpoint,
                    service=service,
                    operation=operation or fn,
                    raise_nexus_error=True,
                )
                return await fn(self, ctx, input, *args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(
            self: Any,
            ctx: Any,
            input: Any,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            verify_nexus_operation(
                ctx,
                input,
                config,
                endpoint=endpoint,
                service=service,
                operation=operation or fn,
                raise_nexus_error=True,
            )
            return fn(self, ctx, input, *args, **kwargs)

        return sync_wrapper

    return decorator


async def tenuo_nexus_signal_workflow(
    ctx: Any,
    input: Any,
    config: Any,
    handle: Any,
    signal: Any,
    arg: Any = _UNSET,
    *,
    args: Sequence[Any] = (),
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    operation: Optional[Any] = None,
    rpc_metadata: Optional[Mapping[str, str | bytes]] = None,
    rpc_timeout: Any = None,
) -> None:
    """Verify a Nexus request, then signal a Temporal workflow handle.

    Use this in sync Nexus router handlers that translate an authorized Nexus
    request into a Temporal signal. The warrant still authorizes the public
    Nexus operation/input; include the target workflow id, signal name, and
    signal payload fields in that input when they need policy constraints.
    """
    verify_nexus_operation(
        ctx,
        input,
        config,
        endpoint=endpoint,
        service=service,
        operation=operation,
        raise_nexus_error=True,
    )
    kwargs = _temporal_handle_kwargs(
        args=args,
        rpc_metadata=rpc_metadata or {},
        rpc_timeout=rpc_timeout,
    )
    if arg is _UNSET:
        await handle.signal(signal, **kwargs)
    else:
        await handle.signal(signal, arg, **kwargs)


async def tenuo_nexus_query_workflow(
    ctx: Any,
    input: Any,
    config: Any,
    handle: Any,
    query: Any,
    arg: Any = _UNSET,
    *,
    args: Sequence[Any] = (),
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    operation: Optional[Any] = None,
    result_type: type | None = None,
    reject_condition: Any = None,
    rpc_metadata: Optional[Mapping[str, str | bytes]] = None,
    rpc_timeout: Any = None,
) -> Any:
    """Verify a Nexus request, then query a Temporal workflow handle."""
    verify_nexus_operation(
        ctx,
        input,
        config,
        endpoint=endpoint,
        service=service,
        operation=operation,
        raise_nexus_error=True,
    )
    kwargs = _temporal_handle_kwargs(
        args=args,
        result_type=result_type,
        reject_condition=reject_condition,
        rpc_metadata=rpc_metadata or {},
        rpc_timeout=rpc_timeout,
    )
    if arg is _UNSET:
        return await handle.query(query, **kwargs)
    return await handle.query(query, arg, **kwargs)


async def tenuo_nexus_execute_update(
    ctx: Any,
    input: Any,
    config: Any,
    handle: Any,
    update: Any,
    arg: Any = _UNSET,
    *,
    args: Sequence[Any] = (),
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    operation: Optional[Any] = None,
    id: str | None = None,
    result_type: type | None = None,
    rpc_metadata: Optional[Mapping[str, str | bytes]] = None,
    rpc_timeout: Any = None,
) -> Any:
    """Verify a Nexus request, then execute a Temporal workflow update."""
    verify_nexus_operation(
        ctx,
        input,
        config,
        endpoint=endpoint,
        service=service,
        operation=operation,
        raise_nexus_error=True,
    )
    kwargs = _temporal_handle_kwargs(
        args=args,
        id=id,
        result_type=result_type,
        rpc_metadata=rpc_metadata or {},
        rpc_timeout=rpc_timeout,
    )
    if arg is _UNSET:
        return await handle.execute_update(update, **kwargs)
    return await handle.execute_update(update, arg, **kwargs)


async def tenuo_nexus_start_update(
    ctx: Any,
    input: Any,
    config: Any,
    handle: Any,
    update: Any,
    arg: Any = _UNSET,
    *,
    wait_for_stage: Any,
    args: Sequence[Any] = (),
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    operation: Optional[Any] = None,
    id: str | None = None,
    result_type: type | None = None,
    rpc_metadata: Optional[Mapping[str, str | bytes]] = None,
    rpc_timeout: Any = None,
) -> Any:
    """Verify a Nexus request, then start a Temporal workflow update."""
    verify_nexus_operation(
        ctx,
        input,
        config,
        endpoint=endpoint,
        service=service,
        operation=operation,
        raise_nexus_error=True,
    )
    kwargs = _temporal_handle_kwargs(
        wait_for_stage=wait_for_stage,
        args=args,
        id=id,
        result_type=result_type,
        rpc_metadata=rpc_metadata or {},
        rpc_timeout=rpc_timeout,
    )
    if arg is _UNSET:
        return await handle.start_update(update, **kwargs)
    return await handle.start_update(update, arg, **kwargs)


def tenuo_forward_nexus_authority(
    ctx: Any,
    input: Any,
    config: Any,
    *,
    workflow_id: Optional[str] = None,
    workflow_type: Optional[str] = None,
    endpoint: Optional[str] = None,
    service: Optional[str] = None,
    operation: Optional[Any] = None,
) -> TenuoNexusWorkflowEnvelope:
    """Create a workflow envelope by forwarding verified Nexus authority.

    This is the explicit escape hatch: the backing workflow receives the same
    warrant/key context that authorized the Nexus operation. If that workflow
    later calls protected activities, its worker config must be able to resolve
    the forwarded ``key_id`` for PoP signing.
    """
    if not workflow_id:
        raise TenuoContextError(
            "tenuo_forward_nexus_authority requires workflow_id= to bind the "
            "envelope to one backing workflow."
        )
    verify_nexus_operation(
        ctx,
        input,
        config,
        endpoint=endpoint,
        service=service,
        operation=operation,
    )
    raw_headers = _decode_nexus_headers(getattr(ctx, "headers", {}) or {})
    return _workflow_envelope_from_raw_headers(
        raw_headers,
        ctx=ctx,
        workflow_id=workflow_id,
        workflow_type=workflow_type,
        endpoint=endpoint,
        service=service,
        operation=operation,
        mode="forwarded",
    )


def tenuo_create_nexus_workflow_envelope(
    warrant: Any,
    key_id: str,
    *,
    workflow_id: Optional[str] = None,
    workflow_type: Optional[str] = None,
    warrant_chain: Optional[List[Any]] = None,
    compress: bool = True,
    source_ctx: Any = None,
    source_endpoint: Optional[str] = None,
    source_service: Optional[str] = None,
    source_operation: Optional[Any] = None,
) -> TenuoNexusWorkflowEnvelope:
    """Create a workflow envelope for handler-minted or attenuated authority.

    Use this as the preferred workflow-backed Nexus path: after verifying the
    operation, the handler passes a narrower workflow warrant whose holder key
    belongs to the handler/backing-workflow namespace.
    """
    if not workflow_id:
        raise TenuoContextError(
            "tenuo_create_nexus_workflow_envelope requires workflow_id= to bind "
            "the envelope to one backing workflow."
        )
    raw_headers = tenuo_headers(warrant, key_id, compress=compress)
    chain = list(warrant_chain) if warrant_chain is not None else [warrant]
    _validate_chain_ends_with_warrant(
        chain,
        warrant,
        operation="tenuo_create_nexus_workflow_envelope",
    )
    if len(chain) > 1:
        from tenuo_core import encode_warrant_stack

        raw_headers[TENUO_CHAIN_HEADER] = encode_warrant_stack(chain).encode("utf-8")

    return _workflow_envelope_from_raw_headers(
        raw_headers,
        ctx=source_ctx,
        workflow_id=workflow_id,
        workflow_type=workflow_type,
        endpoint=source_endpoint,
        service=source_service,
        operation=source_operation,
        mode="minted",
    )


def tenuo_bootstrap_nexus_workflow(envelope: Any) -> None:
    """Install a Nexus workflow envelope into the current Temporal workflow.

    Call this at the start of a workflow-backed Nexus workflow before calling
    ``current_warrant()``, ``current_key_id()``, or ``tenuo_execute_activity()``.
    The worker still needs ``TenuoWorkerInterceptor`` so the run-scoped config
    is present for outbound PoP signing.
    """
    try:
        _bootstrap_nexus_workflow(envelope)
    except Exception as exc:
        _raise_bootstrap_error(exc)


def _bootstrap_nexus_workflow(envelope: Any) -> None:
    env = _coerce_workflow_envelope(envelope)
    if env.version != _TENUO_NEXUS_WORKFLOW_ENVELOPE_VERSION:
        raise TenuoContextError(
            f"Unsupported Tenuo Nexus workflow envelope version: {env.version!r}"
        )
    try:
        from temporalio import workflow  # type: ignore[import-not-found]

        info = workflow.info()
        workflow_id = getattr(info, "workflow_id", None)
        workflow_type = getattr(info, "workflow_type", None)
    except Exception as exc:
        raise TenuoContextError(
            "tenuo_bootstrap_nexus_workflow requires an active Temporal workflow context."
        ) from exc

    if env.target_workflow_id and workflow_id != env.target_workflow_id:
        raise TenuoContextError(
            "Tenuo Nexus workflow envelope target_workflow_id mismatch: "
            f"expected {env.target_workflow_id!r}, got {workflow_id!r}."
        )
    if env.target_workflow_type and workflow_type != env.target_workflow_type:
        raise TenuoContextError(
            "Tenuo Nexus workflow envelope target_workflow_type mismatch: "
            f"expected {env.target_workflow_type!r}, got {workflow_type!r}."
        )

    run_key = _current_run_key()
    raw_headers = _decode_nexus_headers(env.headers)
    warrant = _extract_warrant_from_headers(raw_headers)
    key_id = _extract_key_id_from_headers(raw_headers)
    if warrant is None or key_id is None:
        raise TenuoContextError(
            "Tenuo Nexus workflow envelope is missing warrant or key_id headers."
        )

    chain = [warrant]
    chain_header = raw_headers.get(TENUO_CHAIN_HEADER)
    if chain_header:
        try:
            from tenuo_core import decode_warrant_stack_base64

            chain = list(decode_warrant_stack_base64(chain_header.decode("utf-8")))
            _validate_chain_ends_with_warrant(
                chain,
                warrant,
                operation="tenuo_bootstrap_nexus_workflow",
            )
        except Exception as exc:
            raise ChainValidationError(
                reason=f"Invalid Nexus workflow envelope chain header: {exc}",
                depth=0,
            ) from exc

    with _store_lock:
        config = _workflow_config_store.get(run_key)
    if config is None:
        raise TenuoContextError(
            "tenuo_bootstrap_nexus_workflow requires TenuoWorkerInterceptor on "
            "the backing workflow worker."
        )

    try:
        from tenuo_core import Authorizer

        revocation_list = config._last_good_revocation_list or config.revocation_list
        authorizer = _build_authorizer(
            Authorizer,
            config.trusted_roots,
            config,
            revocation_list=revocation_list,
        )
        authorizer.verify_chain(chain)
    except Exception as exc:
        raise TenuoContextError(
            f"Tenuo Nexus workflow envelope authorization failed: {exc}"
        ) from exc

    with _store_lock:
        _workflow_headers_store[run_key] = raw_headers


def _raise_bootstrap_error(exc: Exception) -> None:
    try:
        from temporalio import workflow  # type: ignore[import-not-found]

        if not workflow.in_workflow():
            raise exc
        from tenuo.temporal.exceptions import _build_non_retryable_application_error

        raise _build_non_retryable_application_error(exc) from exc
    except ImportError:
        raise exc


def _authorized_nexus_headers(
    nexus_client: Any,
    operation: Any,
    input: Any,
    *,
    endpoint: Optional[str],
    service: Optional[str],
    warrant: Any,
    key_id: Optional[str],
    warrant_chain: Optional[List[Any]],
    compress: bool,
    headers: Optional[Mapping[str, str]],
) -> Dict[str, str]:
    endpoint_name = endpoint or getattr(nexus_client, "endpoint", None)
    if not endpoint_name:
        raise TenuoContextError(
            "tenuo_execute_nexus_operation requires endpoint= when it cannot "
            "be read from the Nexus client."
        )
    service_name = service or getattr(nexus_client, "service_name", None)
    existing_headers = dict(headers or {})
    for header_name in existing_headers:
        if header_name.startswith("x-tenuo-"):
            raise TenuoContextError(
                f"Nexus headers already include reserved Tenuo header {header_name!r}."
            )

    resolved_warrant, resolved_key_id, chain, signer = _resolve_workflow_nexus_authority(
        warrant=warrant,
        key_id=key_id,
        warrant_chain=warrant_chain,
    )
    timestamp = _workflow_timestamp()
    tenuo = tenuo_nexus_headers(
        resolved_warrant,
        resolved_key_id,
        signer,
        endpoint=endpoint_name,
        service=service_name,
        operation=operation,
        input=input,
        warrant_chain=chain,
        compress=compress,
        timestamp=timestamp,
    )
    existing_headers.update(tenuo)
    return existing_headers


def _resolve_workflow_nexus_authority(
    *,
    warrant: Any,
    key_id: Optional[str],
    warrant_chain: Optional[List[Any]],
) -> tuple[Any, str, List[Any], Any]:
    run_key = _current_run_key()
    with _store_lock:
        raw_current = dict(_workflow_headers_store.get(run_key, {}))
        config = _workflow_config_store.get(run_key)
    if config is None or config.key_resolver is None:
        raise TenuoContextError(
            "tenuo_execute_nexus_operation requires TenuoPluginConfig with "
            "key_resolver in the active workflow context."
        )

    if (warrant is None) != (key_id is None):
        raise TenuoContextError(
            "tenuo_execute_nexus_operation: warrant and key_id must be provided together."
        )
    if warrant is None:
        warrant = _extract_warrant_from_headers(raw_current)
        if warrant is None:
            raise TenuoContextError("No Tenuo warrant in workflow context")
        key_id = _extract_key_id_from_headers(raw_current)
        if key_id is None:
            raise TenuoContextError("No key_id found in workflow context")

    assert key_id is not None
    if warrant_chain is not None:
        chain = list(warrant_chain)
    elif getattr(warrant, "parent_hash", None) is None:
        chain = [warrant]
    else:
        encoded_current = raw_current.get(TENUO_CHAIN_HEADER)
        if encoded_current:
            from tenuo_core import decode_warrant_stack_base64

            chain = list(decode_warrant_stack_base64(encoded_current.decode("utf-8")))
        else:
            current = _extract_warrant_from_headers(raw_current)
            chain = [current] if current is not None else []
        chain.append(warrant)
    _validate_chain_ends_with_warrant(
        chain,
        warrant,
        operation="tenuo_execute_nexus_operation",
    )

    try:
        signer = config.key_resolver.resolve_sync(key_id)
    except Exception as exc:
        raise TenuoContextError(
            f"tenuo_execute_nexus_operation: failed to resolve key {key_id!r}: {exc}"
        ) from exc
    return warrant, key_id, chain, signer


def _workflow_timestamp() -> int:
    try:
        from temporalio import workflow  # type: ignore[import-not-found]

        return int(workflow.now().timestamp())
    except Exception:
        return int(time.time())


def _nexus_operation_kwargs(**kwargs: Any) -> Dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}


def _temporal_handle_kwargs(**kwargs: Any) -> Dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}


def _workflow_envelope_from_raw_headers(
    raw_headers: Mapping[str, bytes],
    *,
    ctx: Any,
    workflow_id: Optional[str],
    workflow_type: Optional[str],
    endpoint: Optional[str],
    service: Optional[str],
    operation: Optional[Any],
    mode: str,
) -> TenuoNexusWorkflowEnvelope:
    source_operation = operation or getattr(ctx, "operation", None)
    return TenuoNexusWorkflowEnvelope(
        version=_TENUO_NEXUS_WORKFLOW_ENVELOPE_VERSION,
        headers=_encode_nexus_headers(raw_headers),
        source_endpoint=endpoint,
        source_service=service or getattr(ctx, "service", None),
        source_operation=_operation_name(source_operation) if source_operation else None,
        target_workflow_id=workflow_id,
        target_workflow_type=workflow_type,
        mode=mode,
    )


def _coerce_workflow_envelope(envelope: Any) -> TenuoNexusWorkflowEnvelope:
    if isinstance(envelope, TenuoNexusWorkflowEnvelope):
        return envelope
    if isinstance(envelope, Mapping):
        return TenuoNexusWorkflowEnvelope(
            version=str(envelope.get("version", "")),
            headers=dict(envelope.get("headers", {})),
            source_endpoint=envelope.get("source_endpoint"),
            source_service=envelope.get("source_service"),
            source_operation=envelope.get("source_operation"),
            target_workflow_id=envelope.get("target_workflow_id"),
            target_workflow_type=envelope.get("target_workflow_type"),
            mode=str(envelope.get("mode", "")),
        )
    if _dataclasses.is_dataclass(envelope) and not isinstance(envelope, type):
        return _coerce_workflow_envelope(_dataclasses.asdict(envelope))
    raise TenuoContextError(
        "Expected TenuoNexusWorkflowEnvelope or envelope-shaped mapping."
    )


def _verify_nexus_operation(
    ctx: Any,
    input: Any,
    config: Any,
    *,
    endpoint: Optional[str],
    service: Optional[str],
    operation: Optional[Any],
) -> Any:
    raw_headers = _decode_nexus_headers(getattr(ctx, "headers", {}) or {})
    warrant = _extract_warrant_from_headers(raw_headers)
    if warrant is None:
        raise TemporalConstraintViolation(
            tool=_ctx_tool_name(ctx, endpoint, service, operation),
            arguments={},
            constraint="No warrant provided for Nexus operation",
            warrant_id="none",
        )

    chain: Optional[List[Any]] = None
    chain_header = raw_headers.get(TENUO_CHAIN_HEADER)
    if chain_header:
        try:
            from tenuo_core import decode_warrant_stack_base64

            chain = list(decode_warrant_stack_base64(chain_header.decode("utf-8")))
            _validate_chain_ends_with_warrant(
                chain,
                warrant,
                operation="Nexus operation",
            )
        except Exception as exc:
            raise ChainValidationError(
                reason=f"Invalid Nexus warrant chain header: {exc}",
                depth=0,
            ) from exc

    tool_name = _ctx_tool_name(ctx, endpoint, service, operation)
    args = nexus_input_args(input)
    pop_header = raw_headers.get(TENUO_POP_HEADER)
    if not pop_header:
        raise PopVerificationError(
            reason="Missing PoP header for Nexus operation",
            activity_name=tool_name,
        )
    try:
        pop_bytes = base64.b64decode(pop_header, validate=True)
    except Exception as exc:
        raise PopVerificationError(
            reason=f"Malformed Nexus PoP header: {exc}",
            activity_name=tool_name,
        ) from exc

    try:
        from tenuo_core import Authorizer

        revocation_list = config._last_good_revocation_list or config.revocation_list
        authorizer = _build_authorizer(
            Authorizer,
            config.trusted_roots,
            config,
            revocation_list=revocation_list,
        )
        if chain:
            authorizer.check_chain(chain, tool_name, args, signature=pop_bytes)
        else:
            authorizer.authorize_one(warrant, tool_name, args, signature=pop_bytes)
    except Exception as exc:
        raise TenuoContextError(
            f"Nexus operation authorization failed for {tool_name!r}: {exc}"
        ) from exc
    return warrant


def _ctx_tool_name(
    ctx: Any,
    endpoint: Optional[str],
    service: Optional[str],
    operation: Optional[Any],
) -> str:
    service_name = service or getattr(ctx, "service", None)
    operation_name = operation or getattr(ctx, "operation", None)
    endpoint_name = endpoint or "unknown-endpoint"
    return nexus_tool_name(
        endpoint_name,
        operation_name or "unknown-operation",
        service=service_name,
    )


def _operation_name(operation: Any) -> str:
    try:
        import nexusrpc

        nexus_operation = nexusrpc.get_operation(operation)
        nexus_name = getattr(nexus_operation, "name", None)
        if isinstance(nexus_name, str) and nexus_name:
            return nexus_name
    except Exception:
        pass

    name = getattr(operation, "name", None)
    if isinstance(name, str) and name:
        return name
    if isinstance(operation, str):
        return operation
    return getattr(operation, "__name__", str(operation))


def _encode_nexus_headers(headers: Mapping[str, bytes]) -> Dict[str, str]:
    encoded = {
        k: base64.b64encode(bytes(v)).decode("ascii")
        for k, v in headers.items()
        if k.startswith("x-tenuo-")
    }
    encoded[TENUO_NEXUS_HEADER_ENCODING] = _TENUO_NEXUS_HEADER_ENCODING_V1
    return encoded


def _decode_nexus_headers(headers: Mapping[str, Any]) -> Dict[str, bytes]:
    if headers.get(TENUO_NEXUS_HEADER_ENCODING) != _TENUO_NEXUS_HEADER_ENCODING_V1:
        return {
            k: v if isinstance(v, bytes) else str(v).encode("utf-8")
            for k, v in headers.items()
            if k != TENUO_NEXUS_HEADER_ENCODING and k.startswith("x-tenuo-")
        }
    decoded: Dict[str, bytes] = {}
    for k, v in headers.items():
        if k == TENUO_NEXUS_HEADER_ENCODING or not k.startswith("x-tenuo-"):
            continue
        try:
            raw = v if isinstance(v, bytes) else str(v).encode("ascii")
            decoded[k] = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise ChainValidationError(
                reason=f"Failed to decode Nexus Tenuo header {k!r}: {exc}",
                depth=0,
            ) from exc
    return decoded


def _as_nexus_unauthorized(exc: Exception) -> Exception:
    try:
        import nexusrpc

        return nexusrpc.HandlerError(
            str(exc),
            type=nexusrpc.HandlerErrorType.UNAUTHORIZED,
        )
    except Exception:
        return exc
