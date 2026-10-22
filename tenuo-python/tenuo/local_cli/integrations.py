"""Optional framework factories; imports happen only for the selected adapter."""


def local_langchain_tool(tool, *, path=None, warrant=None, key="agent", step=None, **kwargs):
    from tenuo._enforcement import enforce_tool_call, enforce_tool_call_async
    from tenuo.langchain import TenuoTool
    from .runtime import LocalAuthority

    authority = LocalAuthority(path=path, warrant=warrant, key=key)
    authority.require_warrant()

    class LocalTool(TenuoTool):
        def _check_authorization(self, arguments):
            if authority.observing:
                authority.observe(self.name, arguments, step=step, via="langchain",
                                  require_constraints=self.strict, schemas=self._schemas)
                return
            authority.require_warrant()
            with authority.scope() as (snapshot, session, approvals):
                result = enforce_tool_call(
                    tool_name=self.name,
                    tool_args=arguments,
                    bound_warrant=session.bound,
                    trusted_roots=snapshot.roots,
                    warrant_chain=snapshot.chain[:-1],
                    approval_handler=approvals,
                    require_constraints=self.strict,
                    schemas=self._schemas,
                )
                self._emit_and_check(result, session.bound, arguments)

        async def _acheck_authorization(self, arguments):
            if authority.observing:
                authority.observe(self.name, arguments, step=step, via="langchain",
                                  require_constraints=self.strict, schemas=self._schemas)
                return
            authority.require_warrant()
            with authority.scope() as (snapshot, session, approvals):
                result = await enforce_tool_call_async(
                    tool_name=self.name,
                    tool_args=arguments,
                    bound_warrant=session.bound,
                    trusted_roots=snapshot.roots,
                    warrant_chain=snapshot.chain[:-1],
                    approval_handler=approvals,
                    require_constraints=self.strict,
                    schemas=self._schemas,
                )
                self._emit_and_check(result, session.bound, arguments)

    return LocalTool(tool, **kwargs)


def local_mcp_client(*, path=None, warrant=None, key="agent", step=None, **kwargs):
    from contextlib import ExitStack
    from contextvars import ContextVar
    from tenuo.mcp.client import SecureMCPClient
    from .files import DocumentError
    from .runtime import LocalAuthority

    injection = kwargs.get("inject_warrant", True)
    if "approval_handler" in kwargs or not (injection is True or injection == "argument"):
        raise DocumentError("local MCP uses file approvals and always presents its warrant")
    kwargs.setdefault("inject_warrant", True)
    authority = LocalAuthority(path=path, warrant=warrant, key=key)
    authority.require_warrant()
    current_handler = ContextVar("tenuo_local_mcp_approval")

    class LocalClient(SecureMCPClient):
        async def call_tool(
            self,
            tool_name,
            arguments,
            warrant_context=True,
            inject_warrant=None,
            approvals=None,
            timeout=30.0,
            raise_on_tool_error=True,
        ):
            if not warrant_context or not (inject_warrant is None or inject_warrant is True or inject_warrant == "argument"):
                raise DocumentError("local MCP calls cannot disable warrant enforcement or presentation")
            if authority.observing:
                observed = authority.observe(tool_name, arguments, step=step, via="mcp", approvals=approvals)
                # Present the warrant when there is a live one, so the server
                # can check it too; never authorize or block here. An expired
                # warrant isn't presented: the client would refuse the call.
                with ExitStack() as stack:
                    present = False
                    if observed is not None and observed["warrant_id"] is not None:
                        try:
                            snapshot = authority.snapshot(verify=False)
                            if snapshot.chain and not snapshot.chain[-1].is_expired():
                                stack.enter_context(authority.scope(snapshot))
                                present = True
                        except Exception:
                            pass
                    return await super().call_tool(
                        tool_name,
                        arguments,
                        warrant_context=False,
                        inject_warrant=inject_warrant if present else False,
                        approvals=approvals,
                        timeout=timeout,
                        raise_on_tool_error=raise_on_tool_error,
                    )
            authority.require_warrant()
            with authority.scope() as (_, _, handler):
                forwarded = list(approvals or [])

                def collect(request):
                    signed = handler(request)
                    forwarded.extend(signed if isinstance(signed, list) else [signed])
                    return signed

                token = current_handler.set(collect)
                try:
                    return await super().call_tool(
                        tool_name,
                        arguments,
                        warrant_context=True,
                        inject_warrant=inject_warrant,
                        approvals=forwarded,
                        timeout=timeout,
                        raise_on_tool_error=raise_on_tool_error,
                    )
                finally:
                    current_handler.reset(token)

        def create_protected_tool(self, mcp_tool):
            async def invoke(**arguments):
                approvals = arguments.pop("_approvals", None)
                return await self.call_tool(mcp_tool.name, arguments, approvals=approvals)

            invoke.__name__ = mcp_tool.name
            invoke.__doc__ = mcp_tool.description or mcp_tool.name
            return invoke

    return LocalClient(approval_handler=lambda request: current_handler.get()(request), **kwargs)


def local_mcp_verifier(*, path=None, key=None, step=None, **kwargs):
    from tenuo.mcp.server import MCPVerificationResult, MCPVerifier
    from .files import DocumentError
    from .runtime import LocalAuthority

    if kwargs.get("require_warrant", True) is not True or "authorizer" in kwargs or "runtime" in kwargs:
        raise DocumentError("local MCP verification requires warrants and independently loaded trust")
    authority = LocalAuthority(path=path, key=key)

    class LocalVerifier(MCPVerifier):
        def verify(self, tool_name, arguments, meta=None):
            if authority.observing:
                return observe(tool_name, arguments, meta)
            try:
                with authority.scope() as (snapshot, _, _):
                    return MCPVerifier(authorizer=snapshot.authorizer, **kwargs).verify(tool_name, arguments, meta=meta)
            except Exception:
                return MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments={},
                    constraints={},
                    denial_reason="Local verification data unavailable; run tenuo-cli doctor",
                    jsonrpc_error_code=-32001,
                    error_type="configuration_error",
                )

    def observe(tool_name, arguments, meta):
        """Record the call and the verifier's decision, then let it run."""
        from tenuo.mcp.server import _coerce_meta
        from .runtime import _kind, failed_argument

        args = dict(arguments) if isinstance(arguments, dict) else {}
        envelope = args.pop("_tenuo", None)
        try:
            resolved = _coerce_meta(meta)
        except Exception:
            resolved = None
        presented = envelope is not None or (resolved is not None and resolved.get("tenuo") is not None)
        decision, reason, warrant_id, argument = None, "no_warrant", None, None
        if presented:
            try:
                with authority.scope() as (snapshot, _, _):
                    verifier = MCPVerifier(authorizer=snapshot.authorizer, **kwargs)
                    result = verifier.verify(tool_name, arguments, meta=meta)
                decision = "allow" if result.allowed else "deny"
                reason = None if result.allowed else (result.error_type or "denied")
                warrant_id = result.warrant_id
                argument = failed_argument(result)
                if result.allowed:
                    args = dict(result.clean_arguments)
            except Exception as exc:
                decision, reason = "deny", _kind(exc)
        try:
            authority.record(
                tool_name, args, decision=decision, reason=reason, warrant_id=warrant_id, argument=argument, step=step,
                via="mcp-server",
            )
        except Exception:
            import logging

            logging.getLogger(__name__).warning("Tenuo observe: could not record a call to %s", tool_name, exc_info=True)
        observed = MCPVerificationResult(
            allowed=True, tool=tool_name, clean_arguments=args, constraints={}, warrant_id=warrant_id
        )
        setattr(observed, "observed", {"decision": decision, "reason": reason})
        return observed

    if authority.observing:
        try:
            authorizer = authority.snapshot(verify=False).authorizer
        except Exception:
            from tenuo import Authorizer

            authorizer = Authorizer(trusted_roots=[])
    else:
        authorizer = authority.snapshot().authorizer
    return LocalVerifier(authorizer=authorizer, **kwargs)
