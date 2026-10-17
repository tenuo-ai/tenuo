"""Optional framework factories; imports happen only for the selected adapter."""


def local_langchain_tool(tool, *, path=None, warrant, key="agent", **kwargs):
    from tenuo._enforcement import enforce_tool_call, enforce_tool_call_async
    from tenuo.langchain import TenuoTool
    from .runtime import LocalAuthority

    authority = LocalAuthority(path=path, warrant=warrant, key=key)

    class LocalTool(TenuoTool):
        def _check_authorization(self, arguments):
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


def local_mcp_client(*, path=None, warrant, key="agent", **kwargs):
    from contextvars import ContextVar
    from tenuo.mcp.client import SecureMCPClient
    from .files import DocumentError
    from .runtime import LocalAuthority

    if "approval_handler" in kwargs or kwargs.get("inject_warrant") is False:
        raise DocumentError("local MCP uses file approvals and always presents its warrant")
    kwargs.setdefault("inject_warrant", True)
    authority = LocalAuthority(path=path, warrant=warrant, key=key)
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
            if not warrant_context or inject_warrant is False:
                raise DocumentError("local MCP calls cannot disable warrant enforcement or presentation")
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


def local_mcp_verifier(*, path=None, key=None, **kwargs):
    from tenuo.mcp.server import MCPVerificationResult, MCPVerifier
    from .files import DocumentError
    from .runtime import LocalAuthority

    if kwargs.get("require_warrant") is False or "authorizer" in kwargs or "runtime" in kwargs:
        raise DocumentError("local MCP verification requires warrants and independently loaded trust")
    authority = LocalAuthority(path=path, key=key)

    class LocalVerifier(MCPVerifier):
        def verify(self, tool_name, arguments, meta=None):
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

    return LocalVerifier(authorizer=authority.snapshot().authorizer, **kwargs)
