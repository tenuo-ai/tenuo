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
