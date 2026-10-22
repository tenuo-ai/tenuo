# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = ["tenuo==0.3.2", "mcp==1.30.0", "fastmcp==3.4.9"]
# ///
"""Real MCP stdio metadata: SDK envelope + MCPVerifier, fake payment journal."""
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from common import Task, demonstrate, TransportedConstraintDenial
from tenuo import Authorizer, PublicKey, Warrant
from tenuo_core import sign_meta


def serve():
    from fastmcp import FastMCP
    from fastmcp.exceptions import ToolError
    from fastmcp.server.dependencies import get_context
    from pydantic import StrictInt, StrictStr
    from tenuo.mcp import MCPVerifier
    from tenuo.mcp.server import MCPAuthorizationError

    server = FastMCP("task-bounded payments")
    # Launcher configuration, never selected by request arguments/metadata.
    root = PublicKey.from_bytes(bytes.fromhex(os.environ["DEMO_TRUSTED_ROOT"]))
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[root], clock_tolerance_secs=0))

    @server.tool()
    def pay_invoice(invoice_id: StrictStr, bank_account: StrictStr, amount_cents: StrictInt) -> str:
        """Pay the invoice in integer cents."""
        args = dict(invoice_id=invoice_id, bank_account=bank_account, amount_cents=amount_cents)
        try:
            clean = verifier.verify_or_raise("pay_invoice", args, meta=get_context().request_context.meta)
        except MCPAuthorizationError as exc:
            if exc.result.error_type == "constraint_violation":
                raise ToolError("TASK_CONSTRAINT_DENIED: " + str(exc)) from exc
            raise
        # Only fake effect, after root/chain/holder/argument authorization.
        with Path(os.environ["DEMO_JOURNAL"]).open("a") as journal:
            journal.write(json.dumps(clean) + "\n")
        return "paid"

    server.run(transport="stdio", show_banner=False)


async def main():
    with tempfile.TemporaryDirectory() as directory:
        journal = Path(directory) / "payments.jsonl"
        task = Task()
        parameters = StdioServerParameters(command=sys.executable, args=[__file__, "--server"],
            env={"PATH": os.environ.get("PATH", ""), "DEMO_JOURNAL": str(journal),
                 "DEMO_TRUSTED_ROOT": task.root.to_bytes().hex()})
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                async def dispatch(args):
                    # Use the installed SDK encoder, not a hand-built envelope.
                    meta = {"tenuo": sign_meta([Warrant.from_base64(t) for t in task.chain],
                        task.worker, "pay_invoice", json.dumps(args), int(time.time()))}
                    result = await session.call_tool("pay_invoice", args, meta=meta)
                    error = result.is_error if "is_error" in type(result).model_fields else result.isError
                    if error:
                        message = " ".join(getattr(c, "text", "") for c in result.content)
                        if "TASK_CONSTRAINT_DENIED: " in message:
                            raise TransportedConstraintDenial(message)
                        raise RuntimeError(message)

                await demonstrate(dispatch, lambda: len(journal.read_text().splitlines()) if journal.exists() else 0)


if __name__ == "__main__":
    if "--server" in sys.argv:
        serve()
    else:
        asyncio.run(main())
