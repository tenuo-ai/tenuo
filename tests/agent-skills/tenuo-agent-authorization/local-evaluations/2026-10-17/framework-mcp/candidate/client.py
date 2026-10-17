import os, sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def call_refund(journal, order_id, amount_cents, meta=None, *, trusted_root):
    # The local launcher owns configuration; request metadata cannot choose the
    # root. No issuer or holder private keys are passed to the verifier process.
    parameters = StdioServerParameters(
        command=sys.executable, args=[str(Path(__file__).with_name("server.py"))],
        env={"PATH": os.environ.get("PATH", ""), "REFUND_JOURNAL": str(journal),
             "REFUND_TRUSTED_ROOT": trusted_root},
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("refund_order", {"order_id": order_id, "amount_cents": amount_cents}, meta=meta)


def result_is_error(result):
    """MCP 1 uses isError; MCP 2 uses is_error."""
    if "is_error" in type(result).model_fields:
        return result.is_error
    return result.isError
