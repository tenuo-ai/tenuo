import os, sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def call_refund(journal, order_id, amount_cents, meta=None):
    parameters = StdioServerParameters(command=sys.executable, args=[str(Path(__file__).with_name("server.py"))], env={**os.environ, "REFUND_JOURNAL":str(journal)})
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("refund_order", {"order_id": order_id, "amount_cents": amount_cents}, meta=meta)
