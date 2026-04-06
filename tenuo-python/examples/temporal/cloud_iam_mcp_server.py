#!/usr/bin/env python3
"""
Stdio MCP server for examples/temporal/cloud_iam_layering.py.

Exposes ``s3_get_object`` as an MCP tool. Each ``tools/call`` is verified with
``MCPVerifier`` (warrant + PoP in ``params._meta["tenuo"]``) before any AWS
access. This is the **second** Tenuo boundary after ``TenuoPlugin`` on the
Temporal activity; IAM on the worker remains the third layer at the AWS API.

Environment:
  TENUO_CLOUD_IAM_MCP_TRUSTED_ROOT_HEX — hex-encoded Ed25519 issuer public key (64 hex chars)
  TENUO_DEMO_DRY_RUN=1 — skip boto3; return a synthetic body (no AWS credentials)

Run: spawned by ``cloud_iam_layering.py`` via ``SecureMCPClient`` (stdio).
"""

from __future__ import annotations

import asyncio
import os
import sys

try:
    from mcp import types
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
except ImportError:
    print("Install MCP: uv pip install 'tenuo[mcp]'", file=sys.stderr)
    sys.exit(1)

from tenuo import Authorizer, PublicKey
from tenuo.mcp.server import MCPVerifier

DRY_RUN = os.environ.get("TENUO_DEMO_DRY_RUN") == "1"


def _meta_to_dict(meta: object | None) -> dict | None:
    if meta is None:
        return None
    if hasattr(meta, "model_dump"):
        return meta.model_dump(mode="python")
    if isinstance(meta, dict):
        return meta
    return None


def main() -> None:
    hex_key = os.environ.get("TENUO_CLOUD_IAM_MCP_TRUSTED_ROOT_HEX", "").strip()
    if not hex_key:
        print("Missing TENUO_CLOUD_IAM_MCP_TRUSTED_ROOT_HEX", file=sys.stderr)
        sys.exit(1)

    issuer_pk = PublicKey.from_bytes(bytes.fromhex(hex_key))
    authorizer = Authorizer(trusted_roots=[issuer_pk])
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)

    server = Server("tenuo-cloud-iam-mcp-demo")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="s3_get_object",
                description="S3 GetObject (authorized by Tenuo MCPVerifier)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "bucket": {"type": "string"},
                        "key": {"type": "string"},
                    },
                    "required": ["bucket", "key"],
                },
            ),
        ]

    async def handle_call_tool(req: types.CallToolRequest) -> types.ServerResult:
        params = req.params
        tool_name = params.name
        arguments = dict(params.arguments or {})
        meta_dict = _meta_to_dict(params.meta)

        v = verifier.verify(tool_name, arguments, meta=meta_dict)
        if not v.allowed:
            return types.ServerResult(
                types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=v.denial_reason or "MCP authorization denied",
                        )
                    ],
                    isError=True,
                )
            )

        if tool_name != "s3_get_object":
            return types.ServerResult(
                types.CallToolResult(
                    content=[
                        types.TextContent(type="text", text=f"Unknown tool: {tool_name}")
                    ],
                    isError=True,
                )
            )

        bucket = str(v.clean_arguments.get("bucket", ""))
        key = str(v.clean_arguments.get("key", ""))

        if DRY_RUN:
            body = f"[dry-run] would read s3://{bucket}/{key}"
            return types.ServerResult(
                types.CallToolResult(
                    content=[types.TextContent(type="text", text=body)],
                    isError=False,
                )
            )

        try:
            import boto3  # type: ignore[import-not-found]

            s3 = boto3.client("s3")
            response = s3.get_object(Bucket=bucket, Key=key)
            text = response["Body"].read().decode("utf-8")
            return types.ServerResult(
                types.CallToolResult(
                    content=[types.TextContent(type="text", text=text)],
                    isError=False,
                )
            )
        except ImportError:
            return types.ServerResult(
                types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=f"[boto3 not installed] s3://{bucket}/{key}",
                        )
                    ],
                    isError=True,
                )
            )
        except Exception as exc:
            return types.ServerResult(
                types.CallToolResult(
                    content=[types.TextContent(type="text", text=str(exc))],
                    isError=True,
                )
            )

    server.request_handlers[types.CallToolRequest] = handle_call_tool

    async def run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(run())


if __name__ == "__main__":
    main()
