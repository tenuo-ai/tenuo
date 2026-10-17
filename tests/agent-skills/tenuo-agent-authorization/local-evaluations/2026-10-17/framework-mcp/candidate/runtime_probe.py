"""Read-only probes for the actual imported runtime, including native hash."""
import hashlib
import importlib.metadata as metadata
import inspect
import json
import platform
import subprocess
from pathlib import Path

import tenuo
import tenuo_core
import tenuo_core.tenuo_core as native
from tenuo import Warrant
from tenuo.mcp import MCPVerifier
from mcp import ClientSession


def artifact(module):
    path = Path(module.__file__).resolve()
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


source = Path(tenuo.__file__).resolve().parents[2]
print(json.dumps({
    "python": platform.python_version(),
    "versions": {name: metadata.version(name) for name in ("tenuo", "mcp", "fastmcp", "pydantic", "pytest")},
    "tenuo": artifact(tenuo), "tenuo_core": artifact(tenuo_core), "native": artifact(native),
    "source_commit": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip(),
    "signatures": {"MCPVerifier": str(inspect.signature(MCPVerifier)),
                   "MCPVerifier.verify": str(inspect.signature(MCPVerifier.verify)),
                   "Warrant.issue": str(inspect.signature(Warrant.issue)),
                   "ClientSession.call_tool": str(inspect.signature(ClientSession.call_tool))},
}, indent=2))
