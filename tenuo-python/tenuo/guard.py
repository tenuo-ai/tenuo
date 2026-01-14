"""
One-line guard() for instant protection.

This module provides the simplest possible API for adding Tenuo protection
to any LLM client. It auto-detects tool schemas and applies sensible defaults.

Usage:
    from tenuo import guard

    # One line, sensible defaults
    client = guard(OpenAI())

    # With customization
    client = guard(
        OpenAI(),
        root="/app/data",           # Default root for Subpath
        allowed_domains=["api.github.com"],  # For UrlSafe
        allowed_bins=["ls", "cat"],  # For Shlex
    )

The guard() function:
1. Detects the client type (OpenAI, Anthropic, etc.)
2. Scans tool schemas for parameters named 'path', 'url', 'command', etc.
3. Automatically applies appropriate constraints
4. Returns a guarded client that validates all tool calls
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tenuo.guard")

# Parameter name patterns for constraint inference
PATH_PATTERNS = re.compile(r"(path|file|filepath|filename|dir|directory)", re.IGNORECASE)
URL_PATTERNS = re.compile(r"(url|uri|endpoint|href|link)", re.IGNORECASE)
COMMAND_PATTERNS = re.compile(r"(command|cmd|shell|exec|script)", re.IGNORECASE)


def guard(
    client: Any,
    *,
    # Constraint inference
    infer_constraints: bool = True,
    # Subpath defaults
    root: str = "/data",
    # UrlSafe defaults
    allowed_domains: Optional[List[str]] = None,
    block_private: bool = True,
    # Shlex defaults
    allowed_bins: Optional[List[str]] = None,
    # Behavior
    on_denial: str = "raise",
    audit: bool = False,
) -> Any:
    """
    Guard an LLM client with automatic constraint inference.

    This is the simplest way to add Tenuo protection. It auto-detects
    tool schemas and applies sensible security defaults.

    Args:
        client: LLM client (OpenAI, Anthropic, etc.)
        infer_constraints: Auto-detect and apply constraints based on param names
        root: Default root directory for Subpath constraints
        allowed_domains: Allowed domains for UrlSafe (None = block private IPs only)
        block_private: Block private/internal IPs in UrlSafe
        allowed_bins: Allowed binaries for Shlex (default: ["ls", "cat", "echo"])
        on_denial: What to do on constraint violation ("raise", "skip", "log")
        audit: If True, log all decisions without blocking

    Returns:
        Guarded client with same interface as input

    Example:
        # Minimal - just wrap and go
        client = guard(OpenAI())

        # Custom root directory
        client = guard(OpenAI(), root="/app/uploads")

        # Allow specific domains
        client = guard(OpenAI(), allowed_domains=["api.github.com"])

        # Audit mode (log but don't block)
        client = guard(OpenAI(), audit=True)

    The guard automatically:
    - Applies Subpath to params matching 'path', 'file', 'directory', etc.
    - Applies UrlSafe to params matching 'url', 'uri', 'endpoint', etc.
    - Applies Shlex to params matching 'command', 'cmd', 'shell', etc.
    """
    # Detect client type
    client_type = _detect_client_type(client)

    if client_type == "openai":
        return _guard_openai(
            client,
            infer_constraints=infer_constraints,
            root=root,
            allowed_domains=allowed_domains,
            block_private=block_private,
            allowed_bins=allowed_bins,
            on_denial="log" if audit else on_denial,
        )
    elif client_type == "anthropic":
        return _guard_anthropic(
            client,
            infer_constraints=infer_constraints,
            root=root,
            allowed_domains=allowed_domains,
            block_private=block_private,
            allowed_bins=allowed_bins,
            on_denial="log" if audit else on_denial,
        )
    else:
        logger.warning(f"Unknown client type: {type(client)}. Returning unguarded.")
        return client


def _detect_client_type(client: Any) -> str:
    """Detect the type of LLM client."""
    type_name = type(client).__module__ + "." + type(client).__name__

    if "openai" in type_name.lower():
        return "openai"
    elif "anthropic" in type_name.lower():
        return "anthropic"
    elif "vertexai" in type_name.lower() or "google" in type_name.lower():
        return "vertex"
    else:
        return "unknown"


def _guard_openai(
    client: Any,
    *,
    infer_constraints: bool,
    root: str,
    allowed_domains: Optional[List[str]],
    block_private: bool,
    allowed_bins: Optional[List[str]],
    on_denial: str,
) -> Any:
    """Guard an OpenAI client."""
    from .openai import GuardBuilder
    from .constraints import Subpath, UrlSafe, Shlex

    builder = GuardBuilder(client).on_denial(on_denial)  # type: ignore[arg-type]

    if infer_constraints:
        # Get tools from client if available
        tools = _extract_openai_tools(client)
        constraints = _infer_constraints(
            tools,
            root=root,
            allowed_domains=allowed_domains,
            block_private=block_private,
            allowed_bins=allowed_bins,
        )

        for tool_name, tool_constraints in constraints.items():
            builder.allow(tool_name, **tool_constraints)

        # If no tools found, set up wildcard tool with default constraints
        if not tools:
            logger.info("No tools detected. Setting up wildcard constraints.")
            # Allow a wildcard tool that will apply constraints to common parameter names
            builder.allow(
                "*",  # Wildcard - applies to any tool
                path=Subpath(root),
                file=Subpath(root),
                filepath=Subpath(root),
                url=UrlSafe(allow_domains=allowed_domains),
                command=Shlex(allow=allowed_bins or ["ls", "cat", "echo"]),
                cmd=Shlex(allow=allowed_bins or ["ls", "cat", "echo"]),
            )

    return builder.build()


def _guard_anthropic(
    client: Any,
    **kwargs,
) -> Any:
    """Guard an Anthropic client (placeholder for future implementation)."""
    logger.warning("Anthropic guard not yet implemented. Returning unguarded client.")
    return client


def _extract_openai_tools(client: Any) -> List[Dict[str, Any]]:
    """Extract tool definitions from an OpenAI client or its configuration."""
    tools = []

    # Check for tools attribute
    if hasattr(client, "_tools"):
        tools = client._tools
    elif hasattr(client, "tools"):
        tools = client.tools

    # Normalize tool format
    normalized = []
    for tool in tools:
        if isinstance(tool, dict):
            if "function" in tool:
                normalized.append(tool["function"])
            else:
                normalized.append(tool)
        elif hasattr(tool, "function"):
            normalized.append(tool.function)

    return normalized


def _infer_constraints(
    tools: List[Dict[str, Any]],
    *,
    root: str,
    allowed_domains: Optional[List[str]],
    block_private: bool,
    allowed_bins: Optional[List[str]],
) -> Dict[str, Dict[str, Any]]:
    """Infer constraints from tool schemas based on parameter names."""
    from .constraints import Subpath, UrlSafe, Shlex

    constraints: Dict[str, Dict[str, Any]] = {}

    for tool in tools:
        tool_name = tool.get("name", "")
        parameters = tool.get("parameters", {})
        properties = parameters.get("properties", {})

        tool_constraints: Dict[str, Any] = {}

        for param_name, param_schema in properties.items():
            # Check for path-like parameters
            if PATH_PATTERNS.search(param_name):
                tool_constraints[param_name] = Subpath(root)
                logger.debug(f"Inferred Subpath for {tool_name}.{param_name}")

            # Check for URL-like parameters
            elif URL_PATTERNS.search(param_name):
                tool_constraints[param_name] = UrlSafe(
                    allow_domains=allowed_domains,
                )
                logger.debug(f"Inferred UrlSafe for {tool_name}.{param_name}")

            # Check for command-like parameters
            elif COMMAND_PATTERNS.search(param_name):
                bins = allowed_bins or ["ls", "cat", "echo", "head", "tail", "wc"]
                tool_constraints[param_name] = Shlex(allow=bins)
                logger.debug(f"Inferred Shlex for {tool_name}.{param_name}")

        if tool_constraints:
            constraints[tool_name] = tool_constraints

    return constraints


# =============================================================================
# Exports
# =============================================================================

__all__ = ["guard"]
