"""
Tool schemas for Tenuo - define risk levels and recommended constraints.

This module provides a registry of tool schemas that inform:
- What constraints are recommended for each tool
- Risk levels (critical/high/medium/low)
- Whether at least one constraint is required

Usage:
    from tenuo import ToolSchema, register_schema, get_schema

    # Get schema for a built-in tool
    schema = get_schema("read_file")
    print(schema.risk_level)  # "medium"

    # Register a custom tool schema
    register_schema("my_tool", ToolSchema(
        recommended_constraints=["resource_id", "action"],
        require_at_least_one=True,
        risk_level="high",
    ))
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ToolSchema:
    """
    Schema defining constraints and risk level for a tool.

    Attributes:
        recommended_constraints: List of constraint keys recommended for this tool
        require_at_least_one: If True, tool must have at least one constraint
        risk_level: One of "critical", "high", "medium", "low"
        description: Optional description of the tool's security implications
    """
    recommended_constraints: List[str] = field(default_factory=list)
    require_at_least_one: bool = False
    risk_level: str = "medium"  # critical, high, medium, low
    description: Optional[str] = None

    def __post_init__(self) -> None:
        valid_levels = {"critical", "high", "medium", "low"}
        if self.risk_level not in valid_levels:
            raise ValueError(
                f"Invalid risk_level '{self.risk_level}'. "
                f"Must be one of: {valid_levels}"
            )


# Built-in schemas for common tools
TOOL_SCHEMAS: Dict[str, ToolSchema] = {
    # File system tools
    "read_file": ToolSchema(
        recommended_constraints=["path"],
        require_at_least_one=True,
        risk_level="medium",
        description="Read files from the filesystem",
    ),
    "write_file": ToolSchema(
        recommended_constraints=["path"],
        require_at_least_one=True,
        risk_level="high",
        description="Write files to the filesystem",
    ),
    "delete_file": ToolSchema(
        recommended_constraints=["path"],
        require_at_least_one=True,
        risk_level="critical",
        description="Delete files from the filesystem",
    ),
    "list_directory": ToolSchema(
        recommended_constraints=["path"],
        require_at_least_one=False,
        risk_level="low",
        description="List directory contents",
    ),

    # Network tools
    "http_request": ToolSchema(
        recommended_constraints=["url", "domain", "method"],
        require_at_least_one=True,
        risk_level="critical",
        description="Make HTTP requests to external services",
    ),
    "fetch_url": ToolSchema(
        recommended_constraints=["url", "domain"],
        require_at_least_one=True,
        risk_level="high",
        description="Fetch content from URLs",
    ),

    # Communication tools
    "send_email": ToolSchema(
        recommended_constraints=["to", "domain"],
        require_at_least_one=True,
        risk_level="high",
        description="Send emails",
    ),
    "send_message": ToolSchema(
        recommended_constraints=["recipient", "channel"],
        require_at_least_one=True,
        risk_level="high",
        description="Send messages to users or channels",
    ),

    # Database tools
    "query_db": ToolSchema(
        recommended_constraints=["table", "query_type"],
        require_at_least_one=True,
        risk_level="high",
        description="Query database",
    ),
    "execute_sql": ToolSchema(
        recommended_constraints=["table", "operation"],
        require_at_least_one=True,
        risk_level="critical",
        description="Execute raw SQL queries",
    ),

    # Code execution tools
    "run_code": ToolSchema(
        recommended_constraints=["language", "timeout"],
        require_at_least_one=True,
        risk_level="critical",
        description="Execute arbitrary code",
    ),
    "shell_command": ToolSchema(
        recommended_constraints=["command", "working_dir"],
        require_at_least_one=True,
        risk_level="critical",
        description="Execute shell commands",
    ),

    # Search tools
    "web_search": ToolSchema(
        recommended_constraints=["query", "domain"],
        require_at_least_one=False,
        risk_level="low",
        description="Search the web",
    ),
    "search_documents": ToolSchema(
        recommended_constraints=["query", "collection"],
        require_at_least_one=False,
        risk_level="low",
        description="Search document collections",
    ),
}


def register_schema(tool_name: str, schema: ToolSchema) -> None:
    """
    Register a custom tool schema.

    Args:
        tool_name: Name of the tool
        schema: ToolSchema defining constraints and risk level

    Example:
        register_schema("my_api_call", ToolSchema(
            recommended_constraints=["endpoint", "method"],
            require_at_least_one=True,
            risk_level="high",
        ))
    """
    TOOL_SCHEMAS[tool_name] = schema


def get_schema(tool_name: str) -> Optional[ToolSchema]:
    """
    Get the schema for a tool.

    Args:
        tool_name: Name of the tool

    Returns:
        ToolSchema if registered, None otherwise
    """
    return TOOL_SCHEMAS.get(tool_name)


def recommended_constraints(tools: list) -> None:
    """
    Print recommended constraints for tools based on risk level.

    Args:
        tools: List of tools (LangChain tools or callables)

    Example:
        tools = [read_file, send_email, http_request]
        recommended_constraints(tools)

        # Output:
        # Recommended constraints:
        #   http_request: ⚠️  REQUIRED (critical) - url, domain, method
        #   send_email: ⚠️  recommended (high) - to, domain
        #   read_file: recommended (medium) - path
    """
    print("Recommended constraints:\n")

    # Sort by risk level (critical first)
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    items = []
    for tool in tools:
        name = _get_tool_name(tool)
        schema = TOOL_SCHEMAS.get(name)
        if schema and schema.recommended_constraints:
            items.append((name, schema))

    items.sort(key=lambda x: risk_order.get(x[1].risk_level, 99))

    for name, schema in items:
        if schema.risk_level == "critical":
            level_str = "⚠️  REQUIRED (critical)"
        elif schema.risk_level == "high":
            level_str = "⚠️  recommended (high)"
        else:
            level_str = f"recommended ({schema.risk_level})"

        constraints_str = ", ".join(schema.recommended_constraints)
        print(f"  {name}: {level_str} - {constraints_str}")

    if not items:
        print("  (no schemas registered for these tools)")


def check_constraints(tools: list, constraints: dict) -> List[str]:
    """
    Check which tools are missing recommended constraints.

    Args:
        tools: List of tools to check
        constraints: Dict of constraints from the warrant

    Returns:
        List of warning messages for tools missing constraints
    """
    warnings = []

    for tool in tools:
        name = _get_tool_name(tool)
        schema = TOOL_SCHEMAS.get(name)

        if schema and schema.recommended_constraints:
            # Check if any recommended constraint is present
            has_constraint = any(
                c in constraints for c in schema.recommended_constraints
            )

            if not has_constraint:
                if schema.risk_level == "critical":
                    warnings.append(
                        f"CRITICAL: '{name}' has no constraints. "
                        f"Required: {schema.recommended_constraints}"
                    )
                elif schema.risk_level == "high":
                    warnings.append(
                        f"WARNING: '{name}' has no constraints. "
                        f"Recommended: {schema.recommended_constraints}"
                    )

    return warnings


def _get_tool_name(tool) -> str:
    """Extract tool name from various tool types."""
    # LangChain Tool
    if hasattr(tool, 'name'):
        return tool.name
    # Callable with __name__
    if hasattr(tool, '__name__'):
        return tool.__name__
    # Fallback
    return str(tool)


__all__ = [
    "ToolSchema",
    "TOOL_SCHEMAS",
    "register_schema",
    "get_schema",
    "recommended_constraints",
    "check_constraints",
]
