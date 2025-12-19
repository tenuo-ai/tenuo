from typing import Dict, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from tenuo_core import Constraint # type: ignore

class Constraints(Dict[str, Any]):
    """
    Helper class for defining capability constraints.
    
    Acts as a dictionary mapping field names to Constraint objects.
    
    Example:
        constraints = Constraints()
        constraints.add("cluster", Exact("staging-web"))
        constraints.add("replicas", Range(max=5))
        
        # Or using kwargs constructor:
        constraints = Constraints(
            cluster=Exact("staging-web"),
            replicas=Range(max=5)
        )
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def add(self, field: str, constraint: 'Constraint') -> 'Constraints':
        """Add a constraint for a field."""
        self[field] = constraint
        return self

    @classmethod
    def empty(cls) -> 'Constraints':
        """Return an empty Constraints object."""
        return cls()

    @staticmethod
    def for_tool(tool: str, constraints: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Create a capabilities dictionary for a single tool."""
        return {tool: constraints}

    @staticmethod
    def for_tools(tools: list, constraints: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Create a capabilities dictionary for multiple tools with shared constraints.
        
        Example:
            capabilities = Constraints.for_tools(
                ["read_file", "write_file"],
                {"path": Pattern("/data/*")}
            )
            # Returns: {"read_file": {"path": ...}, "write_file": {"path": ...}}
        """
        return {tool: dict(constraints) for tool in tools}
