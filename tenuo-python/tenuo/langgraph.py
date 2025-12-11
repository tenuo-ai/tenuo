from __future__ import annotations
from typing import TypeVar, Optional, Callable, Any
from dataclasses import dataclass, field
from langgraph.graph import StateGraph, END, START
from tenuo import Warrant, Keypair, AuthorizationError
from tenuo.decorators import set_warrant_context, set_keypair_context
import yaml
import copy
import re
import logging

# Module logger
logger = logging.getLogger("tenuo.langgraph")

# Reserved state keys
TENUO_WARRANT = "__tenuo_warrant__"
TENUO_STACK = "__tenuo_stack__"


# =============================================================================
# Validation Error
# =============================================================================

class InterpolationValidationError(AuthorizationError):
    """Raised when an interpolated value fails validation."""
    pass


# =============================================================================
# Config
# =============================================================================

@dataclass
class AttenuationRule:
    """How to narrow a warrant for a specific node."""
    tools: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass
class NodeConfig:
    """Configuration for a single node."""
    role: Optional[str] = None  # "supervisor" or None
    attenuate: Optional[AttenuationRule] = None


@dataclass
class SecureGraphConfig:
    """Loaded from tenuo-graph.yaml."""
    allow_unlisted_nodes: bool = False
    max_stack_depth: int = 16
    nodes: dict[str, NodeConfig] = field(default_factory=dict)
    
    @classmethod
    def from_file(cls, path: str) -> SecureGraphConfig:
        with open(path) as f:
            raw = yaml.safe_load(f)
        return cls.from_dict(raw)
    
    @classmethod
    def from_dict(cls, raw: dict) -> SecureGraphConfig:
        settings = raw.get("settings", {})
        nodes = {}
        
        for name, node_raw in raw.get("nodes", {}).items():
            attenuation = None
            if "attenuate" in node_raw:
                att_raw = node_raw["attenuate"]
                attenuation = AttenuationRule(
                    tools=att_raw.get("tools", []),
                    constraints=att_raw.get("constraints", {}),
                )
            nodes[name] = NodeConfig(
                role=node_raw.get("role"),
                attenuate=attenuation,
            )
        
        return cls(
            allow_unlisted_nodes=settings.get("allow_unlisted_nodes", False),
            max_stack_depth=settings.get("max_stack_depth", 16),
            nodes=nodes,
        )


# =============================================================================
# SecureGraph
# =============================================================================

class SecureGraph:
    """
    Wraps a LangGraph StateGraph with automatic warrant management.
    
    Responsibilities:
    1. Inject warrant state into graph execution
    2. Attenuate warrants on node entry (push stack)
    3. Restore parent warrants on node exit (pop stack)
    4. Set ContextVars so tools see the current warrant
    
    Usage:
        graph = StateGraph(AgentState)
        graph.add_node("supervisor", supervisor_fn)
        graph.add_node("researcher", researcher_fn)
        graph.add_edge("supervisor", "researcher")
        graph.add_edge("researcher", "supervisor")
        
        secure = SecureGraph(
            graph=graph,
            config="tenuo-graph.yaml",
            root_warrant=root_warrant,
            keypair=keypair,
        )
        
        app = secure.compile()
        result = app.invoke({"input": "Research Q3 results"})
    """
    
    def __init__(
        self,
        graph: StateGraph,
        config: str | dict | SecureGraphConfig,
        root_warrant: Warrant,
        keypair: Optional[Keypair] = None,
    ):
        self.original_graph = graph
        self.config = self._load_config(config)
        self.root_warrant = root_warrant
        self.keypair = keypair
        
        # Track which nodes are supervisors (for delegation detection)
        self._supervisors = {
            name for name, cfg in self.config.nodes.items() 
            if cfg.role == "supervisor"
        }
        
        # Build wrapped graph
        self._wrapped_graph = self._wrap_graph()
    
    def _load_config(self, config) -> SecureGraphConfig:
        if isinstance(config, SecureGraphConfig):
            return config
        if isinstance(config, str):
            return SecureGraphConfig.from_file(config)
        if isinstance(config, dict):
            return SecureGraphConfig.from_dict(config)
        raise TypeError(f"Invalid config type: {type(config)}")
    
    def _wrap_graph(self) -> StateGraph:
        """Create a new graph with wrapped nodes."""
        # Copy the graph structure
        wrapped = StateGraph(self.original_graph.state_schema)
        
        # Wrap each node
        for name, node_spec in self.original_graph.nodes.items():
            runnable = node_spec.runnable
            wrapped.add_node(name, self._wrap_node(name, runnable))
        
        # Copy edges (with interception for warrant management)
        for edge in self.original_graph.edges:
            # Edges are tuples (src, dst)
            wrapped.add_edge(edge[0], edge[1])
            
        # Copy conditional edges (branches)
        for src, branches in self.original_graph.branches.items():
            for branch in branches.values():
                wrapped.add_conditional_edges(
                    src,
                    self._wrap_router(branch.path, src),
                    branch.ends
                )
        
        # Set entry point
        if hasattr(self.original_graph, '_entry_point'):
            wrapped.set_entry_point(self.original_graph._entry_point)
        
        return wrapped
    
    def _wrap_node(self, name: str, fn: Callable) -> Callable:
        """
        Wrap a node function to:
        1. Compute the attenuated warrant for this node
        2. Set ContextVars so tools can access it
        3. Execute the original function
        """
        node_config = self.config.nodes.get(name)
        
        # Validate node is configured (unless allow_unlisted_nodes)
        if node_config is None and not self.config.allow_unlisted_nodes:
            raise ValueError(
                f"Node '{name}' not in tenuo config and allow_unlisted_nodes=false"
            )
        
        def wrapped_node(state: dict) -> dict:
            logger.debug(f"Entering node '{name}'")
            # Get current warrant from state (or root if first node)
            parent_warrant = state.get(TENUO_WARRANT, self.root_warrant)
            stack = state.get(TENUO_STACK, [])
            
            # Compute this node's warrant
            node_warrant = self._attenuate(parent_warrant, name, node_config, state)
            logger.debug(f"Node '{name}' warrant: {node_warrant.id}")
            
            # Set context for tools
            with set_warrant_context(node_warrant), set_keypair_context(self.keypair):
                if hasattr(fn, "invoke"):
                    result = fn.invoke(state)
                else:
                    result = fn(state)
            
            # Ensure result is a dict
            if result is None:
                result = {}
            
            # Inject warrant state for next node
            result[TENUO_WARRANT] = node_warrant
            result[TENUO_STACK] = stack
            
            return result
        
        return wrapped_node
    
    def _wrap_router(self, router_func: Callable, name: str) -> Callable:
        """Wrap a router function to manage warrant stack."""
        
        def wrapped_router(state: dict, **kwargs) -> str:
            # Execute original router
            try:
                # Handle both function and Runnable
                if hasattr(router_func, "invoke"):
                    next_node = router_func.invoke(state, **kwargs)
                else:
                    next_node = router_func(state, **kwargs)
            except Exception as e:
                logger.error(f"Router '{name}' failed: {e}")
                raise e
            
            if next_node == END:
                return next_node

            # Get current state
            stack = state.get(TENUO_STACK, [])
            current_warrant = state.get(TENUO_WARRANT)
            
            # 1. Check for RETURN (Is next_node in the stack?)
            # We search from top (end) to bottom (start)
            return_index = -1
            for i in range(len(stack) - 1, -1, -1):
                # Stack items are now (node_name, warrant)
                if stack[i][0] == next_node:
                    return_index = i
                    break
            
            if return_index != -1:
                # Found target in stack -> POP
                logger.debug(f"Router {name} -> {next_node}")
                logger.debug(f"Return detected (found '{next_node}' in stack). Popping.")
                
                # Pop everything AFTER the target (and the target itself to get its warrant)
                # Wait, if stack has [(A, wA), (B, wB)] and we go to A.
                # We want to restore wA.
                # So we keep everything up to A? No, we pop A and use it.
                # The stack represents "contexts we can return to".
                # If we return to A, we are back in A's context. A is no longer "on the stack" of parents.
                # So we slice the stack to `return_index`.
                
                target_frame = stack[return_index]
                restored_warrant = target_frame[1]
                
                # New stack is everything BELOW the target
                new_stack = stack[:return_index]
                
                state[TENUO_STACK] = new_stack
                state[TENUO_WARRANT] = restored_warrant
                logger.debug(f"Restored warrant: {restored_warrant.id}")
                
            # 2. Check for DELEGATION (Is next_node a managed node?)
            elif next_node in self.config.nodes:
                # Not a return, and destination is managed -> PUSH
                logger.debug(f"Router {name} -> {next_node}")
                logger.debug("Delegation detected. Pushing stack.")
                
                # Enforce Max Stack Depth
                max_depth = self.config.max_stack_depth
                if len(stack) >= max_depth:
                    raise AuthorizationError(f"Max warrant stack depth ({max_depth}) exceeded.")
                
                if current_warrant:
                    # Push (current_node, current_warrant)
                    # We push 'name' (the router's source node) as the return target
                    stack.append((name, current_warrant))
                    state[TENUO_STACK] = stack
            
            else:
                # Unmanaged node transition - do nothing (pass through)
                pass
                    
            return next_node
            
        return wrapped_router
    
    def _attenuate(
        self, 
        parent_warrant: Warrant, 
        node_name: str, 
        node_config: Optional[NodeConfig],
        state: dict,
    ) -> Warrant:
        """
        Compute attenuated warrant for a node.
        
        CRITICAL: Always attenuates from PARENT, never from root.
        
        SECURITY: Interpolated values are validated against the 'validate' regex
        before being used in constraints. This prevents path traversal and injection.
        """
        # No config = inherit parent unchanged
        if node_config is None or node_config.attenuate is None:
            return parent_warrant
        
        rule = node_config.attenuate
        
        # Build constraint dict for attenuation
        constraints = {}
        for constraint_name, constraint_raw in rule.constraints.items():
            # Interpolate state values into constraints, with validation
            interpolated_value = self._interpolate_and_validate(
                constraint_raw, state, constraint_name, node_name
            )
            constraints[constraint_name] = self._build_constraint(interpolated_value)
        
        # Attenuate FROM PARENT (not root!)
        tools_arg = None
        if rule.tools:
            tools_arg = ",".join(rule.tools)
            
        return parent_warrant.attenuate(
            tool=tools_arg,
            constraints=constraints if constraints else None,
            keypair=self.keypair,
        )

    def _interpolate_and_validate(
        self, 
        value: Any, 
        state: dict,
        constraint_name: str,
        node_name: str,
    ) -> Any:
        """
        Interpolate ${state.key} patterns with validation of state values.
        
        SECURITY: This is the critical security boundary for dynamic constraints.
        The 'validate' field in config specifies a regex that STATE VALUES must
        match BEFORE interpolation. This prevents:
        - Path traversal (e.g., "../../../etc/passwd")
        - SQL injection (e.g., "'; DROP TABLE users; --")
        - Command injection (e.g., "; rm -rf /")
        
        Config format:
            constraints:
              path:
                pattern: "/data/${state.project_id}/*"
                validate: "^[a-zA-Z0-9_-]+$"  # Validates project_id VALUE
        
        The validation is applied to the RAW STATE VALUES before they are
        substituted into templates. This ensures attackers cannot inject
        malicious characters via user-controlled state.
        
        Raises:
            InterpolationValidationError: If any state value fails validation
        """
        # Extract validation pattern if present (only at top level of constraint dict)
        validate_pattern = None
        if isinstance(value, dict) and "validate" in value:
            validate_pattern = value["validate"]
        
        # If validation is required, validate state values BEFORE interpolation
        if validate_pattern:
            self._validate_state_values_for_interpolation(
                value, state, validate_pattern, constraint_name, node_name
            )
        
        # Perform interpolation (now safe because state values are validated)
        return self._interpolate(value, state)
    
    def _validate_state_values_for_interpolation(
        self,
        template: Any,
        state: dict,
        validate_pattern: str,
        constraint_name: str,
        node_name: str,
    ) -> None:
        """
        Validate all state values that will be interpolated into the template.
        
        This scans the template for ${state.key} patterns and validates
        each corresponding state value against the validation pattern.
        
        Raises:
            InterpolationValidationError: If any state value fails validation
        """
        compiled = re.compile(validate_pattern)
        interpolation_pattern = re.compile(r"\$\{state\.([a-zA-Z0-9_]+)\}")
        
        def find_and_validate(v: Any) -> None:
            if isinstance(v, str):
                # Find all ${state.key} references in this string
                for match in interpolation_pattern.finditer(v):
                    state_key = match.group(1)
                    if state_key in state:
                        state_value = str(state[state_key])
                        if not compiled.fullmatch(state_value):
                            raise InterpolationValidationError(
                                f"Security violation in node '{node_name}', "
                                f"constraint '{constraint_name}': "
                                f"state value for '{state_key}' = '{state_value}' "
                                f"fails validation pattern '{validate_pattern}'. "
                                f"This may indicate a path traversal or injection attempt."
                            )
            elif isinstance(v, dict):
                for sub_v in v.values():
                    find_and_validate(sub_v)
            elif isinstance(v, list):
                for sub_v in v:
                    find_and_validate(sub_v)
        
        find_and_validate(template)

    def _interpolate(self, value: Any, state: dict) -> Any:
        """
        Recursively interpolate ${state.key} patterns in values.
        
        Note: This method only performs interpolation. Validation is handled
        separately by _interpolate_and_validate() for security.
        """
        if isinstance(value, str):
            if value.startswith("${state.") and value.endswith("}"):
                key = value[8:-1]
                if key in state:
                    return state[key]
                else:
                    logger.warning(f"Interpolation key '{key}' not found in state")
                    return value
            
            # Support partial interpolation: "prefix-${state.id}-suffix"
            pattern = re.compile(r"\$\{state\.([a-zA-Z0-9_]+)\}")
            
            def replace(match):
                key = match.group(1)
                return str(state.get(key, match.group(0)))
            
            return pattern.sub(replace, value)
            
        if isinstance(value, list):
            return [self._interpolate(v, state) for v in value]
        
        if isinstance(value, dict):
            return {k: self._interpolate(v, state) for k, v in value.items()}
            
        return value
    
    def _build_constraint(self, raw: dict) -> Any:
        """
        Convert config constraint to Tenuo constraint type.
        
        Supported formats:
            exact: "value"           -> Exact("value")
            pattern: "/path/*"       -> Pattern("/path/*")
            enum: ["a", "b", "c"]    -> OneOf(["a", "b", "c"])
            min: 0, max: 100         -> Range(0, 100)
            
        The 'validate' field is stripped here (used earlier for security validation).
        """
        from tenuo import Exact, Pattern, Range, OneOf
        
        if "exact" in raw:
            return Exact(raw["exact"])
        if "pattern" in raw:
            return Pattern(raw["pattern"])
        if "enum" in raw:
            return OneOf(raw["enum"])
        if "min" in raw or "max" in raw:
            return Range(min_val=raw.get("min"), max_val=raw.get("max"))
        
        raise ValueError(f"Unknown constraint format: {raw}")
    
    
    def compile(self, **kwargs):
        """Compile the secure graph."""
        return self._wrapped_graph.compile(**kwargs)
    
    def invoke(self, input_state: dict, **kwargs) -> dict:
        """Convenience: compile and invoke."""
        # Inject initial warrant state
        input_state[TENUO_WARRANT] = self.root_warrant
        input_state[TENUO_STACK] = []
        
        app = self.compile(**kwargs)
        return app.invoke(input_state)


# =============================================================================
# Tool Protection (Auto-Instrumentation)
# =============================================================================

# Re-export protect_tool for backward compatibility / convenience
from tenuo.langchain import protect_tool
