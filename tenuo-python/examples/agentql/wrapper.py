from typing import Any, List, Dict, Callable, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
import inspect
import time
from tenuo import Warrant, SigningKey, AuthorizationDenied
from lazy_locator import LazySemanticLocator

@dataclass
class AuditEntry:
    timestamp: str
    action: str
    target: str
    result: str
    warrant_depth: int
    warrant_id: str
    latency_ms: float

@dataclass
class PerformanceMetrics:
    """Track authorization performance metrics."""
    total_authorizations: int = 0
    allowed_count: int = 0
    denied_count: int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.total_authorizations if self.total_authorizations > 0 else 0.0

    def record(self, allowed: bool, latency_ms: float):
        self.total_authorizations += 1
        if allowed:
            self.allowed_count += 1
        else:
            self.denied_count += 1
        self.total_latency_ms += latency_ms

# Method mapping: Maps AgentQL method names to (capability_name, args_extractor)
# This makes the wrapper adaptable if AgentQL's API changes
METHOD_TO_CAPABILITY = {
    "goto": ("navigate", lambda a, k: {"url": a[0] if a else k.get("url")}),
    "navigate": ("navigate", lambda a, k: {"url": a[0] if a else k.get("url")}),
    "click": ("click", lambda a, k: {"element": a[0] if a else k.get("element", "unknown")}),
    "fill": ("fill", lambda a, k: {"element": a[0] if len(a) > 1 else k.get("element", "unknown")}),
    # query_data/query_elements are mapped to "query" capability.
    # This enables Data Loss Prevention (DLP) by restricting which fields can be extracted.
    "query_data": ("query", lambda a, k: {"query": a[0] if a else k.get("query", "unknown")}),
    "query_elements": ("query", lambda a, k: {"query": a[0] if a else k.get("query", "unknown")}),
}

def format_denial_error(e: AuthorizationDenied) -> str:
    """
    Strip debug URL from error message for clean demo output.

    Args:
        e: The authorization denial exception

    Returns:
        Cleaned error message without debug URLs
    """
    return str(e).split("Debug at")[0].strip()

def normalize_semantic_label(raw_label: str) -> str:
    """
    Normalize AgentQL query syntax to semantic label.

    Examples:
        "{ search_box }" -> "search_box"
        "search_box" -> "search_box"

    Args:
        raw_label: Raw selector/query string

    Returns:
        Normalized semantic label
    """
    return raw_label.replace("{", "").replace("}", "").strip()

def is_agentql_query(selector: str) -> bool:
    """Check if selector looks like an AgentQL semantic query."""
    return "{" in selector or " " in selector

class TenuoAgentQLAgent:
    """
    A secure wrapper around AgentQL that enforces Tenuo warrants using dynamic proxying.
    """
    def __init__(self, warrant: Warrant, keypair: Optional[SigningKey] = None):
        """
        Initialize the secure agent wrapper.
        
        Args:
            warrant: The Tenuo warrant defining allowed capabilities.
            keypair: The signing key matching the warrant's holder.
                     If None, a new ephemeral key is generated (ONLY for testing/demos where the warrant is also ephemeral).
                     In production, YOU MUST provide the keypair that matches the warrant's holder_id.
        """
        self.warrant = warrant
        # If keypair is not provided, generate ephemeral one (Demo Mode)
        # Note: This only works if the warrant is ALSO minted for this new public key immediately after,
        # or if we are in a mode where we don't strictly enforce PoP (bad practice).
        # For strict PoP, the warrant MUST be minted for the public key of the keypair provided here.
        self.keypair = keypair if keypair else SigningKey.generate()
        self.bound = warrant.bind(self.keypair)
        self.audit_log: List[AuditEntry] = []
        self.metrics = PerformanceMetrics()

    def start_session(self, headless: bool = False, on_page_created: Optional[Callable] = None,
                      window_position: Optional[tuple] = None, window_size: Optional[tuple] = None,
                      force_mock: bool = False):
        if force_mock:
            # Force mock mode for offline demos
            from mock_agentql import MockSession
            session: Any = MockSession()
        else:
            try:
                import agentql  # type: ignore  # noqa: F401
                from playwright.async_api import async_playwright  # noqa: F401
                # Real AgentQL
                session = RealAgentQLSession(
                    headless=headless,
                    on_page_created=on_page_created,
                    window_position=window_position,
                    window_size=window_size
                )
            except ImportError:
                # Fall back to mock mode for offline demos
                from mock_agentql import MockSession
                session = MockSession()

        return SecureContextProxy(session, self)




    def _log(self, action: str, target: str, allowed: bool, latency_ms: float, error: Optional[str] = None):
        """Log authorization decision with full context."""
        warrant_depth = getattr(self.warrant, 'depth', 0) if hasattr(self.warrant, 'depth') else 0
        warrant_id = str(self.warrant.id)[:12] if hasattr(self.warrant, 'id') else "unknown"

        self.audit_log.append(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            action=action,
            target=target,
            result="authorized" if allowed else f"BLOCKED: {error}",
            warrant_depth=warrant_depth,
            warrant_id=warrant_id,
            latency_ms=latency_ms
        ))

    def _build_helpful_error(self, tool: str, args: Dict[str, Any], denial) -> str:
        """
        Build a detailed error message with suggestions for denied actions.

        Args:
            tool: The capability being requested
            args: Arguments for the capability
            denial: Denial information from the bound warrant

        Returns:
            Helpful error message with context and suggestions
        """
        # Base message
        msg = f"Action '{tool}' denied"

        # Add specific context based on tool type
        if tool == "navigate":
            url = args.get("url", "unknown")
            msg += f" for URL: {url}"

            # Check if warrant has navigate capability at all
            if "navigate" not in self.warrant.capabilities:
                msg += ". Warrant does not have 'navigate' capability"
            else:
                # Show allowed patterns
                allowed_patterns = self.warrant.capabilities.get("navigate", {})
                if allowed_patterns:
                    msg += f". Allowed patterns: {allowed_patterns}"

        elif tool in ["fill", "click"]:
            element = args.get("element", "unknown")
            msg += f" for element: '{element}'"

            if tool not in self.warrant.capabilities:
                msg += f". Warrant does not have '{tool}' capability"
            else:
                allowed_elements = self.warrant.capabilities.get(tool, {})
                if allowed_elements:
                    msg += f". Allowed elements: {allowed_elements}"

        elif tool == "query":
            query = args.get("query", "unknown")
            msg += f" for query: {query}"

            if "query" not in self.warrant.capabilities:
                msg += ". Warrant does not have 'query' capability (DLP prevention)"

        # Add suggestion if available
        if denial and hasattr(denial, 'suggestion') and denial.suggestion:
            msg += f". Suggestion: {denial.suggestion}"

        return msg

    def authorize(self, tool: str, args: Dict[str, Any]):
        """
        Check if the action is allowed by the warrant.
        Raises AuthorizationDenied with detailed context if not allowed.
        """
        start_time = time.perf_counter()

        # Check authorization
        allowed = self.bound.allows(tool, args)
        latency_ms = (time.perf_counter() - start_time) * 1000

        # Record metrics
        self.metrics.record(allowed, latency_ms)

        if allowed:
            target = str(args.get("url") or args.get("element") or args.get("query", "unknown"))
            self._log(tool, target, True, latency_ms)
            return True

        # Build helpful error message
        denial = self.bound.why_denied(tool, args)
        msg = self._build_helpful_error(tool, args, denial)

        target = str(args.get("url") or args.get("element") or args.get("query", "unknown"))
        self._log(tool, target, False, latency_ms, msg)
        raise AuthorizationDenied(msg)

    def print_metrics(self):
        """Print performance metrics summary."""
        print(f"\n{'='*60}")
        print("PERFORMANCE METRICS")
        print(f"{'='*60}")
        print(f"Total authorizations: {self.metrics.total_authorizations}")
        print(f"Allowed: {self.metrics.allowed_count}")
        print(f"Denied: {self.metrics.denied_count}")
        print(f"Average latency: {self.metrics.avg_latency_ms:.3f} ms")
        print(f"Total overhead: {self.metrics.total_latency_ms:.3f} ms")
        print(f"{'='*60}\n")

class SecureProxy:
    """
    A dynamic proxy that intercepts method calls to enforce security policies.
    """
    def __init__(self, target: Any, agent: TenuoAgentQLAgent):
        self._target = target
        self._agent = agent

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._target, name)

        # If it's a method, wrap it
        if callable(attr):
            return self._wrap_method(name, attr)

        # If it's a property, wrap the result (e.g. page.url)
        return self._wrap_result(attr)

    def __getitem__(self, key: Any) -> Any:
        # Support list/dict access or AQLResponseProxy access
        item = self._target[key]
        return self._wrap_result(item)

    def _handle_locator_call(self, method: Callable, args: tuple, kwargs: dict) -> Any:
        """
        Unified locator handling logic (extracted to avoid duplication).

        Args:
            method: The locator method being called
            args: Positional arguments
            kwargs: Keyword arguments

        Returns:
            SecureLocatorProxy or LazySemanticLocator wrapping the locator
        """
        raw_label = args[0] if args else kwargs.get("selector", "unknown")
        semantic_label = normalize_semantic_label(raw_label)

        # AgentQL semantic query handling
        if hasattr(self._target, "get_by_prompt") and is_agentql_query(raw_label):
            # For async contexts, return lazy locator
            if inspect.iscoroutinefunction(method):
                result = self._target.get_by_prompt(semantic_label)
                return SecureLocatorProxy(result, self._agent, semantic_label)
            else:
                # For sync contexts (should not happen in real AgentQL, but defensive)
                return LazySemanticLocator(self._target, semantic_label, self._agent)
        else:
            # Standard Playwright locator
            result = method(*args, **kwargs)
            return SecureLocatorProxy(result, self._agent, semantic_label)

    def _wrap_method(self, name: str, method: Callable) -> Callable:
        """
        Wrap a method to enforce authorization and maintain security context.

        Args:
            name: Method name
            method: The callable method

        Returns:
            Wrapped method (async or sync based on original)
        """
        async def async_wrapper(*args, **kwargs):
            # Special handling for locator() - preserve semantic label
            if name == "locator":
                return self._handle_locator_call(method, args, kwargs)

            # Regular authorization check
            self._authorize_action(name, args, kwargs)
            result = await method(*args, **kwargs)
            return self._wrap_result(result)

        def sync_wrapper(*args, **kwargs):
            # Special handling for locator() - preserve semantic label
            if name == "locator":
                return self._handle_locator_call(method, args, kwargs)

            # Regular authorization check
            self._authorize_action(name, args, kwargs)
            result = method(*args, **kwargs)
            return self._wrap_result(result)

        if inspect.iscoroutinefunction(method):
            return async_wrapper
        return sync_wrapper

    def _authorize_action(self, method_name: str, args: tuple, kwargs: dict):
        """
        Map method calls to Tenuo capabilities and authorize them.
        Uses METHOD_TO_CAPABILITY for flexible method mapping.
        """
        if method_name in METHOD_TO_CAPABILITY:
            capability_name, args_extractor = METHOD_TO_CAPABILITY[method_name]
            capability_args = args_extractor(args, kwargs)
            self._agent.authorize(capability_name, capability_args)
        # For unmapped methods, allow (read-only operations)
        # In production, consider default-deny for state-changing operations

    def _wrap_result(self, result: Any) -> Any:
        """
        Recursively wrap returned objects to maintain security enforcement.
        Uses duck typing to avoid fragile type name checking.

        Args:
            result: The result to potentially wrap

        Returns:
            Wrapped result or original if wrapping not needed
        """
        # Primitive types or None don't need wrapping
        if result is None or isinstance(result, (str, int, float, bool)):
            return result

        # Lists might contain objects that need wrapping
        if isinstance(result, list):
             return [self._wrap_result(x) for x in result]

        # Dicts are usually data payloads, don't wrap
        if isinstance(result, dict):
             return result

        # Use duck typing for object wrapping
        # Check for page-like objects (has goto and locator methods)
        if hasattr(result, 'goto') and hasattr(result, 'locator'):
            return SecureProxy(result, self._agent)

        # Check for locator-like objects (has fill and click methods)
        # Should rarely hit this path since locator() is intercepted
        if hasattr(result, 'fill') and hasattr(result, 'click'):
            return SecureLocatorProxy(result, self._agent, "unknown")

        # Check for async context managers (sessions, browsers)
        if hasattr(result, "__aenter__") and hasattr(result, "__aexit__"):
            return SecureContextProxy(result, self._agent)

        # Check for response-like objects (has methods we might want to wrap)
        # AgentQL response proxies typically have data access methods
        if hasattr(result, '__getitem__') and not isinstance(result, (list, dict, str, bytes)):
            return SecureProxy(result, self._agent)

        # Return raw for other types (primitives, unrecognized objects)
        return result


class SecureLocatorProxy(SecureProxy):
    """
    Specialized proxy for AgentQL Locator objects.
    Tracks the semantic label so fill() and click() know which element they're operating on.
    """
    def __init__(self, target: Any, agent: TenuoAgentQLAgent, semantic_label: str):
        super().__init__(target, agent)
        self._semantic_label = semantic_label

    def _authorize_action(self, method_name: str, args: tuple, kwargs: dict):
        """
        Override to inject semantic label for locator-specific operations.
        """
        if method_name == "fill":
            # fill(text) on a locator - use the stored semantic label
            self._agent.authorize("fill", {"element": self._semantic_label})
        elif method_name == "click":
            # click() on a locator - use the stored semantic label
            self._agent.authorize("click", {"element": self._semantic_label})
        else:
            # Fall back to parent logic
            super()._authorize_action(method_name, args, kwargs)

class SecureContextProxy(SecureProxy):
    """Wraps async context managers (like session)"""
    async def __aenter__(self):
        result = await self._target.__aenter__()
        return self._wrap_result(result)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return await self._target.__aexit__(exc_type, exc_val, exc_tb)

class RealAgentQLSession:
    """Manages Playwright + AgentQL lifecycle."""
    def __init__(self, headless: bool = False, on_page_created: Optional[Callable] = None,
                 window_position: Optional[tuple] = None, window_size: Optional[tuple] = None):
        self.headless = headless
        self.on_page_created = on_page_created
        self.window_position = window_position
        self.window_size = window_size
        self.playwright = None
        self.browser = None
        self.page = None

    async def __aenter__(self):
        from playwright.async_api import async_playwright
        import agentql

        self.playwright = await async_playwright().start()

        # Build launch args for window positioning
        args = []
        if self.window_position and not self.headless:
            x, y = self.window_position
            args.append(f'--window-position={x},{y}')
        if self.window_size and not self.headless:
            width, height = self.window_size
            args.append(f'--window-size={width},{height}')

        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=args if args else None
        )
        self.page = await self.browser.new_page()

        # Run hook if provided (e.g. to mock routes)
        if self.on_page_created:
            if inspect.iscoroutinefunction(self.on_page_created):
                await self.on_page_created(self.page)
            else:
                self.on_page_created(self.page)

        # Wrap the page with AgentQL
        return await agentql.wrap_async(self.page)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.page:
            await self.page.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

