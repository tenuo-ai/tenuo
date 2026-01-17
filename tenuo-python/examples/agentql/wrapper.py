from typing import Any, List, Dict, Callable, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
import inspect
from tenuo import Warrant, SigningKey, AuthorizationDenied
from lazy_locator import LazySemanticLocator

@dataclass
class AuditEntry:
    timestamp: str
    action: str
    target: str
    result: str

# Method mapping: Maps AgentQL method names to (capability_name, args_extractor)
# This makes the wrapper adaptable if AgentQL's API changes
METHOD_TO_CAPABILITY = {
    "goto": ("navigate", lambda a, k: {"url": a[0] if a else k.get("url")}),
    "navigate": ("navigate", lambda a, k: {"url": a[0] if a else k.get("url")}),
    "click": ("click", lambda a, k: {"element": a[0] if a else k.get("element", "unknown")}),
    "fill": ("fill", lambda a, k: {"element": a[0] if len(a) > 1 else k.get("element", "unknown")}),
    "query_data": ("query", lambda a, k: {"query": a[0] if a else k.get("query", "unknown")}),
    "query_elements": ("query", lambda a, k: {"query": a[0] if a else k.get("query", "unknown")}),
}

class TenuoAgentQLAgent:
    """
    A secure wrapper around AgentQL that enforces Tenuo warrants using dynamic proxying.
    """
    def __init__(self, warrant: Warrant):
        self.warrant = warrant
        self.keypair = SigningKey.generate()
        self.bound = warrant.bind(self.keypair)
        self.audit_log: List[AuditEntry] = []

    def start_session(self, headless: bool = False, on_page_created: Callable = None):
        try:
            import agentql
            from playwright.async_api import async_playwright
        except ImportError as e:
            raise ImportError(
                "Real 'agentql' and 'playwright' libraries are required. "
                "Please run: pip install agentql playwright"
            ) from e

        # Real AgentQL
        session = RealAgentQLSession(headless=headless, on_page_created=on_page_created)
        # We need to initialize the session (start browser) before returning proxy
        # because the proxy might be used immediately?
        # Actually SecureContextProxy handles __aenter__ which calls session.__aenter__.
        # So returning the session instance wrapped is correct.
        return SecureContextProxy(session, self)




    def _log(self, action: str, target: str, allowed: bool, error: str = None):
        self.audit_log.append(AuditEntry(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            action=action,
            target=target,
            result="✅ authorized" if allowed else f"🚫 BLOCKED ({error})"
        ))

    def authorize(self, tool: str, args: Dict[str, Any]):
        """
        Check if the action is allowed by the warrant.
        Raises AuthorizationDenied if not allowed or if warrant is expired.
        """
        # Check warrant expiration first
        # Note: Expiration checking is typically done by the authorizer during
        # the allows() call, but we can add an explicit check for clarity
        try:
            expires_at = self.warrant.expires_at()
            # Simple check: if expires_at exists and is in the past
            # The warrant library should handle this, but explicit is better for demo
        except Exception:
            pass  # If expiration check fails, let allows() handle it

        # Check authorization
        if self.bound.allows(tool, args):
            self._log(tool, str(args.get("url") or args.get("element")), True)
            return True

        denial = self.bound.why_denied(tool, args)
        msg = f"Action '{tool}' denied"
        if denial.suggestion:
            msg += f". Suggestion: {denial.suggestion}"

        self._log(tool, str(args.get("url") or args.get("element")), False, msg)
        raise AuthorizationDenied(msg)

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

    def _wrap_method(self, name: str, method: Callable) -> Callable:
        async def async_wrapper(*args, **kwargs):
            # Special handling for locator() - preserve semantic label
            if name == "locator":
                raw_label = args[0] if args else kwargs.get("selector", "unknown")
                # Normalize label: "{ foo }" -> "foo"
                semantic_label = raw_label.replace("{", "").replace("}", "").strip()
                
                # If it looked like an AgentQL query (had braces) or we want to force semantic lookup:
                # Use get_by_prompt if available (AgentQL wrapped)
                if hasattr(self._target, "get_by_prompt") and ("{" in raw_label or " " in raw_label):
                     result = self._target.get_by_prompt(semantic_label)
                else:
                     # Fallback to standard locator (Playwright)
                     result = await method(*args, **kwargs) if inspect.iscoroutinefunction(method) else method(*args, **kwargs)
                
                return SecureLocatorProxy(result, self._agent, semantic_label)

            # Regular authorization check
            self._authorize_action(name, args, kwargs)
            if inspect.iscoroutinefunction(method):
                result = await method(*args, **kwargs)
            else:
                result = method(*args, **kwargs)
            return self._wrap_result(result)

        def sync_wrapper(*args, **kwargs):
            # Special handling for locator() - preserve semantic label
            if name == "locator":
                raw_label = args[0] if args else kwargs.get("selector", "unknown")
                # Normalize label: "{ foo }" -> "foo"
                semantic_label = raw_label.replace("{", "").replace("}", "").strip()
                
                # If it looked like an AgentQL query (had braces) or force semantic:
                if hasattr(self._target, "get_by_prompt") and ("{" in raw_label or " " in raw_label):
                     # Return Lazy Locator - this resolves the async mismatch
                     return LazySemanticLocator(self._target, semantic_label, self._agent)
                else:
                     result = method(*args, **kwargs)
                
                return SecureLocatorProxy(result, self._agent, semantic_label)

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
        """
        # Primitive types or None don't need wrapping
        if result is None or isinstance(result, (str, int, float, bool)):
            return result

        # Lists/Dicts might contain objects
        if isinstance(result, list):
             return [self._wrap_result(x) for x in result]
        if isinstance(result, dict):
             # Deep wrap dicts? For now, we only care if they return Locators/proxies
             # But usually response dict is data.
             return result

        # Wrap Pages, Locators, Sessions using duck typing
        type_name = type(result).__name__
        if "Page" in type_name or "Session" in type_name or "ResponseProxy" in type_name:
            return SecureProxy(result, self._agent)

        # Locators need special handling (but shouldn't hit this path if locator() is intercepted)
        if "Locator" in type_name:
            return SecureLocatorProxy(result, self._agent, "unknown")

        # Catch async context managers
        if hasattr(result, "__aenter__"):
            return SecureContextProxy(result, self._agent)

        # Return raw for other types (Responses, etc.)
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
    def __init__(self, headless: bool = False, on_page_created: Callable = None):
        self.headless = headless
        self.on_page_created = on_page_created
        self.playwright = None
        self.browser = None
        self.page = None

    async def __aenter__(self):
        from playwright.async_api import async_playwright
        import agentql
        
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=self.headless)
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

