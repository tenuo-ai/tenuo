from typing import Any, List, Dict, Callable
from dataclasses import dataclass
from datetime import datetime
import inspect
from tenuo import Warrant, SigningKey, AuthorizationDenied

@dataclass
class AuditEntry:
    timestamp: str
    action: str
    target: str
    result: str

class TenuoAgentQLAgent:
    """
    A secure wrapper around AgentQL that enforces Tenuo warrants using dynamic proxying.
    """
    def __init__(self, warrant: Warrant):
        self.warrant = warrant
        self.keypair = SigningKey.generate()
        self.bound = warrant.bind(self.keypair)
        self.audit_log: List[AuditEntry] = []

    def start_session(self):
        # Lazy import of mock or real library
        try:
            import agentql
        except ImportError:
            import mock_agentql as agentql

        real_session = agentql.start_session()
        return SecureContextProxy(real_session, self)

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
        """
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

    def _wrap_method(self, name: str, method: Callable) -> Callable:
        async def async_wrapper(*args, **kwargs):
            self._authorize_action(name, args, kwargs)
            if inspect.iscoroutinefunction(method):
                result = await method(*args, **kwargs)
            else:
                result = method(*args, **kwargs)
            return self._wrap_result(result)

        def sync_wrapper(*args, **kwargs):
            self._authorize_action(name, args, kwargs)
            result = method(*args, **kwargs)
            return self._wrap_result(result)

        if inspect.iscoroutinefunction(method):
            return async_wrapper
        return sync_wrapper

    def _authorize_action(self, method_name: str, args: tuple, kwargs: dict):
        # POLICY MAPPING
        # Map method names to Tenuo capabilities

        if method_name == "goto":
            url = args[0] if args else kwargs.get("url")
            self._agent.authorize("navigate", {"url": url})

        elif method_name == "click":
            # Assuming alias is first arg
            # In AgentQL, alias might be on the locator, but here we support page.click(alias)
            # or locator.click(). If locator.click(), we need the alias stored on the locator.

            # If this is a proxy for a Locator, we might need access to its alias.
            # But the 'fill' and 'click' examples in demo use page.click("alias")?
            # Wait, demo uses:
            # await page.click("delete_account_button")
            # AND
            # await page.locator("search_box").fill(...)

            # Dynamic Handling:
            # If method is on Page:
            element = args[0] if args else kwargs.get("element") or "unknown"
            self._agent.authorize("click", {"element": element})

        elif method_name == "fill":
            # If called on Page: page.fill(alias, value) -> usually not standard AgentQL?
            # If called on Locator: locator.fill(value). Locator needs to know its alias.

            # ISSUE: If this is locator.fill("text"), we need the locator's alias.
            # The Proxy needs to track context?
            # Or we look at self._target.alias if it exists?

            element = "unknown"
            if hasattr(self._target, "alias"):
                element = self._target.alias
            elif args:
                # Fallback for page.fill("alias", "text")
                element = args[0]

            self._agent.authorize("fill", {"element": element})

        # Default: Allow other methods (read-only) or add more rules.
        # For strict security, we should default deny unknown state-changing methods.
        # But for this demo, we can just intercept the key ones.

    def _wrap_result(self, result: Any) -> Any:
        # Recursively wrap objects that need security
        # We can detect by type or duck-typing

        # Primitive types or None don't need wrapping
        if result is None or isinstance(result, (str, int, float, bool)):
            return result

        # Lists/Dicts might contain objects? (Skip for now for simplicity)

        # Wrap everything else (Pages, Locators, Sessions)
        # Using duck typing or specific check
        type_name = type(result).__name__
        if "Page" in type_name or "Locator" in type_name or "Session" in type_name:
             return SecureProxy(result, self._agent)

        # Also catch context managers
        if hasattr(result, "__aenter__"):
             return SecureContextProxy(result, self._agent)

        # Return raw for things like Responses?
        return result

class SecureContextProxy(SecureProxy):
    """Wraps async context managers (like session)"""
    async def __aenter__(self):
        result = await self._target.__aenter__()
        return self._wrap_result(result)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return await self._target.__aexit__(exc_type, exc_val, exc_tb)
