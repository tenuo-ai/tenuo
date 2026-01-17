from typing import Any, List, Dict
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
from tenuo import Warrant, SigningKey, BoundWarrant, UnauthorizedError

@dataclass
class AuditEntry:
    timestamp: str
    action: str
    target: str
    result: str

class TenuoAgentQLAgent:
    """
    A secure wrapper around AgentQL that enforces Tenuo warrants.
    """
    def __init__(self, warrant: Warrant):
        self.warrant = warrant
        # In a real app, the agent holds its own private key.
        # For this demo, we auto-generate one to bind the warrant.
        self.keypair = SigningKey.generate()
        self.bound = warrant.bind(self.keypair)
        self.audit_log: List[AuditEntry] = []

    def start_session(self):
        # Return a context manager that proxies the AgentQL session
        return SecureSession(self)
    
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
        # In Tenuo v0.1:
        # validate() returns an AuthorizationResult (truthy if allowed)
        # or raises if we want to enforce it strictly.
        # Here we use allows() for logic since we are in-process, 
        # mimicking a "Policy Enforcement Point".
        
        # NOTE: In a real remote scenario, we would use validate() with PoP.
        if self.bound.allows(tool, args):
            self._log(tool, str(args.get("url") or args.get("element")), True)
            return True
        
        # If denied, get a reason
        denial = self.bound.why_denied(tool, args)
        msg = f"Action '{tool}' denied"
        if denial.suggestion:
            msg += f". Suggestion: {denial.suggestion}"
            
        self._log(tool, str(args.get("url") or args.get("element")), False, msg)
        raise UnauthorizedError(msg)

class SecureSession:
    def __init__(self, agent: TenuoAgentQLAgent):
        self.agent = agent
        # Lazy import of mock or real library
        try:
            import agentql
        except ImportError:
            from . import mock_agentql as agentql
        
        self._backend = agentql.start_session()
        self._session = None

    async def __aenter__(self):
        self._session = await self._backend.__aenter__()
        return SecurePage(self._session, self.agent)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._backend.__aexit__(exc_type, exc_val, exc_tb)

class SecurePage:
    def __init__(self, page, agent: TenuoAgentQLAgent):
        self._page = page
        self.agent = agent

    async def goto(self, url: str):
        self.agent.authorize("navigate", {"url": url})
        return await self._page.goto(url)

    def locator(self, alias: str):
        return SecureLocator(self._page.locator(alias), alias, self.agent)
    
    async def click(self, alias: str):
        self.agent.authorize("click", {"element": alias})
        await self._page.click(alias)

class SecureLocator:
    def __init__(self, locator, alias: str, agent: TenuoAgentQLAgent):
        self._locator = locator
        self.alias = alias
        self.agent = agent

    async def fill(self, text: str):
        self.agent.authorize("fill", {"element": self.alias})
        await self._locator.fill(text)
