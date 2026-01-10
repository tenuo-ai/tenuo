"""
Orchestrator - Plans tasks, delegates to workers with attenuated warrants.

The Orchestrator is the "brain" that:
1. Analyzes tasks and proposes capabilities (via LLM)
2. Receives an approved warrant from the control plane
3. Delegates subsets to specialized workers (attenuation)
4. Coordinates worker execution

Key security properties demonstrated:
- Monotonicity: Workers can only receive subsets of orchestrator's authority
- Attenuation: Each worker gets minimum needed permissions
- Temporal safety: Shows what happens with stale/mismatched warrants
"""

import re
import json
from typing import List, Dict, Any, Optional
from tenuo import Warrant, SigningKey, PublicKey
import display


# System prompt for capability analysis
CAPABILITY_ANALYSIS_PROMPT = """You are a security-aware AI assistant analyzing what capabilities are needed for a task.

AVAILABLE TOOLS:
- fetch_url: Fetch content from a URL. Constraint: url (the specific URL)
- summarize: Summarize text content. No constraints needed.
- write_file: Write to a file. Constraint: path (file path pattern)
- http_request: Make arbitrary HTTP requests (DANGEROUS - avoid if possible)
- send_email: Send emails (DANGEROUS - avoid if possible)

TASK: Analyze the user's request and determine the MINIMUM capabilities needed.

RULES:
1. Only request capabilities actually needed for the task
2. Be SPECIFIC with constraints (exact URLs, exact paths)
3. NEVER request http_request or send_email unless explicitly asked
4. Explain your reasoning

OUTPUT FORMAT (JSON):
{
  "reasoning": "Brief explanation of your analysis",
  "capabilities": [
    {"tool": "tool_name", "constraints": {"key": "value"}, "reason": "why needed"}
  ]
}

Example for "Summarize https://example.com":
{
  "reasoning": "User wants to summarize a specific URL. I need fetch_url for that exact URL and summarize to process the content.",
  "capabilities": [
    {"tool": "fetch_url", "constraints": {"url": "https://example.com"}, "reason": "Fetch the specified URL"},
    {"tool": "summarize", "constraints": {}, "reason": "Summarize the fetched content"}
  ]
}"""


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    url_pattern = r"https?://[^\s,\)\]\"\'<>]+"
    urls = re.findall(url_pattern, text)
    # Also check for domain-only mentions
    domain_pattern = r"\b([a-zA-Z0-9-]+\.(?:com|org|net|io|dev))\b"
    domains = re.findall(domain_pattern, text)
    for domain in domains:
        if not any(domain in url for url in urls):
            urls.append(f"https://{domain}")
    return urls


class Worker:
    """
    Represents a worker agent that receives a delegated warrant.

    Workers have their own keypair and can only operate within
    the bounds of their delegated warrant.
    """

    def __init__(self, name: str, specialty: str):
        self.name = name
        self.specialty = specialty
        self.signing_key = SigningKey.generate()
        self.warrant: Optional[Warrant] = None

    @property
    def public_key(self) -> PublicKey:
        return self.signing_key.public_key

    def __repr__(self) -> str:
        return f"Worker({self.name}, {self.specialty})"


class Orchestrator:
    """
    The orchestrator plans and coordinates task execution.

    It holds a warrant from the control plane and can delegate
    attenuated subsets to specialized workers.
    """

    def __init__(self):
        self.signing_key = SigningKey.generate()
        self.warrant: Optional[Warrant] = None
        self.workers: Dict[str, Worker] = {}

    @property
    def public_key(self) -> PublicKey:
        return self.signing_key.public_key

    def receive_warrant(self, warrant: Warrant):
        """Receive approved warrant from control plane."""
        self.warrant = warrant

    def create_worker(self, name: str, specialty: str) -> Worker:
        """Create a new worker agent."""
        worker = Worker(name, specialty)
        self.workers[name] = worker
        return worker

    def delegate_to_worker(
        self,
        worker: Worker,
        tools: List[str],
        constraints: Optional[Dict[str, Any]] = None,
        ttl: int = 60,
    ) -> Optional[Warrant]:
        """
        Delegate an attenuated warrant to a worker.

        The worker's warrant is a SUBSET of the orchestrator's warrant.
        This demonstrates MONOTONICITY - authority can only decrease.

        Args:
            worker: The worker to delegate to
            tools: List of tool names to grant (must be subset of orchestrator's)
            constraints: Additional constraints to apply (can only tighten)
            ttl: Time-to-live for worker's warrant

        Returns:
            The delegated warrant, or None if delegation fails
        """
        if self.warrant is None:
            display.print_verdict(False, "Delegation Failed", "Orchestrator has no warrant to delegate from.")
            return None

        constraints = constraints or {}

        # Build the attenuated warrant
        try:
            builder = self.warrant.grant_builder()
            builder = builder.holder(worker.public_key)
            builder = builder.ttl(ttl)

            # Add only the specified tools (attenuation)
            for tool in tools:
                if tool in constraints and constraints[tool]:
                    # Constraints are passed as keyword arguments
                    builder = builder.capability(tool, **constraints[tool])
                else:
                    builder = builder.capability(tool)

            child_warrant = builder.grant(self.signing_key)
            worker.warrant = child_warrant

            display.print_delegation(self.public_key, worker.name, worker.public_key, tools, constraints, ttl)

            return child_warrant

        except Exception as e:
            display.print_verdict(False, "Delegation Failed", str(e))
            return None

    def delegate_stale_warrant(
        self,
        worker: Worker,
        stale_warrant: Warrant,
    ):
        """
        Demonstrate what happens when a worker has a stale/wrong warrant.

        This shows TEMPORAL MISMATCH - the worker has a warrant that
        doesn't match current authorization.
        """
        worker.warrant = stale_warrant
        display.print_stale_warrant_warning(worker.name)


async def propose_capabilities_with_llm(
    model,
    task: str,
) -> List[Dict[str, Any]]:
    """
    Use the LLM to analyze a task and propose capabilities.

    This is the impressive part - the audience sees the LLM
    reasoning about what permissions it needs!

    Args:
        model: LM Studio model
        task: The user's task description

    Returns:
        List of capability proposals
    """
    import lmstudio as lms

    display.print_step(1, "LLM Analyzes Task", "Watch the LLM reason about what capabilities it needs...")

    chat = lms.Chat(CAPABILITY_ANALYSIS_PROMPT)
    chat.add_user_message(f"Analyze this task: {task}")

    # Get the LLM's response
    response = await model.respond(chat)
    response_text = str(response.content) if hasattr(response, "content") else str(response)

    # Show the LLM's reasoning
    display.print_llm_reasoning(response_text)

    # Parse the JSON response
    try:
        # Find JSON in response (LLM might include extra text)
        json_match = re.search(r"\{[\s\S]*\}", response_text)
        if json_match:
            result = json.loads(json_match.group())
            return result.get("capabilities", [])
    except json.JSONDecodeError:
        pass

    # Fallback to regex extraction if JSON parsing fails
    display.console.print("[dim]Falling back to pattern matching...[/dim]")
    return propose_capabilities_fallback(task)


def propose_capabilities_fallback(task: str) -> List[Dict[str, Any]]:
    """
    Fallback capability proposal using pattern matching.
    Used when LLM response can't be parsed.
    """
    capabilities = []
    task_lower = task.lower()
    urls = extract_urls(task)

    if urls:
        capabilities.append(
            {
                "tool": "fetch_url",
                "constraints": {"url": f"one of {urls}"},
                "reason": "Fetch content from specified URLs",
            }
        )

    if "summar" in task_lower:
        capabilities.append({"tool": "summarize", "constraints": {}, "reason": "Summarize the content"})

    if "save" in task_lower or "write" in task_lower:
        import config

        capabilities.append(
            {"tool": "write_file", "constraints": {"path": f"{config.OUTPUT_DIR}/*"}, "reason": "Save output to file"}
        )

    if not capabilities:
        capabilities.append({"tool": "summarize", "constraints": {}, "reason": "Default text processing"})

    return capabilities


def propose_capabilities_sync(task: str) -> List[Dict[str, Any]]:
    """
    Synchronous capability proposal (no LLM, for --simulate mode).
    """
    display.print_step(
        1, "Analyze Task (Simulated)", "In full mode, the LLM would reason about needed capabilities here."
    )

    return propose_capabilities_fallback(task)
