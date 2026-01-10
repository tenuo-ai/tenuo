# lmstudio is optional - only needed when running with LLM
try:
    import lmstudio as lms
except ImportError:
    lms = None

import display
from protected_tools import ProtectedToolWrapper
from tools import web_search, read_file, write_file, http_request, delegate
from prompts import RESEARCH_AGENT_SYSTEM_PROMPT, SUMMARY_AGENT_SYSTEM_PROMPT
from tenuo import Warrant, Capability, Pattern, Exact, SigningKey


async def run_research_agent(
    model, warrant: Warrant, signing_key: SigningKey, delegate_to_key: SigningKey = None
) -> tuple:
    """
    Runs the Research Agent loop.

    Args:
        model: LM Studio model
        warrant: Research Agent's warrant
        signing_key: Research Agent's signing key
        delegate_to_key: Optional key for the delegate (Summary Agent).
                        If provided, child warrant will be bound to this key.

    Returns:
        (summary_task, child_warrant) if delegation occurs, or (None, None).
    """
    display.print_header("RESEARCH AGENT")
    display.print_warrant_details(warrant, "Research Agent")

    # Wrap tools with cryptographic authorization (PoP)
    protector = ProtectedToolWrapper(warrant, signing_key)

    # We need to intercept 'delegate' manually to handle the warrant minting logic
    # because delegate needs access to the *parent* warrant (current warrant) to mint the child.

    delegation_result = {"task": None, "child_warrant": None}

    def custom_delegate(agent: str, task: str, capabilities: list) -> str:
        """
        Delegate a task to another agent with specified permissions.

        Args:
            agent: Target agent name (e.g., "summary_agent")
            task: Task description for the delegate
            capabilities: List of capabilities to grant, e.g.:
                [{"tool": "read_file", "path": "/tmp/research/*"}]
        """
        # 1. Authorize the delegation itself (can_delegate=True)
        # The protector wrapper already checked 'delegate' tool access before calling this.
        # But we need to validate the *arguments* (capabilities) are a subset.

        display.print_agent_thought(f"Delegating to {agent} with restricted capabilities")

        try:
            # Construct requested capabilities
            # capabilities arg comes as list of dicts: [{"tool": "read_file", "path": "..."}]
            requested_caps = []
            for cap_dict in capabilities:
                cap_copy = dict(cap_dict)  # Don't mutate original
                name = cap_copy.pop("tool")

                # Build constraint kwargs
                constraint_kwargs = {}
                for k, v in cap_copy.items():
                    # Simple heuristic: if it contains '*', make it a Pattern
                    if isinstance(v, str) and ("*" in v or "?" in v):
                        constraint_kwargs[k] = Pattern(v)
                    else:
                        constraint_kwargs[k] = Exact(str(v))

                requested_caps.append(Capability(name, **constraint_kwargs))

            # MINT CHILD WARRANT (Attenuation)
            # Research Agent delegates to Summary Agent
            builder = warrant.grant_builder()
            builder.ttl(300)

            # Bind child warrant to delegate's key if provided
            if delegate_to_key:
                builder.holder(delegate_to_key.public_key)

            for cap in requested_caps:
                builder.capability(cap.tool, cap.constraints)

            child = builder.grant(signing_key)

            # Store result to return to orchestrator
            delegation_result["task"] = task
            delegation_result["child_warrant"] = child

            return "Delegation successful. Child warrant minted."

        except Exception as e:
            display.print_verdict(False, "Delegation Failed - Escalation Blocked", str(e))
            return f"DELEGATION ERROR: {str(e)}"

    # Mix standard tools with our custom delegate
    # Note: 'delegate' tool in tools.py is a placeholder. We override it here.
    safe_tools = protector.guard(
        [
            web_search,
            write_file,
            read_file,
            http_request,  # Protected (likely denied)
            # delegate is wrapped next
        ]
    )

    # Manually wrap our custom delegate so it gets the logging/checking
    # BUT we need to be careful: custom_delegate does the business logic.
    # The guard checks if 'delegate' tool is allowed.
    safe_tools.append(protector._wrap(custom_delegate))

    # Run LLM
    try:
        root = "Find papers about prompt injection and save notes."
        display.print_agent_thought(f"Starting task: {root}")

        chat = lms.Chat(initial_prompt=RESEARCH_AGENT_SYSTEM_PROMPT)
        chat.add_user_message(root)

        result = await model.act(chat, safe_tools)

        if result:
            display.print_agent_thought(f"Agent completed: {str(result)[:100]}...")

    except Exception as e:
        display.print_verdict(False, "Agent Error", str(e))

    return delegation_result["task"], delegation_result["child_warrant"]


async def run_summary_agent(model, warrant: Warrant, signing_key: SigningKey, task: str):
    """
    Runs the Summary Agent loop with a delegated (attenuated) warrant.

    Args:
        model: LM Studio model
        warrant: Summary Agent's (delegated) warrant
        signing_key: Summary Agent's signing key (must match warrant holder)
        task: The delegated task to perform
    """
    display.print_header("SUMMARY AGENT (DELEGATED)")

    display.print_learning(
        "Monotonic Attenuation",
        "Child warrants can only have FEWER capabilities than their parent.\n"
        "The Summary Agent has a subset of the Research Agent's permissions.",
    )

    display.print_warrant_details(warrant, "Summary Agent")

    # Wrap tools with cryptographic authorization (PoP)
    protector = ProtectedToolWrapper(warrant, signing_key)
    safe_tools = protector.guard(
        [
            read_file,
            write_file,
            http_request,  # Will be blocked - not in child warrant
            delegate,  # Will be blocked - not in child warrant
        ]
    )

    display.print_agent_thought(f"Starting delegated task: {task}")

    try:
        chat = lms.Chat(initial_prompt=SUMMARY_AGENT_SYSTEM_PROMPT)
        chat.add_user_message(task)

        result = await model.act(chat, safe_tools)

        if result:
            display.print_agent_thought(f"Summary completed: {str(result)[:100]}...")

    except Exception as e:
        display.print_verdict(False, "Summary Agent Error", str(e))
