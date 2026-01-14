"""
A2A Adapter - Client implementation.

Provides A2AClient for sending tasks with warrants to A2A agents.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any, AsyncIterator, Dict, List, Optional, Union

from .types import (
    AgentCard,
    Message,
    TaskResult,
    TaskUpdate,
)
from .errors import A2AError, KeyMismatchError, WarrantExpiredError

if TYPE_CHECKING:
    from .types import Warrant

    try:
        from tenuo_core import SigningKey
    except ImportError:
        SigningKey = Any  # type: ignore

__all__ = [
    "A2AClient",
    "delegate",
]

logger = logging.getLogger("tenuo.a2a.client")


# =============================================================================
# A2A Client
# =============================================================================


class A2AClient:
    """
    Client for sending tasks to A2A agents with warrants.

    Example:
        client = A2AClient("https://research-agent.example.com")

        # Discover agent capabilities
        card = await client.discover()
        print(f"Agent requires warrant: {card.requires_warrant}")

        # Send task with warrant
        result = await client.send_task(
            message="Find papers on security",
            warrant=my_warrant,
        )
    """

    def __init__(
        self,
        url: str,
        *,
        auth: Optional[Any] = None,
        pin_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize A2A client.

        Args:
            url: Base URL of the A2A agent
            auth: Optional authentication config
            pin_key: Expected public key (raises KeyMismatchError if different)
            timeout: Request timeout in seconds
        """
        self.url = url.rstrip("/")
        self.auth = auth
        self.pin_key = pin_key
        self.timeout = timeout

        # Cached agent card
        self._agent_card: Optional[AgentCard] = None

        # HTTP client (lazy init)
        self._client = None

    async def _get_client(self):
        """Get or create httpx client."""
        if self._client is None:
            try:
                import httpx
            except ImportError:
                raise ImportError("httpx is required for A2A client. Install with: pip install tenuo[a2a]")
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    # -------------------------------------------------------------------------
    # Discovery
    # -------------------------------------------------------------------------

    async def discover(self) -> AgentCard:
        """
        Fetch agent card from the server.

        If pin_key was provided, raises KeyMismatchError if the agent's
        public key doesn't match. This prevents TOFU attacks where a
        compromised server swaps its key.

        Returns:
            AgentCard with agent capabilities and Tenuo config
        """
        client = await self._get_client()

        # Try well-known endpoint first
        response = await client.get(f"{self.url}/.well-known/agent.json")

        if response.status_code != 200:
            # Try JSON-RPC discovery
            response = await client.post(
                f"{self.url}/a2a",
                json={
                    "jsonrpc": "2.0",
                    "method": "agent/discover",
                    "params": {},
                    "id": 1,
                },
            )
            data = response.json()
            if "error" in data:
                raise RuntimeError(f"Discovery failed: {data['error']}")
            card_data = data.get("result", {})
        else:
            card_data = response.json()

        card = AgentCard.from_dict(card_data)

        # Validate pinned key if provided
        if self.pin_key and card.public_key:
            if card.public_key != self.pin_key:
                raise KeyMismatchError(self.pin_key, card.public_key)

        self._agent_card = card
        return card

    # -------------------------------------------------------------------------
    # Task Sending
    # -------------------------------------------------------------------------

    async def send_task(
        self,
        message: Union[str, Message],
        warrant: "Warrant",
        *,
        skill: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        warrant_chain: Optional[List["Warrant"]] = None,
        signing_key: Optional["SigningKey"] = None,
    ) -> TaskResult:
        """
        Send a task to the agent with a warrant.

        Args:
            message: Task message (string or Message object)
            warrant: Tenuo warrant for authorization (the leaf warrant)
            skill: Skill to invoke (required)
            arguments: Arguments for the skill
            task_id: Optional task ID (generated if not provided)
            warrant_chain: Optional delegation chain (parent-first order, excluding leaf)
            signing_key: Signing key for Proof-of-Possession (required if agent requires PoP)

        Returns:
            TaskResult with output

        Example:
            # Direct invocation with PoP
            result = await client.send_task(
                message="Search for papers",
                warrant=my_warrant,
                skill="search_papers",
                arguments={"query": "AI safety"},
                signing_key=my_key,
            )

            # With delegation chain and PoP
            result = await client.send_task(
                message="Search for papers",
                warrant=leaf_warrant,
                skill="search_papers",
                arguments={"query": "AI safety"},
                warrant_chain=[root_warrant, intermediate_warrant],
                signing_key=my_key,
            )
        """
        client = await self._get_client()

        # Build message content
        if isinstance(message, str):
            message_content = message
        else:
            message_content = message.content

        # Skill is required - no implicit inference from warrant
        if skill is None:
            raise ValueError(
                "skill is required. Specify the skill to invoke explicitly. "
                "Example: client.send_task(message='...', warrant=w, skill='search_papers')"
            )

        # Serialize warrant using to_base64() - the canonical method
        # Warrant must be a tenuo Warrant object with to_base64()
        if not hasattr(warrant, "to_base64"):
            raise TypeError(f"warrant must be a Warrant object with to_base64() method, got {type(warrant).__name__}")
        warrant_token = warrant.to_base64()

        # Build headers
        headers: Dict[str, str] = {"X-Tenuo-Warrant": warrant_token}

        # Add delegation chain if provided (semicolon-separated, parent-first)
        if warrant_chain:
            chain_tokens = []
            for w in warrant_chain:
                if not hasattr(w, "to_base64"):
                    raise TypeError(f"warrant_chain items must have to_base64() method, got {type(w).__name__}")
                chain_tokens.append(w.to_base64())
            headers["X-Tenuo-Warrant-Chain"] = ";".join(chain_tokens)

        # Generate Proof-of-Possession signature if signing_key provided
        args = arguments or {}
        if signing_key is not None:
            if not hasattr(warrant, "sign"):
                raise TypeError(
                    f"warrant must have sign() method for PoP, got {type(warrant).__name__}. "
                    "Ensure you're using a tenuo_core.Warrant object."
                )
            # Convert arguments to ConstraintValue format for PoP signing
            # SECURITY: Fail-closed if tenuo_core unavailable. PoP requires
            # proper ConstraintValue types for deterministic signing.
            try:
                from tenuo_core import ConstraintValue

                args_cv = {k: ConstraintValue.from_any(v) for k, v in args.items()}
            except ImportError as e:
                raise ImportError(
                    "tenuo_core.ConstraintValue required for PoP signing. Install with: pip install tenuo[a2a]"
                ) from e

            # Sign the request
            pop_signature = warrant.sign(signing_key, skill, args_cv)
            # Encode as base64 URL-safe
            pop_bytes = bytes(pop_signature)
            headers["X-Tenuo-PoP"] = base64.urlsafe_b64encode(pop_bytes).decode("ascii")
            logger.debug(f"Generated PoP signature for skill '{skill}'")

        # Build request with known task_id for response validation
        expected_task_id = task_id or str(uuid.uuid4())
        task_data = {
            "id": expected_task_id,
            "message": message_content,
            "skill": skill,
            "arguments": args,
        }

        # Send request
        response = await client.post(
            f"{self.url}/a2a",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "method": "task/send",
                "params": {"task": task_data},
                "id": 1,
            },
        )

        data = response.json()

        # Validate JSON-RPC response structure
        if not isinstance(data, dict):
            raise ValueError(f"Invalid JSON-RPC response: expected dict, got {type(data).__name__}")

        if "error" in data:
            error = data["error"]
            from .errors import A2AError

            # Create appropriate error
            message = error.get("message", "Unknown error")
            error_data = error.get("data", {})

            raise A2AError(message, error_data)

        result_data = data.get("result", {})
        if not isinstance(result_data, dict):
            raise ValueError(f"Invalid result: expected dict, got {type(result_data).__name__}")

        # Validate task_id matches to prevent response spoofing
        response_task_id = result_data.get("task_id")
        if response_task_id and response_task_id != expected_task_id:
            raise ValueError(
                f"Response task_id mismatch: expected {expected_task_id!r}, "
                f"got {response_task_id!r}. Possible response spoofing."
            )

        return TaskResult.from_dict(result_data)

    async def send_task_streaming(
        self,
        message: Union[str, Message],
        warrant: "Warrant",
        *,
        skill: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        warrant_chain: Optional[List["Warrant"]] = None,
        signing_key: Optional["SigningKey"] = None,
        stream_timeout: Optional[float] = 300.0,
        strict_task_id: bool = True,
    ) -> AsyncIterator[TaskUpdate]:
        """
        Send a streaming task to the agent.

        Uses Server-Sent Events (SSE) for streaming responses.
        Yields TaskUpdate objects for each event.

        Args:
            message: Task message (string or Message object)
            warrant: Tenuo warrant for authorization (the leaf warrant)
            skill: Skill to invoke (required)
            arguments: Arguments for the skill
            task_id: Optional task ID (generated if not provided)
            warrant_chain: Optional delegation chain (parent-first order, excluding leaf)
            signing_key: Signing key for Proof-of-Possession (required if agent requires PoP)
            stream_timeout: Maximum total time for streaming in seconds (default 5 min).
                           None disables the timeout. Prevents slow-drip DoS attacks.
            strict_task_id: If True (default), abort stream if response task_id doesn't
                           match expected. Prevents response spoofing attacks.

        Yields:
            TaskUpdate objects for status, artifacts, messages, and completion

        Raises:
            A2AError: If server returns an error (including mid-stream expiry)
            TimeoutError: If stream_timeout is exceeded
            ValueError: If strict_task_id=True and response task_id doesn't match
        """
        client = await self._get_client()

        # Build message content
        if isinstance(message, str):
            message_content = message
        else:
            message_content = message.content

        # Skill is required
        if skill is None:
            raise ValueError(
                "skill is required. Specify the skill to invoke explicitly. "
                "Example: client.send_task_streaming(message='...', warrant=w, skill='search_papers')"
            )

        # Serialize warrant
        if not hasattr(warrant, "to_base64"):
            raise TypeError(f"warrant must be a Warrant object with to_base64() method, got {type(warrant).__name__}")
        warrant_token = warrant.to_base64()

        # Build headers
        headers: Dict[str, str] = {
            "X-Tenuo-Warrant": warrant_token,
            "Accept": "text/event-stream",
        }

        # Add delegation chain if provided
        if warrant_chain:
            chain_tokens = []
            for w in warrant_chain:
                if not hasattr(w, "to_base64"):
                    raise TypeError(f"warrant_chain items must have to_base64() method, got {type(w).__name__}")
                chain_tokens.append(w.to_base64())
            headers["X-Tenuo-Warrant-Chain"] = ";".join(chain_tokens)

        # Generate Proof-of-Possession signature if signing_key provided
        args = arguments or {}
        if signing_key is not None:
            if not hasattr(warrant, "sign"):
                raise TypeError(
                    f"warrant must have sign() method for PoP, got {type(warrant).__name__}. "
                    "Ensure you're using a tenuo_core.Warrant object."
                )
            # SECURITY: Fail-closed if tenuo_core unavailable
            try:
                from tenuo_core import ConstraintValue

                args_cv = {k: ConstraintValue.from_any(v) for k, v in args.items()}
            except ImportError as e:
                raise ImportError(
                    "tenuo_core.ConstraintValue required for PoP signing. Install with: pip install tenuo[a2a]"
                ) from e

            pop_signature = warrant.sign(signing_key, skill, args_cv)
            pop_bytes = bytes(pop_signature)
            headers["X-Tenuo-PoP"] = base64.urlsafe_b64encode(pop_bytes).decode("ascii")
            logger.debug(f"Generated PoP signature for streaming skill '{skill}'")

        # Build request
        expected_task_id = task_id or str(uuid.uuid4())
        task_data = {
            "id": expected_task_id,
            "message": message_content,
            "skill": skill,
            "arguments": args,
        }

        # Calculate deadline for stream timeout
        deadline = time.monotonic() + stream_timeout if stream_timeout else None

        # Send streaming request
        async with client.stream(
            "POST",
            f"{self.url}/a2a",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "method": "task/sendSubscribe",
                "params": {"task": task_data},
                "id": 1,
            },
        ) as response:
            # Check for non-streaming error response
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                # Non-streaming JSON error
                data = json.loads(await response.aread())
                if "error" in data:
                    error = data["error"]
                    raise A2AError(error.get("message", "Unknown error"), error.get("data", {}))

            # Parse SSE events
            data_buffer = ""
            async for line in response.aiter_lines():
                # Check stream timeout (prevents slow-drip DoS)
                if deadline and time.monotonic() > deadline:
                    raise TimeoutError(
                        f"Stream timeout exceeded ({stream_timeout}s). This prevents slow-drip DoS attacks."
                    )
                line = line.strip()

                if line.startswith("data:"):
                    data_buffer = line[5:].strip()
                elif line == "" and data_buffer:
                    # End of event
                    try:
                        event_data = json.loads(data_buffer)
                        update = TaskUpdate.from_dict(event_data)

                        # SECURITY: Validate task_id to prevent response spoofing
                        response_task_id = event_data.get("task_id")
                        if response_task_id and response_task_id != expected_task_id:
                            msg = (
                                f"Task ID mismatch in stream: expected {expected_task_id!r}, "
                                f"got {response_task_id!r}. Possible response spoofing."
                            )
                            if strict_task_id:
                                raise ValueError(msg)
                            logger.warning(msg)

                        # Check for error events
                        if update.type.value == "error":
                            error_code = event_data.get("code")
                            error_message = event_data.get("message", "Error during streaming")

                            # Check for mid-stream expiry
                            if error_code == -32004 and event_data.get("data", {}).get("mid_stream"):
                                raise WarrantExpiredError()

                            raise A2AError(error_message, event_data.get("data", {}))

                        yield update

                        # Stop on complete
                        if update.type.value == "complete":
                            return

                    except json.JSONDecodeError:
                        logger.warning(f"Invalid SSE data: {data_buffer!r}")
                    finally:
                        data_buffer = ""


# =============================================================================
# Delegation Helper
# =============================================================================


async def delegate(
    to: str,
    warrant: "Warrant",
    message: Union[str, Message],
    *,
    skill: str,
    arguments: Optional[Dict[str, Any]] = None,
    pin_key: Optional[str] = None,
    warrant_chain: Optional[List["Warrant"]] = None,
) -> TaskResult:
    """
    Convenience function to delegate a task to another agent.

    NOTE: This expects a pre-attenuated warrant. Attenuation happens BEFORE
    calling delegate(), not inside it. This keeps the function simple and
    gives callers full control over attenuation.

    Example:
        # Step 1: Attenuate your warrant for the target
        attenuated = my_warrant.attenuate(
            grants=[Grant("search_papers")],
            audience="https://research-agent.example.com",  # Bind to target
            ttl=300,
            key=my_key,
        )

        # Step 2: Delegate with the attenuated warrant
        result = await delegate(
            to="https://research-agent.example.com",
            warrant=attenuated,
            message="Find TOCTOU papers",
            skill="search_papers",
        )

    Args:
        to: Target agent URL
        warrant: Warrant for authorization (should be pre-attenuated with audience)
        message: Task message
        skill: Skill to invoke (required)
        arguments: Skill arguments
        pin_key: Expected public key of target (for TOFU protection)
        warrant_chain: Optional delegation chain (if warrant was delegated)

    Returns:
        TaskResult from the target agent
    """
    async with A2AClient(to, pin_key=pin_key) as client:
        return await client.send_task(
            message=message,
            warrant=warrant,
            skill=skill,
            arguments=arguments,
            warrant_chain=warrant_chain,
        )
