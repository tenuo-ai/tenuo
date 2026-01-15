"""
tenuo[a2a] - Inter-agent delegation with warrant-based authorization.

A2A handles agent-to-agent communication. This package adds warrant-based
authorization to that communication.

Server usage:
    from tenuo.a2a import A2AServer
    from tenuo.constraints import Subpath

    server = A2AServer(
        name="Research Agent",
        url="https://research-agent.example.com",
        public_key=my_public_key,
        trusted_issuers=[orchestrator_key],
    )

    @server.skill("read_file", constraints={"path": Subpath})
    async def read_file(path: str) -> str:
        with open(path) as f:
            return f.read()

    uvicorn.run(server.app, port=8000)

Client usage:
    from tenuo.a2a import A2AClient, delegate

    client = A2AClient("https://research-agent.example.com")
    result = await client.send_task(
        message="Read the config",
        warrant=my_warrant,
    )
"""

from .types import (
    # Core types
    Grant,
    AgentCard,
    SkillInfo,
    Message,
    TaskResult,
    TaskUpdate,
    TaskUpdateType,
    # Audit
    AuditEvent,
    AuditEventType,
    # Context
    current_task_warrant,
)

from .errors import (
    # Base
    A2AError,
    A2AErrorCode,
    # Warrant validation
    MissingWarrantError,
    InvalidSignatureError,
    UntrustedIssuerError,
    WarrantExpiredError,
    AudienceMismatchError,
    ReplayDetectedError,
    # Authorization
    SkillNotFoundError,
    SkillNotGrantedError,
    ConstraintViolationError,
    UnknownConstraintError,
    RevokedError,
    # Chain
    ChainInvalidError,
    ChainMissingError,
    ChainValidationError,
    ChainReason,
    # PoP (Proof-of-Possession)
    PopRequiredError,
    PopVerificationError,
    MissingSigningKeyError,
    # Client
    KeyMismatchError,
    # Configuration
    ConstraintBindingError,
)

from .server import A2AServer
from .client import A2AClient, delegate
from .helpers import explain, explain_str, visualize_chain, dry_run, simulate, SimulationTrace

__all__ = [
    # Server
    "A2AServer",
    # Client
    "A2AClient",
    "delegate",
    # DX Helpers
    "explain",
    "explain_str",
    "visualize_chain",
    "dry_run",
    "simulate",
    "SimulationTrace",
    # Types
    "Grant",
    "AgentCard",
    "SkillInfo",
    "Message",
    "TaskResult",
    "TaskUpdate",
    "TaskUpdateType",
    # Audit
    "AuditEvent",
    "AuditEventType",
    # Context
    "current_task_warrant",
    # Errors
    "A2AError",
    "A2AErrorCode",
    "MissingWarrantError",
    "InvalidSignatureError",
    "UntrustedIssuerError",
    "WarrantExpiredError",
    "AudienceMismatchError",
    "ReplayDetectedError",
    "SkillNotFoundError",
    "SkillNotGrantedError",
    "ConstraintViolationError",
    "UnknownConstraintError",
    "RevokedError",
    "ChainInvalidError",
    "ChainMissingError",
    "ChainValidationError",
    "ChainReason",
    "PopRequiredError",
    "PopVerificationError",
    "MissingSigningKeyError",
    "KeyMismatchError",
    "ConstraintBindingError",
]
