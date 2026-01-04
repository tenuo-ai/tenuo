#!/usr/bin/env python3
"""
FastAPI Complete Integration Example

This example demonstrates a complete FastAPI application with Tenuo authorization:
- Middleware for warrant extraction and context setting
- Multiple protected endpoints
- Error handling and proper HTTP responses
- SigningKey loading from secrets
- Request-scoped warrant validation

Key Patterns:
1. Warrant extracted from X-Tenuo-Warrant header
2. SigningKey loaded from file (K8s secret mount)
3. Context set per-request in middleware
4. Protected endpoints use @guard decorator
5. Proper error handling with HTTP status codes

Run with: uvicorn fastapi_integration:app --reload
"""

import os
import logging
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from tenuo import (
    SigningKey,
    Warrant,
    Pattern,
    Range,
    guard,
    warrant_scope,
    key_scope,
)
from tenuo.exceptions import AuthorizationError, ScopeViolation

# Alias for backwards compatibility
WarrantError = ScopeViolation

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

# In production, load from environment or K8s secret
KEYPAIR_PATH = os.getenv("TENUO_KEYPAIR_PATH", "/var/run/secrets/tenuo/signing_key")
WARRANT_HEADER = "X-Tenuo-Warrant"

# ============================================================================
# SigningKey Loading (Agent Identity)
# ============================================================================

def load_agent_signing_key() -> SigningKey:
    """
    Load agent signing_key from file (e.g., K8s secret mount).

    In production:
    - Load from /var/run/secrets/tenuo/signing_key (K8s Secret)
    - Or from environment variable (for local dev)
    - Or from AWS Secrets Manager / HashiCorp Vault
    """
    try:
        if os.path.exists(KEYPAIR_PATH):
            with open(KEYPAIR_PATH, "r") as f:
                return SigningKey.from_pem(f.read())
        else:
            # Fallback: generate for demo (NOT for production!)
            logger.warning(f"SigningKey file not found at {KEYPAIR_PATH}, generating demo signing_key")
            return SigningKey.generate()
    except Exception as e:
        logger.error(f"Failed to load signing_key: {e}")
        raise


# Load signing_key at startup
AGENT_KEYPAIR = load_agent_signing_key()
logger.info(f"Agent signing_key loaded (public key: {AGENT_KEYPAIR.public_key.to_bytes()[:8].hex()}...)")

# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="Tenuo FastAPI Example",
    description="Complete FastAPI integration with Tenuo authorization",
    version="1.0.0"
)

# ============================================================================
# Middleware: Warrant Extraction and Context Setting
# ============================================================================

# ============================================================================
# Dependency Injection: Warrant Extraction
# ============================================================================

async def get_warrant(request: Request) -> Warrant:
    """
    FastAPI dependency to extract and validate warrant from request header.

    This pattern ensures contextvars propagate correctly through async boundaries.
    The warrant is extracted here and set in context within each endpoint handler.
    """
    warrant_b64 = request.headers.get(WARRANT_HEADER)

    if not warrant_b64:
        raise HTTPException(
            status_code=401,
            detail=f"Missing {WARRANT_HEADER} header"
        )

    try:
        warrant = Warrant.from_base64(warrant_b64)
        # Note: Expiration is checked by @guard decorator during authorization
        # No need to check here - let the decorator handle it with proper error messages
        return warrant
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid warrant format", "details": str(e)}
        )
    except Exception as e:
        logger.error(f"Warrant processing error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "Internal server error", "details": str(e)}
        )

# ============================================================================
# Protected Tool Functions
# ============================================================================

FILE_ROOT = Path("/tmp/tenuo_fastapi_demo").resolve()


def _resolve_under_root(user_path: str) -> Path:
    """
    Resolve a user-provided relative path under FILE_ROOT.

    This provides defense in depth for the FastAPI example and avoids
    directory traversal (even if the process working directory changes).
    """
    p = Path(user_path)
    if p.is_absolute():
        raise HTTPException(status_code=403, detail="Invalid path")

    full = (FILE_ROOT / p).resolve()
    try:
        full.relative_to(FILE_ROOT)
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid path")

    return full


@guard(tool="read_file")
def read_file(file_path: str) -> str:
    """
    Protected file reading function.
    Only authorized paths (per warrant constraints) are allowed.

    Security: Path is validated by Tenuo constraints AND sanitized here.
    """
    full_path = _resolve_under_root(file_path)

    try:
        with open(full_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except Exception:
        raise HTTPException(status_code=500, detail="Error reading file")


@guard(tool="write_file")
def write_file(file_path: str, content: str) -> None:
    """
    Protected file writing function.
    Only authorized paths (per warrant constraints) are allowed.

    Security: Path is validated by Tenuo constraints AND sanitized here.
    """
    full_path = _resolve_under_root(file_path)

    try:
        # Ensure root exists for this example
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
    except Exception:
        raise HTTPException(status_code=500, detail="Error writing file")


@guard(tool="manage_cluster")
def manage_cluster(cluster: str, action: str, replicas: int) -> dict:
    """
    Protected cluster management function.
    Constraints on cluster name pattern and replicas are enforced.
    """
    # Simulate cluster management
    return {
        "status": "success",
        "cluster": cluster,
        "action": action,
        "replicas": replicas,
        "message": f"Executed {action} on {cluster} with {replicas} replicas"
    }

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Public endpoint (no warrant required)."""
    return {
        "message": "Tenuo FastAPI Example",
        "endpoints": {
            "read_file": "/api/files/{file_path}",
            "write_file": "/api/files/{file_path}",
            "manage_cluster": "/api/cluster/{cluster}",
            "health": "/health"
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint (no warrant required)."""
    return {"status": "healthy", "agent_signing_key_loaded": True}


@app.get("/api/files/{file_path:path}")
async def read_file_endpoint(file_path: str, warrant: Warrant = Depends(get_warrant)):
    """
    Read file endpoint.

    Requires:
    - X-Tenuo-Warrant header with warrant authorizing "read_file"
    - Warrant constraints must allow the requested file_path

    Note: Warrant expiration and authorization are handled by @guard decorator.
    The middleware sets the context, and @guard uses it.
    """
    # Set warrant and signing_key in context for this request
    # This ensures contextvars propagate correctly through async boundaries
    with warrant_scope(warrant), key_scope(AGENT_KEYPAIR):
        try:
            content = read_file(file_path)
            return {
                "status": "success",
                "file_path": file_path,
                "content": content[:100] + "..." if len(content) > 100 else content
            }
        except AuthorizationError as e:
            logger.warning(f"Authorization failed for {file_path}: {e}")
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Authorization failed",
                    "message": str(e),
                    "file_path": file_path
                }
            )


@app.post("/api/files/{file_path:path}")
async def write_file_endpoint(file_path: str, content: dict, warrant: Warrant = Depends(get_warrant)):
    """
    Write file endpoint.

    Requires:
    - X-Tenuo-Warrant header with warrant authorizing "write_file"
    - Warrant constraints must allow the requested file_path
    """
    with warrant_scope(warrant), key_scope(AGENT_KEYPAIR):
        try:
            write_file(file_path, content.get("content", ""))
            return {
                "status": "success",
                "file_path": file_path,
                "message": "File written successfully"
            }
        except AuthorizationError as e:
            logger.warning(f"Authorization failed for {file_path}: {e}")
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Authorization failed",
                    "message": str(e),
                    "file_path": file_path
                }
            )


@app.post("/api/cluster/{cluster}")
async def manage_cluster_endpoint(cluster: str, request: dict, warrant: Warrant = Depends(get_warrant)):
    """
    Cluster management endpoint.

    Requires:
    - X-Tenuo-Warrant header with warrant authorizing "manage_cluster"
    - Warrant constraints must allow the cluster name and replicas
    """
    action = request.get("action", "status")
    replicas = request.get("replicas", 1)

    with warrant_scope(warrant), key_scope(AGENT_KEYPAIR):
        try:
            result = manage_cluster(cluster, action, replicas)
            return result
        except AuthorizationError as e:
            logger.warning(f"Authorization failed for cluster {cluster}: {e}")
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Authorization failed",
                    "message": str(e),
                    "cluster": cluster,
                    "action": action
                }
            )

# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(AuthorizationError)
async def authorization_error_handler(request: Request, exc: AuthorizationError):
    """Handle Tenuo authorization errors."""
    logger.warning(f"Authorization error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=403,
        content={
            "error": "Authorization failed",
            "message": str(exc),
            "path": request.url.path
        }
    )


@app.exception_handler(WarrantError)
async def warrant_error_handler(request: Request, exc: WarrantError):
    """Handle Tenuo warrant errors."""
    logger.error(f"Warrant error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=400,
        content={
            "error": "Warrant error",
            "message": str(exc),
            "path": request.url.path
        }
    )

# ============================================================================
# Demo/Testing Functions
# ============================================================================

def create_demo_warrants() -> dict[str, tuple[Warrant, str]]:
    """
    Create demo warrants for testing.
    In production, warrants are issued by the control plane.

    Note: Each tool gets its own warrant. This is the recommended pattern
    for fine-grained authorization control.
    """
    read_warrant = (Warrant.mint_builder()
        .capability("read_file", file_path=Pattern("/tmp/*"))
        .holder(AGENT_KEYPAIR.public_key)
        .ttl(3600)
        .mint(AGENT_KEYPAIR))

    write_warrant = (Warrant.mint_builder()
        .capability("write_file", file_path=Pattern("/tmp/*"))
        .holder(AGENT_KEYPAIR.public_key)
        .ttl(3600)
        .mint(AGENT_KEYPAIR))

    cluster_warrant = (Warrant.mint_builder()
        .capability("manage_cluster",
            cluster=Pattern("staging-*"),
            replicas=Range.max_value(15))
        .holder(AGENT_KEYPAIR.public_key)
        .ttl(3600)
        .mint(AGENT_KEYPAIR))

    return {
        "read_file": (read_warrant, read_warrant.to_base64()),
        "write_file": (write_warrant, write_warrant.to_base64()),
        "manage_cluster": (cluster_warrant, cluster_warrant.to_base64())
    }


if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("Tenuo FastAPI Integration Example")
    print("=" * 60)
    print(f"\nAgent signing_key loaded: {AGENT_KEYPAIR.public_key.to_bytes()[:8].hex()}...")
    print("\nTo test, create a warrant and include it in the X-Tenuo-Warrant header:")
    print("\nExample:")
    warrants = create_demo_warrants()
    read_warrant, read_b64 = warrants["read_file"]
    print("  # Read file:")
    print(f"  curl -H 'X-Tenuo-Warrant: {read_b64[:50]}...' http://localhost:8000/api/files/tmp/test.txt")
    print("\n  # Write file:")
    write_warrant, write_b64 = warrants["write_file"]
    print(f"  curl -X POST -H 'X-Tenuo-Warrant: {write_b64[:50]}...' \\")
    print("       -H 'Content-Type: application/json' \\")
    print("       -d '{\"content\":\"test\"}' \\")
    print("       http://localhost:8000/api/files/tmp/test.txt")
    print("\nStarting server on http://localhost:8000")
    print("=" * 60)

    uvicorn.run(app, host="0.0.0.0", port=8000)
