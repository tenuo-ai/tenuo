#!/usr/bin/env python3
"""
FastAPI Complete Integration Example

This example demonstrates a complete FastAPI application with Tenuo authorization:
- SecureAPIRouter for automatic route protection
- Multiple protected endpoints with automatic tool name inference
- Error handling and proper HTTP responses
- SigningKey loading from secrets
- Request-scoped warrant validation with client-side PoP

Key Patterns:
1. configure_tenuo() for app-level setup
2. SecureAPIRouter as drop-in replacement for APIRouter
3. Automatic warrant extraction from X-Tenuo-Warrant header
4. Automatic PoP signature verification from X-Tenuo-PoP header
5. Tool names auto-inferred from HTTP method + path

Run with: uvicorn fastapi_integration:app --reload
"""

import os
import logging
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, HTTPException
from tenuo import SigningKey, Warrant, Pattern, Range
from tenuo.fastapi import SecureAPIRouter, configure_tenuo, SecurityContext

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

# In production, load from environment or K8s secret
KEYPAIR_PATH = os.getenv("TENUO_KEYPAIR_PATH", "/var/run/secrets/tenuo/signing_key")


# ============================================================================
# SigningKey Loading (Issuer Identity)
# ============================================================================


def load_issuer_signing_key() -> SigningKey:
    """
    Load issuer signing_key from file (e.g., K8s secret mount).

    In production:
    - Load from /var/run/secrets/tenuo/signing_key (K8s Secret)
    - Or from environment variable (for local dev)
    - Or from AWS Secrets Manager / HashiCorp Vault

    Note: For FastAPI with client-side PoP, this is the ISSUER key used
    to verify warrant signatures, not the holder's key.
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
ISSUER_KEY = load_issuer_signing_key()
logger.info(f"Issuer signing_key loaded (public key: {ISSUER_KEY.public_key.to_bytes()[:8].hex()}...)")

# ============================================================================
# FastAPI App with Tenuo Configuration
# ============================================================================

app = FastAPI(
    title="Tenuo FastAPI Example",
    description="Complete FastAPI integration with Tenuo authorization using SecureAPIRouter",
    version="1.0.0",
)

# Configure Tenuo with trusted issuer
configure_tenuo(
    app,
    trusted_issuers=[ISSUER_KEY.public_key],
    expose_error_details=False,  # SECURITY: Keep False in production
)

logger.info("Tenuo configured with SecureAPIRouter pattern")

# ============================================================================
# Protected Tool Functions (Business Logic)
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


def read_file_internal(file_path: str) -> str:
    """
    Internal file reading function.
    Path is validated by Tenuo constraints AND sanitized here.
    """
    full_path = _resolve_under_root(file_path)

    try:
        with open(full_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except Exception:
        raise HTTPException(status_code=500, detail="Error reading file")


def write_file_internal(file_path: str, content: str) -> None:
    """
    Internal file writing function.
    Path is validated by Tenuo constraints AND sanitized here.
    """
    full_path = _resolve_under_root(file_path)

    try:
        # Ensure root exists for this example
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
    except Exception:
        raise HTTPException(status_code=500, detail="Error writing file")


def manage_cluster_internal(cluster: str, action: str, replicas: int) -> dict:
    """
    Internal cluster management function.
    Constraints on cluster name pattern and replicas are enforced by Tenuo.
    """
    # Simulate cluster management
    return {
        "status": "success",
        "cluster": cluster,
        "action": action,
        "replicas": replicas,
        "message": f"Executed {action} on {cluster} with {replicas} replicas",
    }


# ============================================================================
# SecureAPIRouter - Automatic Protection
# ============================================================================

# Create secure router with automatic Tenuo protection
# Tool names are auto-inferred: GET /api/files/{path} → "api_files_read"
router = SecureAPIRouter(
    prefix="/api",
    tool_prefix="api",  # Prefix for auto-generated tool names
    tags=["protected"],
)


@router.get("/files/{file_path:path}", tool="read_file")
async def read_file_endpoint(file_path: str, ctx: SecurityContext):
    """
    Read file endpoint with automatic Tenuo protection.

    Authorization:
    - Warrant and PoP signature extracted automatically from headers
    - Tool name: "read_file" (explicit override)
    - Arguments: {"file_path": "..."} extracted from path
    - Constraints checked: path must match warrant constraints

    Returns file content if authorized.
    """
    # SecurityContext provides access to verified warrant and args
    logger.info(f"File read authorized by warrant {ctx.warrant.id}")

    content = read_file_internal(file_path)
    return {
        "status": "success",
        "file_path": file_path,
        "content": content[:100] + "..." if len(content) > 100 else content,
        "warrant_holder": ctx.holder,
    }


@router.post("/files/{file_path:path}", tool="write_file")
async def write_file_endpoint(file_path: str, body: Dict[str, str], ctx: SecurityContext):
    """
    Write file endpoint with automatic Tenuo protection.

    Authorization:
    - Tool name: "write_file" (explicit override)
    - Arguments: {"file_path": "...", "content": "..."}
    - Constraints checked before execution
    """
    content = body.get("content", "")
    write_file_internal(file_path, content)

    return {
        "status": "success",
        "file_path": file_path,
        "message": "File written successfully",
        "warrant_id": ctx.warrant.id,
    }


@router.post("/cluster/{cluster}", tool="manage_cluster")
async def manage_cluster_endpoint(cluster: str, request: Dict[str, any], ctx: SecurityContext):
    """
    Cluster management endpoint with automatic Tenuo protection.

    Authorization:
    - Tool name: "manage_cluster" (explicit override)
    - Arguments: {"cluster": "...", "action": "...", "replicas": ...}
    - Constraints: cluster pattern and replicas range
    """
    action = request.get("action", "status")
    replicas = request.get("replicas", 1)

    result = manage_cluster_internal(cluster, action, replicas)
    result["warrant_holder"] = ctx.holder
    return result


# Include the secure router in the app
app.include_router(router)

# ============================================================================
# Public Endpoints (No Authorization Required)
# ============================================================================


@app.get("/")
async def root():
    """Public endpoint (no warrant required)."""
    return {
        "message": "Tenuo FastAPI Example with SecureAPIRouter",
        "pattern": "Automatic protection with auto-inferred tool names",
        "endpoints": {
            "read_file": "GET /api/files/{file_path}",
            "write_file": "POST /api/files/{file_path}",
            "manage_cluster": "POST /api/cluster/{cluster}",
            "health": "/health",
        },
        "authorization": {
            "header": "X-Tenuo-Warrant: <base64-encoded-warrant>",
            "pop_header": "X-Tenuo-PoP: <base64-encoded-signature>",
            "pattern": "Client-side PoP (Remote PEP)",
        },
    }


@app.get("/health")
async def health():
    """Health check endpoint (no warrant required)."""
    return {"status": "healthy", "issuer_key_loaded": True, "integration": "SecureAPIRouter"}


# ============================================================================
# Demo/Testing Functions
# ============================================================================


def create_demo_warrants() -> Dict[str, tuple[Warrant, str]]:
    """
    Create demo warrants for testing.
    In production, warrants are issued by the control plane.

    Note: In FastAPI with client-side PoP, the CLIENT holds a signing key
    and creates PoP signatures. The server (this API) only needs the issuer's
    public key to verify warrant signatures.
    """
    # Generate a client key (would be held by the API client)
    client_key = SigningKey.generate()

    read_warrant = (
        Warrant.mint_builder()
        .capability("read_file", file_path=Pattern("/tmp/*"))
        .holder(client_key.public_key)
        .ttl(3600)
        .mint(ISSUER_KEY)
    )

    write_warrant = (
        Warrant.mint_builder()
        .capability("write_file", file_path=Pattern("/tmp/*"))
        .holder(client_key.public_key)
        .ttl(3600)
        .mint(ISSUER_KEY)
    )

    cluster_warrant = (
        Warrant.mint_builder()
        .capability("manage_cluster", cluster=Pattern("staging-*"), replicas=Range.max_value(15))
        .holder(client_key.public_key)
        .ttl(3600)
        .mint(ISSUER_KEY)
    )

    return {
        "read_file": (read_warrant, read_warrant.to_base64(), client_key),
        "write_file": (write_warrant, write_warrant.to_base64(), client_key),
        "manage_cluster": (cluster_warrant, cluster_warrant.to_base64(), client_key),
    }


if __name__ == "__main__":
    import uvicorn
    import base64

    print("=" * 70)
    print("Tenuo FastAPI Integration Example - SecureAPIRouter Pattern")
    print("=" * 70)
    print(f"\nIssuer key loaded: {ISSUER_KEY.public_key.to_bytes()[:8].hex()}...")
    print("\nPattern: SecureAPIRouter with automatic protection")
    print("  - Tool names auto-inferred from routes")
    print("  - Warrant + PoP extracted automatically")
    print("  - Client-side PoP (Remote PEP pattern)")

    print("\n" + "=" * 70)
    print("Testing with demo warrants:")
    print("=" * 70)

    warrants = create_demo_warrants()
    read_warrant, read_b64, client_key = warrants["read_file"]

    # Create test file for demo
    test_file = FILE_ROOT / "test.txt"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text("Hello from Tenuo FastAPI!")

    print("\n# 1. Read file (authorized):")
    print(f"   File: {test_file}")

    # Create PoP signature for this specific call
    args = {"file_path": "test.txt"}
    pop_sig = read_warrant.sign(client_key, "read_file", args)
    pop_b64 = base64.b64encode(bytes(pop_sig)).decode("utf-8")

    print(f'   curl -H "X-Tenuo-Warrant: {read_b64[:60]}..." \\')
    print(f'        -H "X-Tenuo-PoP: {pop_b64[:40]}..." \\')
    print("        http://localhost:8000/api/files/test.txt")

    print("\n# 2. Write file:")
    write_warrant, write_b64, write_key = warrants["write_file"]
    write_args = {"file_path": "output.txt"}
    write_pop = write_warrant.sign(write_key, "write_file", write_args)
    write_pop_b64 = base64.b64encode(bytes(write_pop)).decode("utf-8")

    print(f'   curl -X POST -H "X-Tenuo-Warrant: {write_b64[:60]}..." \\')
    print(f'        -H "X-Tenuo-PoP: {write_pop_b64[:40]}..." \\')
    print('        -H "Content-Type: application/json" \\')
    print('        -d \'{"content":"Hello World"}\' \\')
    print("        http://localhost:8000/api/files/output.txt")

    print("\n# 3. Manage cluster:")
    cluster_warrant, cluster_b64, cluster_key = warrants["manage_cluster"]
    cluster_args = {"cluster": "staging-web", "action": "scale", "replicas": 5}
    cluster_pop = cluster_warrant.sign(cluster_key, "manage_cluster", cluster_args)
    cluster_pop_b64 = base64.b64encode(bytes(cluster_pop)).decode("utf-8")

    print(f'   curl -X POST -H "X-Tenuo-Warrant: {cluster_b64[:60]}..." \\')
    print(f'        -H "X-Tenuo-PoP: {cluster_pop_b64[:40]}..." \\')
    print('        -H "Content-Type: application/json" \\')
    print('        -d \'{"action":"scale","replicas":5}\' \\')
    print("        http://localhost:8000/api/cluster/staging-web")

    print("\n" + "=" * 70)
    print("Key Points:")
    print("=" * 70)
    print("✓ SecureAPIRouter replaces standard APIRouter")
    print("✓ Each route automatically protected with TenuoGuard")
    print("✓ Tool names inferred or explicitly set with tool= parameter")
    print("✓ Client creates PoP signature with their signing key")
    print("✓ Server verifies warrant signature + PoP signature + constraints")
    print("✓ Same security as manual pattern, less boilerplate")

    print("\n" + "=" * 70)
    print("Starting server on http://localhost:8000")
    print("=" * 70 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=8000)
