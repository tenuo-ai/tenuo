#!/usr/bin/env python3
"""
Kubernetes Integration Example with Tenuo + LangChain

This example demonstrates how to use Tenuo with LangChain agents running in Kubernetes.

Key Patterns:
1. Warrants loaded from environment variables or mounted secrets
2. Warrant context set per-request (from headers or request metadata)
3. Control plane issues warrants, agents verify locally
4. Works across pods, services, and ingress

Architecture:
    Control Plane (Issuer)
         │
         │ Issues warrant (signed)
         ▼
    Kubernetes Secret / ConfigMap
         │
         │ Mounted to pods
         ▼
    LangChain Agent Pods
         │
         │ Load warrant at startup
         │ Set in context per-request
         ▼
    Protected Tool Functions (@lockdown)
"""

from tenuo import (
    Keypair, Warrant, Pattern, Range, Exact,
    lockdown, set_warrant_context, AuthorizationError
)
from typing import Optional, Dict, Any
import os
import json
import base64


# ============================================================================
# Warrant Loading from Kubernetes Environment
# ============================================================================

def load_warrant_from_env() -> Optional[Warrant]:
    """
    Load warrant from Kubernetes environment variable.
    
    ENV VARIABLE: TENUO_WARRANT_BASE64 (set by K8s Secret/ConfigMap)
    
    In K8s, you would set this via:
    - ConfigMap (for non-sensitive warrants)
    - Secret (for sensitive warrants) - RECOMMENDED
    - Init container that fetches from control plane
    
    Example K8s Secret:
        apiVersion: v1
        kind: Secret
        metadata:
          name: tenuo-warrant
        type: Opaque
        stringData:
          WARRANT_BASE64: <base64-encoded-warrant>
    
    Returns:
        Warrant if successfully loaded, None if not found or invalid.
    """
    warrant_b64 = os.getenv("TENUO_WARRANT_BASE64")
    if not warrant_b64:
        return None
    
    try:
        return Warrant.from_base64(warrant_b64)
    except ValueError as e:
        # Invalid base64 or warrant format
        print(f"Error: Invalid warrant format in TENUO_WARRANT_BASE64: {e}")
        return None
    except Exception as e:
        # Unexpected error
        print(f"Error loading warrant from env: {e}")
        return None


def load_warrant_from_file(path: str = "/etc/tenuo/warrant.b64") -> Optional[Warrant]:
    """
    Load warrant from mounted Kubernetes Secret/ConfigMap.
    
    HARDCODED DEFAULT PATH: /etc/tenuo/warrant.b64
    In production: Use env var TENUO_WARRANT_FILE_PATH or config.
    
    Example K8s Deployment:
        volumes:
        - name: tenuo-warrant
          secret:
            secretName: tenuo-warrant
        containers:
        - volumeMounts:
          - name: tenuo-warrant
            mountPath: /etc/tenuo
            readOnly: true
    
    Args:
        path: File path to warrant (default: /etc/tenuo/warrant.b64)
    
    Returns:
        Warrant if successfully loaded, None if not found or invalid.
    """
    try:
        with open(path, 'r') as f:
            warrant_b64 = f.read().strip()
        if not warrant_b64:
            print(f"Warning: Warrant file {path} is empty")
            return None
        return Warrant.from_base64(warrant_b64)
    except FileNotFoundError:
        # File doesn't exist - this is normal if warrant is loaded from env instead
        return None
    except PermissionError:
        print(f"Error: Permission denied reading warrant file: {path}")
        return None
    except ValueError as e:
        # Invalid base64 or warrant format
        print(f"Error: Invalid warrant format in {path}: {e}")
        return None
    except Exception as e:
        # Unexpected error
        print(f"Error loading warrant from file {path}: {e}")
        return None


def load_warrant_from_request_header(headers: Dict[str, str]) -> Optional[Warrant]:
    """
    Load warrant from HTTP request header (e.g., from ingress or API gateway).
    
    This is useful when:
    - Ingress validates warrant before forwarding
    - API gateway issues warrants per-request
    - Warrant is passed from upstream service
    
    Example header:
        X-Tenuo-Warrant: <base64-encoded-warrant>
    """
    warrant_header = headers.get("X-Tenuo-Warrant") or headers.get("x-tenuo-warrant")
    if not warrant_header:
        return None
    
    try:
        return Warrant.from_base64(warrant_header)
    except Exception as e:
        print(f"Error loading warrant from header: {e}")
        return None


# ============================================================================
# Control Plane: Warrant Issuance (Simulated)
# ============================================================================

class ControlPlane:
    """
    [SIMULATION] Simulates a control plane service that issues warrants.
    
    This is a demo class. In production, the control plane would be:
    - A separate K8s service/deployment
    - Authenticated via service account tokens
    - Issues warrants based on agent registration/policy
    - Stores root keypair in secure storage (K8s Secret, HSM, etc.)
    """
    
    def __init__(self, keypair: Keypair):
        self.keypair = keypair
    
    def issue_agent_warrant(
        self,
        agent_id: str,
        constraints: Dict[str, Any],
        ttl_seconds: int = 3600
    ) -> Warrant:
        """
        [SIMULATION] Issue a warrant for a specific agent.
        
        In K8s, this might be called:
        - During agent pod startup (init container)
        - Via admission webhook
        - Via operator that watches agent deployments
        
        Args:
            agent_id: Identifier for the agent (for logging/audit)
            constraints: Constraint dictionary (e.g., {"file_path": Pattern("/tmp/*")})
            ttl_seconds: Time-to-live in seconds (HARDCODED default: 3600)
        
        Returns:
            Warrant object
        """
        return Warrant.create(
            tool="agent_tools",  # HARDCODED: General tool name. In production, use config.
            constraints=constraints,
            ttl_seconds=ttl_seconds,  # HARDCODED default: 3600. In production, use env var or config.
            keypair=self.keypair
        )
    
    def issue_warrant_for_request(
        self,
        request_metadata: Dict[str, Any],
        ttl_seconds: int = 300  # Short TTL for request-scoped warrants
    ) -> Warrant:
        """
        Issue a warrant for a specific request (e.g., from API gateway).
        
        This is useful for:
        - Per-request authorization
        - Dynamic constraint injection based on user/tenant
        - Request-scoped capabilities
        """
        # Extract constraints from request metadata (user, tenant, etc.)
        constraints = {
            "user_id": Exact(request_metadata.get("user_id", "anonymous")),
            "tenant": Pattern(request_metadata.get("tenant", "*")),
        }
        
        return Warrant.create(
            tool="agent_tools",
            constraints=constraints,
            ttl_seconds=ttl_seconds,
            keypair=self.keypair
        )


# ============================================================================
# Protected Tool Functions
# ============================================================================

@lockdown(tool="read_file", extract_args=lambda file_path, **kwargs: {"file_path": file_path})
def read_file_tool(file_path: str) -> str:
    """Read a file. Protected by Tenuo."""
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: File not found: {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"


@lockdown(tool="write_file", extract_args=lambda file_path, content, **kwargs: {"file_path": file_path, "content": content})
def write_file_tool(file_path: str, content: str) -> str:
    """Write to a file. Protected by Tenuo."""
    try:
        with open(file_path, 'w') as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {file_path}"
    except Exception as e:
        return f"Error: {str(e)}"


# ============================================================================
# Kubernetes-Aware LangChain Integration
# ============================================================================

class KubernetesWarrantManager:
    """
    Manages warrants in a Kubernetes environment.
    
    Supports multiple warrant sources:
    1. Environment variable (for pod-level warrants)
    2. Mounted secret/file (for persistent warrants)
    3. Request headers (for per-request warrants)
    """
    
    def __init__(self):
        # Try to load warrant at startup (from env or file)
        self.pod_warrant = (
            load_warrant_from_env() or
            load_warrant_from_file() or
            None
        )
        
        if self.pod_warrant:
            print(f"✓ Loaded pod-level warrant (tool: {self.pod_warrant.tool})")
        else:
            print("⚠ No pod-level warrant found - will use request-scoped warrants")
    
    def get_warrant_for_request(
        self,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[Warrant]:
        """
        Get warrant for current request.
        
        Priority:
        1. Request header (per-request warrant)
        2. Pod-level warrant (from env/file)
        
        Returns None if no warrant available.
        """
        # Try request header first (most specific)
        if headers:
            request_warrant = load_warrant_from_request_header(headers)
            if request_warrant:
                return request_warrant
        
        # Fall back to pod-level warrant
        return self.pod_warrant


# ============================================================================
# FastAPI Integration Example (Common in K8s)
# ============================================================================

def create_fastapi_middleware_example():
    """
    Example FastAPI middleware for Kubernetes deployment.
    
    This shows how to integrate Tenuo with FastAPI in K8s:
    - Load warrant from request headers or pod-level config
    - Set warrant in context for all request handlers
    - Works with LangChain agents called from FastAPI routes
    """
    middleware_code = '''
from fastapi import FastAPI, Request, Header
from tenuo import set_warrant_context, AuthorizationError
from kubernetes_warrant_manager import KubernetesWarrantManager

app = FastAPI()
warrant_manager = KubernetesWarrantManager()

@app.middleware("http")
async def tenuo_middleware(request: Request, call_next):
    """Set warrant in context for each request."""
    # Get warrant from request headers or pod-level config
    headers = dict(request.headers)
    warrant = warrant_manager.get_warrant_for_request(headers)
    
    if not warrant:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="No warrant available")
    
    # Set warrant in context for this request
    with set_warrant_context(warrant):
        response = await call_next(request)
        return response

@app.post("/agent/run")
async def run_agent(prompt: str, request: Request):
    """Run LangChain agent with Tenuo protection."""
    # Warrant is already in context from middleware
    # All @lockdown functions are automatically protected
    from langchain_agent import agent_executor
    
    response = agent_executor.invoke({"input": prompt})
    return {"output": response["output"]}
'''
    return middleware_code


# ============================================================================
# Kubernetes Deployment Examples
# ============================================================================

def generate_kubernetes_manifests():
    """
    Generate example Kubernetes manifests for Tenuo + LangChain deployment.
    """
    
    deployment_yaml = '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: langchain-agent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: langchain-agent
  template:
    metadata:
      labels:
        app: langchain-agent
    spec:
      serviceAccountName: langchain-agent
      initContainers:
      # Optional: Fetch warrant from control plane at startup
      - name: fetch-warrant
        image: tenuo/fetch-warrant:latest
        env:
        - name: AGENT_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: CONTROL_PLANE_URL
          value: "https://control-plane.tenuo.svc.cluster.local"
        volumeMounts:
        - name: warrant
          mountPath: /etc/tenuo
      containers:
      - name: agent
        image: langchain-agent:latest
        env:
        # Option 1: Warrant from mounted secret
        - name: TENUO_WARRANT_BASE64
          valueFrom:
            secretKeyRef:
              name: tenuo-warrant
              key: WARRANT_BASE64
        # Option 2: Load from file (mounted secret)
        volumeMounts:
        - name: warrant
          mountPath: /etc/tenuo
          readOnly: true
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: warrant
        secret:
          secretName: tenuo-warrant
---
apiVersion: v1
kind: Secret
metadata:
  name: tenuo-warrant
type: Opaque
stringData:
  WARRANT_BASE64: <base64-encoded-warrant-from-control-plane>
---
apiVersion: v1
kind: Service
metadata:
  name: langchain-agent
spec:
  selector:
    app: langchain-agent
  ports:
  - port: 8000
    targetPort: 8000
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: langchain-agent
  annotations:
    # Optional: Ingress can validate/forward warrants
    nginx.ingress.kubernetes.io/configuration-snippet: |
      proxy_set_header X-Tenuo-Warrant $http_x_tenuo_warrant;
spec:
  rules:
  - host: agent.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: langchain-agent
            port:
              number: 8000
'''
    
    return deployment_yaml


# ============================================================================
# Main Example
# ============================================================================

def main():
    print("=== Tenuo + LangChain Kubernetes Integration ===\n")
    
    # ========================================================================
    # STEP 1: Simulate Control Plane Issuing Warrant (SIMULATION)
    # ========================================================================
    print("1. [SIMULATION] Control Plane: Issuing warrant for agent...")
    try:
        # SIMULATION: Generate keypair for demo
        # In production: Control plane keypair is loaded from secure storage (K8s Secret, HSM, etc.)
        control_keypair = Keypair.generate()
        control_plane = ControlPlane(control_keypair)
        
        # SIMULATION: Create warrant with hardcoded constraints
        # In production: Constraints come from policy engine, agent registration, or configuration
        # HARDCODED: tool="read_file", Pattern("/tmp/*"), ttl_seconds=3600
        # In production: Use env vars or config for these values
        agent_warrant = Warrant.create(
            tool="read_file",  # Match the tool name used in @lockdown decorator
            constraints={
                "file_path": Pattern("/tmp/*"),  # HARDCODED: Only /tmp/ files for demo safety
            },
            ttl_seconds=3600,  # HARDCODED: 1 hour TTL. In production, use env var or config.
            keypair=control_keypair
        )
        print(f"   ✓ Warrant issued (ID: {agent_warrant.id[:8]}...)")
        print(f"   ✓ Constraints: file_path=/tmp/*\n")
    except Exception as e:
        print(f"   ✗ Error creating warrant: {e}")
        return
    
    # ========================================================================
    # STEP 2: Simulate Loading Warrant in K8s Pod (SIMULATION)
    # ========================================================================
    print("2. [SIMULATION] Agent Pod: Loading warrant...")
    
    # SIMULATION: Set environment variable for demo
    # In production: This is set by K8s Secret/ConfigMap
    try:
        os.environ["TENUO_WARRANT_BASE64"] = agent_warrant.to_base64()
        warrant_from_env = load_warrant_from_env()
        if warrant_from_env:
            print(f"   ✓ Loaded from env (TENUO_WARRANT_BASE64): Success")
        else:
            print(f"   ⚠ Loaded from env: Failed (should not happen in this demo)")
    except Exception as e:
        print(f"   ✗ Error loading from env: {e}")
    
    # SIMULATION: Create temp file to simulate mounted K8s Secret
    # In real K8s: This would be mounted at /etc/tenuo/warrant.b64
    # HARDCODED PATH: /tmp/warrant.b64 (temp file for demo)
    # In production: Use /etc/tenuo/warrant.b64 or path from env var
    temp_warrant_file = "/tmp/warrant.b64"
    try:
        with open(temp_warrant_file, 'w') as f:
            f.write(agent_warrant.to_base64())
        
        # Load from the temp file (simulating mounted secret)
        warrant_from_file = load_warrant_from_file(temp_warrant_file)
        if warrant_from_file:
            print(f"   ✓ Loaded from file ({temp_warrant_file}): Success")
        else:
            print(f"   ⚠ Loaded from file: Failed")
    except Exception as e:
        print(f"   ✗ Error creating/loading temp warrant file: {e}\n")
    
    print()  # Blank line
    
    # ========================================================================
    # STEP 3: Initialize Warrant Manager (REAL CODE - Production-ready)
    # ========================================================================
    print("3. Initializing Kubernetes Warrant Manager...")
    try:
        warrant_manager = KubernetesWarrantManager()
        print()
    except Exception as e:
        print(f"   ✗ Error initializing warrant manager: {e}")
        return
    
    # ========================================================================
    # STEP 4: Simulate Request with Warrant in Header (SIMULATION)
    # ========================================================================
    print("4. [SIMULATION] Simulating request with warrant in header...")
    try:
        # SIMULATION: Create mock request headers
        # In production: Headers come from HTTP request (FastAPI, Flask, etc.)
        request_headers = {
            "X-Tenuo-Warrant": agent_warrant.to_base64(),  # HARDCODED: Demo warrant
            "User-Agent": "langchain-client/1.0"  # HARDCODED: Mock user agent
        }
        request_warrant = warrant_manager.get_warrant_for_request(request_headers)
        if request_warrant:
            print(f"   ✓ Loaded warrant from request header: Success\n")
        else:
            print(f"   ⚠ Loaded warrant from request: Failed\n")
    except Exception as e:
        print(f"   ✗ Error loading warrant from request: {e}\n")
    
    # ========================================================================
    # STEP 5: Demonstrate Protection (REAL CODE - Production-ready)
    # ========================================================================
    print("5. Testing protection with loaded warrant...")
    try:
        with set_warrant_context(agent_warrant):
            # Test authorized access
            # HARDCODED PATH: /tmp/test.txt for demo
            # In production: Use tempfile or env-specified test directory
            try:
                result = read_file_tool("/tmp/test.txt")
                print(f"   ✓ read_file('/tmp/test.txt'): Allowed (matches Pattern('/tmp/*'))")
            except AuthorizationError as e:
                print(f"   ✗ Unexpected authorization error: {e}")
            except Exception as e:
                print(f"   ✗ Unexpected error: {e}")
            
            # Test blocked access
            # HARDCODED PATH: /etc/passwd (protected system file for demo)
            try:
                read_file_tool("/etc/passwd")
                print("   ✗ Should have been blocked!")
            except AuthorizationError as e:
                print(f"   ✓ read_file('/etc/passwd'): Blocked ({str(e)[:60]}...)\n")
            except Exception as e:
                print(f"   ✗ Unexpected error (not AuthorizationError): {e}\n")
    except Exception as e:
        print(f"   ✗ Error in protection test: {e}\n")
    
    # ========================================================================
    # STEP 6: Show Deployment Pattern (DOCUMENTATION)
    # ========================================================================
    print("6. Kubernetes Deployment Pattern:")
    print("   - Control Plane issues warrant → K8s Secret")
    print("   - Agent pods mount secret → Load warrant at startup")
    print("   - Per-request warrants from headers → Set in context")
    print("   - All @lockdown functions automatically protected\n")
    
    print("=== Kubernetes Integration Complete ===\n")
    print("Key Points:")
    print("  ✓ Warrants loaded from K8s Secrets/ConfigMaps")
    print("  ✓ Per-request warrants from ingress/API gateway")
    print("  ✓ ContextVar works across async boundaries (FastAPI)")
    print("  ✓ No network calls - 100% offline verification")
    print("  ✓ Works across multiple pods/replicas")
    
    # ========================================================================
    # Cleanup (SIMULATION - Remove temp files)
    # ========================================================================
    try:
        if os.path.exists(temp_warrant_file):
            os.remove(temp_warrant_file)
    except Exception as e:
        print(f"\n⚠ Warning: Could not clean up temp file {temp_warrant_file}: {e}")


if __name__ == "__main__":
    main()

