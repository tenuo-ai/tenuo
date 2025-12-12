import json
import datetime
from tenuo import (
    GatewayConfig, CompiledGatewayConfig, RevocationManager,
    Keypair, Warrant, Authorizer, SignedRevocationList,
    MAX_CONSTRAINT_DEPTH, WIRE_VERSION, Exact
)

def test_gateway_config():
    print("\n=== Testing Gateway Config ===")
    
    yaml_config = """
version: "1.0"
settings:
  warrant_header: "X-Tenuo-Warrant"
  pop_header: "X-Tenuo-Signature"

tools:
  read_user:
    description: "Read user data"
    constraints: {}
  write_data:
    description: "Write data"
    constraints: {}

routes:
  - pattern: "/api/v1/users/{user_id}"
    method: ["GET"]
    tool: "read_user"
    extra_constraints:
      user_id:
        from: "path"
        path: "user_id"
      request_id:
        from: "header"
        path: "X-Request-ID"
        
  - pattern: "/api/v1/data"
    method: ["POST"]
    tool: "write_data"
    extra_constraints:
      payload:
        from: "body"
        path: "data"
"""

    # 1. Load Config
    print("Loading config from YAML...")
    config = GatewayConfig.from_yaml(yaml_config)
    print(f"Config version: {config.version}")
    
    # 2. Compile Config
    print("Compiling config...")
    compiled = CompiledGatewayConfig.compile(config)
    
    # 3. Test Extraction (Match)
    print("Testing extraction (match)...")
    headers = {"X-Request-ID": "req-123"}
    query = {}
    body = None
    
    result = compiled.extract("GET", "/api/v1/users/alice", headers, query, body)
    assert result is not None
    tool, constraints = result
    print(f"Matched tool: {tool}")
    print(f"Extracted constraints: {constraints}")
    
    assert tool == "read_user"
    assert constraints["user_id"] == "alice"
    assert constraints["request_id"] == "req-123"
    
    # 4. Test Extraction (No Match)
    print("Testing extraction (no match)...")
    result = compiled.extract("POST", "/api/v1/users/alice", headers, query, body)
    assert result is None
    print("Correctly returned None for non-matching route")

    # 5. Test Body Extraction
    print("Testing body extraction...")
    body_dict = {"data": {"foo": "bar"}}
    result = compiled.extract("POST", "/api/v1/data", headers, query, body_dict)
    assert result is not None
    tool, constraints = result
    print(f"Matched tool: {tool}")
    print(f"Extracted constraints: {constraints}")
    
    assert tool == "write_data"
    assert constraints["payload"] == {"foo": "bar"}

def test_revocation():
    print("\n=== Testing Revocation ===")
    
    # Setup keys
    cp_kp = Keypair.generate()
    issuer_kp = Keypair.generate()
    holder_kp = Keypair.generate()
    
    # Create a warrant (PoP-bound to holder)
    warrant = Warrant.create(
        tool="read_user",
        constraints={"user_id": Exact("alice")},
        ttl_seconds=3600,
        keypair=issuer_kp,
        authorized_holder=holder_kp.public_key(),  # PoP is mandatory
    )
    
    # Initialize Revocation Manager
    manager = RevocationManager()
    
    # 1. Submit Revocation Request
    print("Submitting revocation request...")
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat() + "Z"
    
    manager.submit_request(
        warrant_id=warrant.id,
        reason="Key compromise",
        warrant_issuer=issuer_kp.public_key(),  # Note: method call
        warrant_expires_at=expires_at,
        control_plane_key=cp_kp.public_key(),   # Note: method call
        revocation_keypair=issuer_kp,  # Issuer revoking
        warrant_holder=None
    )
    
    pending = manager.pending_ids()
    print(f"Pending revocations: {pending}")
    assert warrant.id in pending
    
    # 2. Generate SRL
    print("Generating SRL...")
    srl = manager.generate_srl(cp_kp, 1)
    print(f"SRL Version: {srl.version}")
    revoked = srl.revoked_ids()  # Note: method call
    print(f"Revoked IDs count: {len(revoked)}")
    assert warrant.id in revoked
    
    # 3. Verify Revocation with Authorizer
    print("Verifying revocation with Authorizer...")
    authorizer = Authorizer.new(cp_kp.public_key())  # Note: factory method
    authorizer.set_revocation_list(srl, cp_kp.public_key())  # Note: needs expected_issuer
    
    # Check chain (should fail because warrant is revoked)
    try:
        authorizer.verify_chain([warrant])
        print("ERROR: Warrant should be revoked but passed verification!")
    except Exception as e:
        print(f"Success: Verification failed as expected: {e}")
        assert "revoked" in str(e).lower()

if __name__ == "__main__":
    try:
        test_gateway_config()
        test_revocation()
        print("\nAll tests passed!")
    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
