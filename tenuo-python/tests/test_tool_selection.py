"""Test tool selection methods in AttenuationBuilder."""
from tenuo import Keypair, Warrant, TrustLevel


def test_with_tool_single():
    """Test with_tool() sets a single tool for issuer warrants."""
    parent_kp = Keypair.generate()
    child_kp = Keypair.generate()
    
    # Create issuer warrant with multiple tools
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db"],
        trust_ceiling=TrustLevel.Internal,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # Attenuate to single tool
    child = issuer.attenuate().with_tool("read_file").delegate_to(child_kp, parent_kp)
    
    # Verify only one tool remains
    assert child.issuable_tools == ["read_file"]


def test_with_tools_multiple():
    """Test with_tools() sets multiple tools for issuer warrants."""
    parent_kp = Keypair.generate()
    child_kp = Keypair.generate()
    
    # Create issuer warrant with multiple tools
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db", "delete_file"],
        trust_ceiling=TrustLevel.Internal,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # Attenuate to subset of tools
    child = issuer.attenuate().with_tools(["read_file", "query_db"]).delegate_to(child_kp, parent_kp)
    
    # Verify correct tools remain
    assert set(child.issuable_tools) == {"read_file", "query_db"}


def test_drop_tools():
    """Test drop_tools() removes specific tools."""
    parent_kp = Keypair.generate()
    child_kp = Keypair.generate()
    
    # Create issuer warrant with multiple tools
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db"],
        trust_ceiling=TrustLevel.Internal,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # Drop specific tools
    child = issuer.attenuate().drop_tools(["send_email"]).delegate_to(child_kp, parent_kp)
    
    # Verify tool was dropped
    assert set(child.issuable_tools) == {"read_file", "query_db"}


def test_tool_selection_combinations():
    """Test combining tool selection methods."""
    parent_kp = Keypair.generate()
    child_kp = Keypair.generate()
    
    # Create issuer warrant
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db", "delete_file"],
        trust_ceiling=TrustLevel.Internal,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # First narrow to subset, then drop one more
    child = (
        issuer.attenuate()
        .with_tools(["read_file", "send_email", "query_db"])
        .drop_tools(["send_email"])
        .delegate_to(child_kp, parent_kp)
    )
    
    # Verify final tool set
    assert set(child.issuable_tools) == {"read_file", "query_db"}


def test_with_tool_replaces_all():
    """Test that with_tool() replaces entire tool list."""
    parent_kp = Keypair.generate()
    child_kp = Keypair.generate()
    
    # Create issuer warrant
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db"],
        trust_ceiling=TrustLevel.Internal,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # Set single tool (should replace all)
    child = issuer.attenuate().with_tool("query_db").delegate_to(child_kp, parent_kp)
    
    # Verify only one tool
    assert child.issuable_tools == ["query_db"]
    assert len(child.issuable_tools) == 1
