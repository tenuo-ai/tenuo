"""Test tool selection methods in GrantBuilder."""
from tenuo import SigningKey, Warrant
from tenuo_core import Clearance


def test_with_issuable_tool_single():
    """Test issuable_tool() sets a single tool for issuer warrants."""
    parent_kp = SigningKey.generate()
    
    # Create issuer warrant with multiple tools
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db"],
        clearance=Clearance.INTERNAL,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # Attenuate to single tool using with_issuable_tool (for issuer warrants)
    child = issuer.attenuate().issuable_tool("read_file").grant(parent_kp)
    
    # Verify only one tool remains
    assert child.issuable_tools == ["read_file"]


def test_with_issuable_tools_multiple():
    """Test issuable_tools() sets multiple tools for issuer warrants."""
    parent_kp = SigningKey.generate()
    
    # Create issuer warrant with multiple tools
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db", "delete_file"],
        clearance=Clearance.INTERNAL,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # Attenuate to subset of tools using with_issuable_tools (for issuer warrants)
    child = issuer.attenuate().issuable_tools(["read_file", "query_db"]).grant(parent_kp)
    
    # Verify correct tools remain
    assert set(child.issuable_tools) == {"read_file", "query_db"}


def test_drop_tools():
    """Test drop_tools() removes specific tools."""
    parent_kp = SigningKey.generate()
    
    # Create issuer warrant with multiple tools
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db"],
        clearance=Clearance.INTERNAL,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # Drop specific tools
    child = issuer.attenuate().drop_tools(["send_email"]).grant(parent_kp)
    
    # Verify tool was dropped
    assert set(child.issuable_tools) == {"read_file", "query_db"}


def test_issuable_tool_selection_combinations():
    """Test combining tool selection methods for issuer warrants."""
    parent_kp = SigningKey.generate()
    
    # Create issuer warrant
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db", "delete_file"],
        clearance=Clearance.INTERNAL,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # First narrow to subset, then drop one more (using issuable_tools methods)
    child = (
        issuer.attenuate()
        .issuable_tools(["read_file", "send_email", "query_db"])
        .drop_tools(["send_email"])
        .grant(parent_kp)
    )
    
    # Verify final tool set
    assert set(child.issuable_tools) == {"read_file", "query_db"}


def test_with_issuable_tool_replaces_all():
    """Test that issuable_tool() replaces entire tool list for issuer warrants."""
    parent_kp = SigningKey.generate()
    
    # Create issuer warrant
    issuer = Warrant.issue_issuer(
        issuable_tools=["read_file", "send_email", "query_db"],
        clearance=Clearance.INTERNAL,
        keypair=parent_kp,
        ttl_seconds=3600,
    )
    
    # Set single tool using with_issuable_tool (should replace all)
    child = issuer.attenuate().issuable_tool("query_db").grant(parent_kp)
    
    # Verify only one tool
    assert child.issuable_tools == ["query_db"]
    assert len(child.issuable_tools) == 1
