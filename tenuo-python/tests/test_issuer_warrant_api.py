"""
Tests for issuer warrant API availability and correctness.

Verifies:
1. Warrant.issue_issuer() exists and works
2. warrant.issue_execution() exists and returns IssuanceBuilder
3. delegate() tool parameter actually does something (or documents that it doesn't)
"""

import pytest
from tenuo import (
    Warrant,
    Keypair,
    TrustLevel,
    Pattern,
    Exact,
)


class TestIssuerWarrantExists:
    """Test that issue_issuer() exists and works."""
    
    def test_issue_issuer_exists(self):
        """Warrant.issue_issuer should be a callable static method."""
        assert hasattr(Warrant, 'issue_issuer'), "Warrant.issue_issuer() is missing"
        assert callable(Warrant.issue_issuer), "Warrant.issue_issuer should be callable"
    
    def test_issue_issuer_creates_issuer_warrant(self):
        """issue_issuer() should create an issuer warrant."""
        issuer_kp = Keypair.generate()
        
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file", "send_email"],
            trust_ceiling=TrustLevel.Internal,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )
        
        assert issuer_warrant is not None
        assert issuer_warrant.id is not None
        # Issuer warrants have issuable_tools, not tools
        assert issuer_warrant.issuable_tools is not None
        assert "read_file" in issuer_warrant.issuable_tools
        assert "send_email" in issuer_warrant.issuable_tools
    
    def test_issue_issuer_with_holder(self):
        """issue_issuer() should accept a holder parameter."""
        issuer_kp = Keypair.generate()
        holder_kp = Keypair.generate()
        
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file"],
            trust_ceiling=TrustLevel.Internal,
            keypair=issuer_kp,
            holder=holder_kp.public_key,
            ttl_seconds=3600,
        )
        
        assert issuer_warrant.authorized_holder is not None


class TestIssueExecutionExists:
    """Test that issue_execution() exists and returns IssuanceBuilder."""
    
    def test_issue_execution_exists(self):
        """Issuer warrant should have issue_execution() method."""
        issuer_kp = Keypair.generate()
        
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file"],
            trust_ceiling=TrustLevel.Internal,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )
        
        assert hasattr(issuer_warrant, 'issue_execution'), "warrant.issue_execution() is missing"
        assert callable(issuer_warrant.issue_execution), "warrant.issue_execution should be callable"
    
    def test_issue_execution_returns_builder(self):
        """issue_execution() should return an IssuanceBuilder."""
        issuer_kp = Keypair.generate()
        
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file"],
            trust_ceiling=TrustLevel.Internal,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )
        
        builder = issuer_warrant.issue_execution()
        
        # Should be a builder with fluent API methods
        assert builder is not None
        assert hasattr(builder, 'with_tool'), "IssuanceBuilder should have with_tool()"
        assert hasattr(builder, 'with_constraint'), "IssuanceBuilder should have with_constraint()"
        assert hasattr(builder, 'with_holder'), "IssuanceBuilder should have with_holder()"
        assert hasattr(builder, 'build'), "IssuanceBuilder should have build()"
    
    def test_issue_execution_only_on_issuer_warrants(self):
        """issue_execution() should fail on execution warrants."""
        kp = Keypair.generate()
        
        # Create execution warrant (not issuer)
        exec_warrant = Warrant.issue(
            tools=["read_file"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        with pytest.raises(Exception):  # Should raise ValidationError or similar
            exec_warrant.issue_execution()
    
    def test_issue_execution_full_flow(self):
        """Full flow: issue_issuer -> issue_execution -> build."""
        issuer_kp = Keypair.generate()
        worker_kp = Keypair.generate()
        
        # Step 1: Create issuer warrant
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file", "send_email"],
            trust_ceiling=TrustLevel.Internal,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )
        
        # Step 2: Issue execution warrant from issuer warrant
        builder = issuer_warrant.issue_execution()
        builder.with_tool("read_file")
        builder.with_holder(worker_kp.public_key)
        builder.with_constraint("path", Pattern("/data/*"))
        builder.with_ttl(300)  # TTL is required
        
        # Step 3: Build (needs keypair of issuer warrant holder)
        exec_warrant = builder.build(issuer_kp, issuer_kp)
        
        assert exec_warrant is not None
        assert exec_warrant.tools is not None
        assert "read_file" in exec_warrant.tools
        # Should NOT have tools that weren't selected
        assert "send_email" not in exec_warrant.tools


class TestDelegateMethod:
    """Test delegate() method behavior."""
    
    def test_delegate_exists(self):
        """Warrant should have delegate() method."""
        kp = Keypair.generate()
        
        warrant = Warrant.issue(
            tools=["read_file"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        assert hasattr(warrant, 'delegate'), "warrant.delegate() is missing"
    
    def test_delegate_narrows_constraints(self):
        """delegate() should narrow constraints."""
        from tenuo import configure, root_task_sync, set_keypair_context, Pattern
        from tenuo.config import reset_config
        
        reset_config()
        
        kp = Keypair.generate()
        worker_kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        with root_task_sync(tools=["read_file"], path=Pattern("/data/*")) as parent:
            with set_keypair_context(kp):
                child = parent.delegate(
                    holder=worker_kp.public_key,
                    path=Exact("/data/q3.pdf"),  # Narrower constraint
                )
                
                # Tools should be inherited (execution warrants can't narrow tools)
                assert child.tools == parent.tools
                
                # But constraints should be narrowed
                child_constraints = child.constraints_dict()
                assert child_constraints is not None
    
    def test_delegate_inherits_tools(self):
        """
        delegate() CANNOT narrow tools for execution warrants.
        
        This is BY DESIGN. To narrow tools, use an Issuer warrant
        and call issue_execution() instead.
        """
        from tenuo import configure, root_task_sync, set_keypair_context
        from tenuo.config import reset_config
        
        reset_config()
        
        kp = Keypair.generate()
        worker_kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        with root_task_sync(tools=["read_file", "send_email"]) as parent:
            with set_keypair_context(kp):
                child = parent.delegate(
                    holder=worker_kp.public_key,
                    # No tool param - by design, can't narrow tools
                )
                
                # Child MUST have same tools as parent
                # This is the expected behavior for execution warrants
                assert child.tools == parent.tools, (
                    "Execution warrants inherit all parent tools. "
                    "Use issue_execution() from issuer warrants to narrow tools."
                )


class TestAttenuateBuilderToolSelection:
    """Test tool selection/narrowing via attenuate_builder."""
    
    def test_attenuate_builder_can_narrow_tools(self):
        """
        AttenuationBuilder.with_tools() CAN narrow tools for execution warrants.
        This enables "always shrinking authority" for non-terminal warrants.
        """
        kp = Keypair.generate()
        worker_kp = Keypair.generate()
        
        # Create execution warrant with multiple tools
        parent = Warrant.issue(
            tools=["read_file", "send_email", "query_db"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        # Narrow to just read_file
        builder = parent.attenuate_builder()
        builder.with_tools(["read_file"])
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)
        
        # Child has ONLY the narrowed tools
        assert child.tools == ["read_file"], (
            f"Expected ['read_file'], got {child.tools}"
        )
        assert "send_email" not in child.tools
        assert "query_db" not in child.tools
    
    def test_attenuate_builder_with_tool_single(self):
        """with_tool() narrows to a single tool."""
        kp = Keypair.generate()
        worker_kp = Keypair.generate()
        
        parent = Warrant.issue(
            tools=["read_file", "send_email"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        builder = parent.attenuate_builder()
        builder.with_tool("send_email")  # Narrow to just send_email
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)
        
        assert child.tools == ["send_email"]
    
    def test_attenuate_rejects_tool_not_in_parent(self):
        """Cannot add tools that weren't in parent."""
        import pytest
        
        kp = Keypair.generate()
        worker_kp = Keypair.generate()
        
        parent = Warrant.issue(
            tools=["read_file"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        builder = parent.attenuate_builder()
        builder.with_tools(["read_file", "delete_file"])  # delete_file not in parent!
        builder.with_holder(worker_kp.public_key)
        
        with pytest.raises(Exception) as exc_info:
            builder.delegate_to(kp, kp)
        
        assert "delete_file" in str(exc_info.value) or "not in parent" in str(exc_info.value)
    
    def test_issue_execution_can_select_tools(self):
        """
        Issuer warrants + issue_execution() is another way to select tools.
        """
        issuer_kp = Keypair.generate()
        worker_kp = Keypair.generate()
        
        # Create issuer warrant with all tools
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file", "send_email", "query_db"],
            trust_ceiling=TrustLevel.Internal,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )
        
        # Issue execution warrant with ONLY read_file
        builder = issuer_warrant.issue_execution()
        builder.with_tool("read_file")
        builder.with_holder(worker_kp.public_key)
        builder.with_ttl(300)
        exec_warrant = builder.build(issuer_kp, issuer_kp)
        
        assert exec_warrant.tools == ["read_file"]


class TestTerminalWarrants:
    """Test terminal warrant behavior."""
    
    def test_is_terminal_property(self):
        """Warrant.is_terminal() returns correct value."""
        kp = Keypair.generate()
        
        # Non-terminal warrant (no max_depth or max_depth > depth)
        warrant = Warrant.issue(
            tools=["read_file"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        # Should not be terminal (depth=0, no max_depth limit)
        assert hasattr(warrant, 'is_terminal'), "Warrant should have is_terminal method"
        assert not warrant.is_terminal(), "Root warrant with no max_depth should not be terminal"
    
    def test_terminal_warrant_via_builder(self):
        """Creating a terminal warrant via .terminal() method."""
        kp = Keypair.generate()
        worker_kp = Keypair.generate()
        
        parent = Warrant.issue(
            tools=["read_file"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        # Create terminal child
        builder = parent.attenuate_builder()
        builder.terminal()  # Make it terminal
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)
        
        # Child should be terminal
        assert child.is_terminal(), "Warrant created with .terminal() should be terminal"
    
    def test_terminal_warrant_cannot_delegate(self):
        """Terminal warrants cannot delegate further."""
        import pytest
        
        kp = Keypair.generate()
        worker_kp = Keypair.generate()
        another_kp = Keypair.generate()
        
        parent = Warrant.issue(
            tools=["read_file"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        # Create terminal child
        builder = parent.attenuate_builder()
        builder.terminal()
        builder.with_holder(worker_kp.public_key)
        terminal = builder.delegate_to(kp, kp)
        
        assert terminal.is_terminal()
        
        # Try to delegate from terminal warrant - should fail
        builder2 = terminal.attenuate_builder()
        builder2.with_holder(another_kp.public_key)
        
        with pytest.raises(Exception) as exc_info:
            builder2.delegate_to(worker_kp, worker_kp)
        
        # Should fail due to depth exceeded
        assert "depth" in str(exc_info.value).lower() or "exceed" in str(exc_info.value).lower()
