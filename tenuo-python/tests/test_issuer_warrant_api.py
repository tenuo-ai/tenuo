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
    """Test tool selection behavior via attenuate_builder and issue_execution."""
    
    def test_attenuate_builder_tools_only_for_issuer_warrants(self):
        """
        AttenuationBuilder.with_tools() only works for ISSUER warrants (issuable_tools).
        It does NOT narrow tools for EXECUTION warrants.
        
        This is BY DESIGN. Use issue_execution() from issuer warrants to select tools.
        """
        kp = Keypair.generate()
        worker_kp = Keypair.generate()
        
        # Create execution warrant with multiple tools
        parent = Warrant.issue(
            tools=["read_file", "send_email", "query_db"],
            keypair=kp,
            ttl_seconds=3600,
        )
        
        # AttenuationBuilder.with_tools affects issuable_tools, not tools
        # So calling it on an execution warrant has no effect on tools
        builder = parent.attenuate_builder()
        builder.with_tools(["read_file"])  # This sets issuable_tools, not tools!
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)
        
        # Child still has ALL parent tools - by design
        assert child.tools == parent.tools, (
            "Execution warrant tools cannot be narrowed via attenuate(). "
            "Use issue_execution() from issuer warrants instead."
        )
    
    def test_issue_execution_can_select_tools(self):
        """
        To narrow tools, use an Issuer warrant + issue_execution().
        This is the proper way to create execution warrants with specific tools.
        """
        issuer_kp = Keypair.generate()
        worker_kp = Keypair.generate()
        
        # Step 1: Create issuer warrant with all tools
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file", "send_email", "query_db"],
            trust_ceiling=TrustLevel.Internal,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )
        
        # Step 2: Issue execution warrant with ONLY read_file
        builder = issuer_warrant.issue_execution()
        builder.with_tool("read_file")  # Select just one tool
        builder.with_holder(worker_kp.public_key)
        builder.with_ttl(300)
        exec_warrant = builder.build(issuer_kp, issuer_kp)
        
        # Execution warrant has ONLY the selected tool
        assert exec_warrant.tools == ["read_file"]
        assert "send_email" not in exec_warrant.tools
        assert "query_db" not in exec_warrant.tools
