"""
Tests for issuer warrant API availability and correctness.

Verifies:
1. Warrant.issue_issuer() exists and works
2. warrant.issue_execution() exists and returns IssuanceBuilder
3. grant() tool parameter actually does something (or documents that it doesn't)
"""

import pytest
from tenuo import (
    Warrant,
    SigningKey,
    Pattern,
    Exact,
    Capability,
)
from tenuo.constraints import Constraints
from tenuo_core import Clearance


class TestIssuerWarrantExists:
    """Test that issue_issuer() exists and works."""

    def test_issue_issuer_exists(self):
        """Warrant.issue_issuer should be a callable static method."""
        assert hasattr(Warrant, 'issue_issuer'), "Warrant.issue_issuer() is missing"
        assert callable(Warrant.issue_issuer), "Warrant.issue_issuer should be callable"

    def test_issue_issuer_creates_issuer_warrant(self):
        """issue_issuer() should create an issuer warrant."""
        issuer_kp = SigningKey.generate()

        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file", "send_email"],
            clearance=Clearance.INTERNAL,
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
        issuer_kp = SigningKey.generate()
        holder_kp = SigningKey.generate()

        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file"],
            clearance=Clearance.INTERNAL,
            keypair=issuer_kp,
            holder=holder_kp.public_key,
            ttl_seconds=3600,
        )

        assert issuer_warrant.authorized_holder is not None


class TestIssueExecutionExists:
    """Test that issue_execution() exists and returns IssuanceBuilder."""

    def test_issue_execution_exists(self):
        """Issuer warrant should have issue_execution() method."""
        issuer_kp = SigningKey.generate()

        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file"],
            clearance=Clearance.INTERNAL,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )

        assert hasattr(issuer_warrant, 'issue_execution'), "warrant.issue_execution() is missing"
        assert callable(issuer_warrant.issue_execution), "warrant.issue_execution should be callable"

    def test_issue_execution_returns_builder(self):
        """issue_execution() should return an IssuanceBuilder."""
        issuer_kp = SigningKey.generate()

        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file"],
            clearance=Clearance.INTERNAL,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )

        builder = issuer_warrant.issue_execution()

        # Should be a builder with fluent API methods
        assert builder is not None
        assert hasattr(builder, 'tool'), "IssuanceBuilder should have tool()"
        assert hasattr(builder, 'capability'), "IssuanceBuilder should have capability()"
        assert hasattr(builder, 'holder'), "IssuanceBuilder should have holder()"
        assert hasattr(builder, 'ttl'), "IssuanceBuilder should have ttl()"
        assert hasattr(builder, 'build'), "IssuanceBuilder should have build()"

    def test_issue_execution_only_on_issuer_warrants(self):
        """issue_execution() should fail on execution warrants."""
        kp = SigningKey.generate()

        # Create execution warrant (not issuer)
        exec_warrant = Warrant.mint(
            keypair=kp,
            capabilities=Constraints.for_tool("read_file", {}),
            ttl_seconds=3600,
        )

        with pytest.raises(Exception):  # Should raise ValidationError or similar
            exec_warrant.issue_execution()

    def test_issue_execution_full_flow(self):
        """Full flow: issue_issuer -> issue_execution -> build."""
        issuer_kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        # Step 1: Create issuer warrant
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file", "send_email"],
            clearance=Clearance.INTERNAL,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )

        # Step 2: Issue execution warrant from issuer warrant
        builder = issuer_warrant.issue_execution()
        builder.tool("read_file")
        builder.holder(worker_kp.public_key)
        builder.capability("read_file", {"path": Pattern("/data/*")})
        builder.ttl(300)  # TTL is required

        # Step 3: Build (needs keypair of issuer warrant holder)
        exec_warrant = builder.build(issuer_kp)

        assert exec_warrant is not None
        assert exec_warrant.tools is not None
        assert "read_file" in exec_warrant.tools
        # Should NOT have tools that weren't selected
        assert "send_email" not in exec_warrant.tools


class TestGrantMethod:
    """Test grant() method behavior."""

    def test_grant_exists(self):
        """Warrant should have grant() method."""
        kp = SigningKey.generate()

        warrant = Warrant.mint(
            keypair=kp,
            capabilities=Constraints.for_tool("read_file", {}),
            ttl_seconds=3600,
        )

        assert hasattr(warrant, 'grant'), "warrant.grant() is missing"

    def test_grant_narrows_constraints(self):
        """grant() should narrow constraints."""
        from tenuo import configure, mint_sync, Pattern
        from tenuo.config import reset_config

        reset_config()

        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)

        with mint_sync(Capability("read_file", path=Pattern("/data/*"))) as parent:
            child = parent.grant(
                to=worker_kp.public_key,
                allow=["read_file"],
                ttl=300,
                key=kp,
                path=Exact("/data/q3.pdf"),  # Narrower constraint
            )

            # Tools should be as specified in allow
            assert "read_file" in child.tools

            # But constraints should be narrowed
            child_constraints = child.capabilities.get("read_file")
            assert child_constraints is not None

    def test_grant_inherits_tools(self):
        """
        grant() CANNOT narrow tools for execution warrants.

        This is BY DESIGN. To narrow tools, use an Issuer warrant
        and call issue_execution() instead.
        """
        from tenuo import configure, mint_sync
        from tenuo.config import reset_config

        reset_config()

        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)

        with mint_sync(Capability("read_file"), Capability("send_email")) as parent:
            child = parent.grant(
                to=worker_kp.public_key,
                allow=["read_file", "send_email"],  # Inherit all tools
                ttl=300,
                key=kp,
            )

            # Child should have the tools we specified in allow
            assert sorted(child.tools) == sorted(["read_file", "send_email"]), (
                "grant() creates child with specified tools"
            )


class TestGrantBuilderToolSelection:
    """Test tool selection/narrowing via grant_builder."""

    def test_grant_builder_can_narrow_tools(self):
        """
        GrantBuilder.tools() CAN narrow tools for execution warrants.
        This enables "always shrinking authority" for non-terminal warrants.
        """
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        # Create execution warrant with multiple tools
        parent = Warrant.mint(
            keypair=kp,
            capabilities={t: {} for t in ["read_file", "send_email", "query_db"]},
            ttl_seconds=3600,
        )

        # POLA: inherit_all first, then narrow
        builder = parent.grant_builder()
        builder.inherit_all()  # Start with all parent capabilities
        builder.tools(["read_file"])  # Then narrow
        builder.holder(worker_kp.public_key)
        child = builder.grant(kp)

        # Child has ONLY the narrowed tools
        assert child.tools == ["read_file"], (
            f"Expected ['read_file'], got {child.tools}"
        )
        assert "send_email" not in child.tools
        assert "query_db" not in child.tools

    def test_grant_builder_tool_single(self):
        """tool() narrows to a single tool."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.mint(
            keypair=kp,
            capabilities={t: {} for t in ["read_file", "send_email"]},
            ttl_seconds=3600,
        )

        # POLA: inherit_all first, then narrow
        builder = parent.grant_builder()
        builder.inherit_all()
        builder.tool("send_email")  # Narrow to just send_email
        builder.holder(worker_kp.public_key)
        child = builder.grant(kp)

        assert child.tools == ["send_email"]

    def test_grant_builder_rejects_tool_not_in_parent(self):
        """Cannot add tools that weren't in parent."""


        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.mint(
            keypair=kp,
            capabilities=Constraints.for_tool("read_file", {}),
            ttl_seconds=3600,
        )

        # POLA: inherit_all first, then narrow
        builder = parent.grant_builder()
        builder.inherit_all()
        builder.tools(["read_file", "delete_file"])  # delete_file not in parent!
        builder.holder(worker_kp.public_key)

        # Should not raise, but silently ignore 'delete_file'
        child = builder.grant(kp)

        assert "read_file" in child.tools
        assert "delete_file" not in child.tools

    def test_issue_execution_can_select_tools(self):
        """
        Issuer warrants + issue_execution() is another way to select tools.
        """
        issuer_kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        # Create issuer warrant with all tools
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["read_file", "send_email", "query_db"],
            clearance=Clearance.INTERNAL,
            keypair=issuer_kp,
            ttl_seconds=3600,
        )

        # Issue execution warrant with ONLY read_file
        builder = issuer_warrant.issue_execution()
        builder.tool("read_file")
        builder.holder(worker_kp.public_key)
        builder.ttl(300)
        exec_warrant = builder.build(issuer_kp)

        assert exec_warrant.tools == ["read_file"]


class TestTerminalWarrants:
    """Test terminal warrant behavior."""

    def test_is_terminal_property(self):
        """Warrant.is_terminal() returns correct value."""
        kp = SigningKey.generate()

        # Non-terminal warrant (no max_depth or max_depth > depth)
        warrant = Warrant.mint(
            keypair=kp,
            capabilities=Constraints.for_tool("read_file", {}),
            ttl_seconds=3600,
        )

        # Should not be terminal (depth=0, no max_depth limit)
        assert hasattr(warrant, 'is_terminal'), "Warrant should have is_terminal method"
        assert not warrant.is_terminal(), "Root warrant with no max_depth should not be terminal"

    def test_terminal_warrant_via_builder(self):
        """Creating a terminal warrant via .terminal() method."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.mint(
            keypair=kp,
            capabilities=Constraints.for_tool("read_file", {}),
            ttl_seconds=3600,
        )

        # POLA: inherit_all, then make terminal
        builder = parent.grant_builder()
        builder.inherit_all()
        builder.terminal()  # Make it terminal
        builder.holder(worker_kp.public_key)
        child = builder.grant(kp)

        # Child should be terminal
        assert child.is_terminal(), "Warrant created with .terminal() should be terminal"

    def test_terminal_warrant_cannot_grant(self):
        """Terminal warrants cannot grant further."""
        import pytest

        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()
        another_kp = SigningKey.generate()

        parent = Warrant.mint(
            keypair=kp,
            capabilities=Constraints.for_tool("read_file", {}),
            ttl_seconds=3600,
        )

        # POLA: inherit_all, then make terminal
        builder = parent.grant_builder()
        builder.inherit_all()
        builder.terminal()
        builder.holder(worker_kp.public_key)
        terminal = builder.grant(kp)

        assert terminal.is_terminal()

        # Try to delegate from terminal warrant - should fail
        builder2 = terminal.grant_builder()
        builder2.inherit_all()
        builder2.holder(another_kp.public_key)

        with pytest.raises(Exception) as exc_info:
            builder2.grant(worker_kp)

        # Should fail due to depth exceeded
        assert "depth" in str(exc_info.value).lower() or "exceed" in str(exc_info.value).lower()
