"""
Tests for Principle of Least Authority (POLA) behavior.

POLA: When attenuating a warrant, the child starts with NO capabilities.
You must explicitly specify what you want.

This prevents accidentally granting more authority than intended.
"""

import pytest
from tenuo import (
    Warrant,
    SigningKey,
    Pattern,
    Exact,
    Range,
)
from tenuo.exceptions import ValidationError


class TestPOLADefaultBehavior:
    """Test that POLA defaults are enforced."""

    def test_attenuate_without_capabilities_fails(self):
        """Attenuating without specifying capabilities should fail."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={"read_file": {"path": Pattern("/data/*")}},
            ttl_seconds=3600
        )

        # Attempt to attenuate without specifying any capabilities
        builder = parent.attenuate_builder()
        builder.with_holder(worker_kp.public_key)

        # Should fail: "execution warrant must have at least one tool"
        with pytest.raises(ValidationError) as exc_info:
            builder.delegate_to(kp, kp)

        assert "at least one tool" in str(exc_info.value).lower()

    def test_inherit_all_allows_full_inheritance(self):
        """inherit_all() explicitly opts into full capability inheritance."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={
                "read_file": {"path": Pattern("/data/*")},
                "write_file": {"path": Pattern("/data/*")}
            },
            ttl_seconds=3600
        )

        # With inherit_all(), child gets all parent capabilities
        builder = parent.attenuate_builder()
        builder.inherit_all()
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)

        assert sorted(child.tools) == ["read_file", "write_file"]

    def test_explicit_capability_grants_only_that_tool(self):
        """with_capability() grants only the specified tool."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={
                "read_file": {"path": Pattern("/data/*")},
                "write_file": {"path": Pattern("/data/*")},
                "delete_file": {"path": Pattern("/data/*")}
            },
            ttl_seconds=3600
        )

        # Only grant read_file
        builder = parent.attenuate_builder()
        builder.with_capability("read_file", {"path": Exact("/data/report.txt")})
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)

        # Child should ONLY have read_file
        assert child.tools == ["read_file"]
        assert "write_file" not in child.tools
        assert "delete_file" not in child.tools


class TestPOLAWithInheritAll:
    """Test inherit_all() followed by narrowing."""

    def test_inherit_all_then_narrow_tools(self):
        """inherit_all() + with_tools() narrows to subset."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={
                "read_file": {},
                "write_file": {},
                "delete_file": {}
            },
            ttl_seconds=3600
        )

        # Inherit all, then narrow to just read_file
        builder = parent.attenuate_builder()
        builder.inherit_all()
        builder.with_tools(["read_file"])
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)

        assert child.tools == ["read_file"]

    def test_inherit_all_then_narrow_constraints(self):
        """inherit_all() + with_capability() narrows constraints."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={"query": {"max_rows": Range.max_value(1000)}},
            ttl_seconds=3600
        )

        # Inherit all, then narrow max_rows
        builder = parent.attenuate_builder()
        builder.inherit_all()
        builder.with_capability("query", {"max_rows": Range.max_value(100)})
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)

        assert child.tools == ["query"]
        # Constraint should be narrowed
        child_constraints = child.capabilities.get("query", {})
        assert child_constraints is not None


class TestPOLADelegateMethod:
    """Test that delegate() convenience method handles POLA correctly."""

    def test_delegate_inherits_all_internally(self):
        """delegate() should call inherit_all() internally."""
        from tenuo import set_signing_key_context

        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={
                "read_file": {"path": Pattern("/data/*")},
                "write_file": {"path": Pattern("/data/*")}
            },
            ttl_seconds=3600
        )

        # delegate() should work without explicit inherit_all()
        with set_signing_key_context(kp):
            child = parent.delegate(holder=worker_kp.public_key)

        # Child should have all parent tools
        assert sorted(child.tools) == ["read_file", "write_file"]

    def test_delegate_with_tools_narrows(self):
        """delegate(tools=[...]) narrows to specified tools."""
        from tenuo import set_signing_key_context

        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={
                "read_file": {},
                "write_file": {},
                "delete_file": {}
            },
            ttl_seconds=3600
        )

        with set_signing_key_context(kp):
            child = parent.delegate(
                holder=worker_kp.public_key,
                tools=["read_file"]
            )

        assert child.tools == ["read_file"]


class TestPOLASecurityGuarantees:
    """Test POLA security guarantees."""

    def test_forgetting_to_add_capability_is_safe(self):
        """Forgetting to add a capability = no access (safe failure)."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={
                "read_file": {},
                "delete_file": {}  # Dangerous capability
            },
            ttl_seconds=3600
        )

        # Developer only adds read_file, forgets about delete_file
        # With POLA, this is SAFE - delete_file is NOT granted
        builder = parent.attenuate_builder()
        builder.with_capability("read_file", {})
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)

        assert child.tools == ["read_file"]
        assert "delete_file" not in child.tools  # Safe!

    def test_inherit_all_is_explicit_opt_in(self):
        """inherit_all() is a deliberate choice, not accidental."""
        kp = SigningKey.generate()
        worker_kp = SigningKey.generate()

        parent = Warrant.issue(
            keypair=kp,
            capabilities={
                "read_file": {},
                "admin_action": {}  # Sensitive capability
            },
            ttl_seconds=3600
        )

        # Explicit inherit_all = deliberate choice to grant all
        builder = parent.attenuate_builder()
        builder.inherit_all()  # Developer explicitly chose this
        builder.with_holder(worker_kp.public_key)
        child = builder.delegate_to(kp, kp)

        # Both capabilities granted - this was intentional
        assert sorted(child.tools) == ["admin_action", "read_file"]
