"""
Tests for @lockdown decorator and ContextVar functionality.
"""

import pytest
from tenuo import (
    Keypair, Warrant, Pattern, Range, Exact,
    lockdown, set_warrant_context, get_warrant_context,
    AuthorizationError
)


class TestLockdownDecorator:
    """Tests for @lockdown decorator."""
    
    def test_lockdown_with_explicit_warrant(self):
        """Test @lockdown with explicit warrant."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="upgrade_cluster",
            constraints={
                "cluster": Pattern("staging-*"),
                "budget": Range.max_value(10000.0)
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="upgrade_cluster")
        def upgrade_cluster(cluster: str, budget: float):
            return f"Upgrading {cluster} with ${budget}"
        
        # Should succeed with authorized args
        result = upgrade_cluster("staging-web", 5000.0)
        assert "staging-web" in result
        
        # Should raise AuthorizationError with unauthorized args
        with pytest.raises(AuthorizationError):
            upgrade_cluster("production-web", 5000.0)
        
        with pytest.raises(AuthorizationError):
            upgrade_cluster("staging-web", 15000.0)
    
    def test_lockdown_with_context(self):
        """Test @lockdown with ContextVar (no explicit warrant)."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="upgrade_cluster",
            constraints={
                "cluster": Pattern("staging-*"),
                "budget": Range.max_value(10000.0)
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(tool="upgrade_cluster")
        def upgrade_cluster(cluster: str, budget: float):
            return f"Upgrading {cluster} with ${budget}"
        
        # Should succeed with warrant in context
        with set_warrant_context(warrant):
            result = upgrade_cluster("staging-web", 5000.0)
            assert "staging-web" in result
        
        # Should raise AuthorizationError without warrant in context
        with pytest.raises(AuthorizationError):
            upgrade_cluster("staging-web", 5000.0)
    
    def test_lockdown_with_extract_args(self):
        """Test @lockdown with custom extract_args function."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="read_file",
            constraints={"file_path": Pattern("/tmp/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        def extract_file_path(file_path: str, **kwargs):
            return {"file_path": file_path}
        
        @lockdown(warrant, tool="read_file", extract_args=extract_file_path)
        def read_file(file_path: str):
            return f"Reading {file_path}"
        
        # Should succeed
        result = read_file("/tmp/test.txt")
        assert "/tmp/test.txt" in result
        
        # Should fail
        with pytest.raises(AuthorizationError):
            read_file("/etc/passwd")


class TestPositionalArguments:
    """
    Tests for positional argument handling in @lockdown decorator.
    
    This is critical for security - positional args must be correctly mapped
    to parameter names and checked against warrant constraints.
    """
    
    def test_positional_args_authorized(self):
        """Positional args should be authorized when valid."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="read_file",
            constraints={"path": Pattern("/tmp/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="read_file")
        def read_file(path: str):
            return f"Reading {path}"
        
        # Positional arg should work
        result = read_file("/tmp/safe.txt")
        assert "/tmp/safe.txt" in result
    
    def test_positional_args_unauthorized(self):
        """Positional args should be REJECTED when unauthorized."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="read_file",
            constraints={"path": Pattern("/tmp/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="read_file")
        def read_file(path: str):
            return f"Reading {path}"
        
        # CRITICAL: Unauthorized positional arg MUST be rejected
        with pytest.raises(AuthorizationError):
            read_file("/etc/passwd")  # positional - should FAIL
    
    def test_mixed_positional_and_keyword(self):
        """Mixed positional and keyword args should all be checked."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="copy_file",
            constraints={
                "src": Pattern("/tmp/*"),
                "dst": Pattern("/backup/*")
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="copy_file")
        def copy_file(src: str, dst: str):
            return f"Copying {src} to {dst}"
        
        # Both positional - should work
        result = copy_file("/tmp/a.txt", "/backup/a.txt")
        assert "Copying" in result
        
        # Mixed: positional src, keyword dst - should work
        result = copy_file("/tmp/b.txt", dst="/backup/b.txt")
        assert "Copying" in result
        
        # Mixed: unauthorized positional src
        with pytest.raises(AuthorizationError):
            copy_file("/etc/passwd", dst="/backup/stolen.txt")
        
        # Mixed: authorized positional src, unauthorized keyword dst
        with pytest.raises(AuthorizationError):
            copy_file("/tmp/c.txt", dst="/etc/shadow")
    
    def test_positional_with_multiple_params(self):
        """Multiple positional args must map to correct parameters."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="transfer",
            constraints={
                "amount": Range.max_value(1000.0),
                "account": Pattern("savings-*")
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="transfer")
        def transfer(amount: float, account: str):
            return f"Transferring ${amount} to {account}"
        
        # Positional args in correct order - should work
        result = transfer(500.0, "savings-001")
        assert "500" in result
        
        # First positional exceeds limit
        with pytest.raises(AuthorizationError):
            transfer(5000.0, "savings-001")
        
        # Second positional unauthorized pattern
        with pytest.raises(AuthorizationError):
            transfer(500.0, "checking-001")
    
    def test_keyword_only_params_not_bypassable(self):
        """Keyword-only params cannot be bypassed with positional args."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="delete",
            constraints={"path": Pattern("/tmp/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="delete")
        def delete(*, path: str):  # Keyword-only
            return f"Deleting {path}"
        
        # Must use keyword
        result = delete(path="/tmp/safe.txt")
        assert "/tmp/safe.txt" in result
        
        # Unauthorized keyword
        with pytest.raises(AuthorizationError):
            delete(path="/etc/passwd")
    
    def test_explicit_override_of_default_checked(self):
        """Explicitly overriding a default value must be checked."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="read_file",
            constraints={
                "path": Pattern("/tmp/*"),
                "encoding": Exact("utf-8")  # Only utf-8 allowed
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="read_file")
        def read_file(path: str, encoding: str = "utf-8"):
            return f"Reading {path} as {encoding}"
        
        # Overriding with unauthorized encoding via POSITIONAL - should fail
        with pytest.raises(AuthorizationError):
            read_file("/tmp/test.txt", "latin-1")
        
        # Overriding with unauthorized encoding via KEYWORD - should fail
        with pytest.raises(AuthorizationError):
            read_file("/tmp/test.txt", encoding="latin-1")
        
        # Explicitly passing authorized value - should work
        result = read_file("/tmp/test.txt", "utf-8")
        assert "utf-8" in result
    
    def test_default_values_checked(self):
        """
        Default parameter values MUST be checked against constraints.
        
        This prevents a security bypass where a function has a dangerous
        default value (e.g., sudo=True) that would violate constraints.
        """
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="dangerous_op",
            constraints={
                "path": Pattern("/tmp/*"),
                "sudo": Exact(False)  # sudo=False REQUIRED
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="dangerous_op")
        def dangerous_op(path: str, sudo: bool = True):  # DEFAULT IS DANGEROUS!
            return f"Operating on {path} with sudo={sudo}"
        
        # Default sudo=True violates constraint - MUST be rejected
        with pytest.raises(AuthorizationError):
            dangerous_op("/tmp/test.txt")  # Uses default sudo=True
        
        # Explicitly passing sudo=False - should work
        result = dangerous_op("/tmp/test.txt", sudo=False)
        assert "sudo=False" in result
    
    def test_safe_default_values_allowed(self):
        """Safe default values that match constraints should be allowed."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="read_file",
            constraints={
                "path": Pattern("/tmp/*"),
                "encoding": Exact("utf-8")
            },
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(warrant, tool="read_file")
        def read_file(path: str, encoding: str = "utf-8"):  # Safe default
            return f"Reading {path} as {encoding}"
        
        # Using safe default - should work
        result = read_file("/tmp/test.txt")
        assert "utf-8" in result


class TestMethodDecorator:
    """Tests for @lockdown on class methods."""
    
    def test_method_positional_args(self):
        """Class method positional args should be correctly mapped (self excluded)."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="process",
            constraints={"data": Pattern("safe-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        class Processor:
            @lockdown(warrant, tool="process")
            def process(self, data: str):
                return f"Processing {data}"
        
        proc = Processor()
        
        # Positional arg (self is bound, so "safe-data" is first real arg)
        result = proc.process("safe-data")
        assert "safe-data" in result
        
        # Unauthorized positional
        with pytest.raises(AuthorizationError):
            proc.process("unsafe-data")


class TestContextVar:
    """Tests for ContextVar warrant management."""
    
    def test_set_warrant_context(self):
        """Test setting warrant in context."""
        keypair = Keypair.generate()
        warrant = Warrant.create(
            tool="test",
            constraints={},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Initially no warrant
        assert get_warrant_context() is None
        
        # Set warrant in context
        with set_warrant_context(warrant):
            context_warrant = get_warrant_context()
            assert context_warrant is not None
            assert context_warrant.tool == warrant.tool
        
        # Context should be cleared after exit
        assert get_warrant_context() is None
    
    def test_nested_contexts(self):
        """Test nested warrant contexts."""
        keypair = Keypair.generate()
        warrant1 = Warrant.create(
            tool="test1",
            constraints={"cluster": Pattern("staging-*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        warrant2 = Warrant.create(
            tool="test2",
            constraints={"cluster": Exact("staging-web")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        with set_warrant_context(warrant1):
            assert get_warrant_context().tool == "test1"
            
            with set_warrant_context(warrant2):
                assert get_warrant_context().tool == "test2"
            
            # Should revert to outer context
            assert get_warrant_context().tool == "test1"

