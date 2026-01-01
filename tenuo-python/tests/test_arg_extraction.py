import pytest
from tenuo import (
    Warrant,
    SigningKey,
    guard,
    Exact,
)
from tenuo.constraints import Constraints

@pytest.fixture
def keypair():
    return SigningKey.generate()

@pytest.fixture
def warrant(keypair):
    return Warrant.mint(
        keypair=keypair,
        capabilities=Constraints.for_tool("test_tool", {"a": Exact("1"), "b": Exact("2")}),
        ttl_seconds=300
    )

def test_guard_arg_extraction_standard(warrant, keypair):
    """Test standard positional and keyword arguments."""

    @guard(warrant, tool="test_tool", keypair=keypair)
    def func(a, b="2"):
        return "success"

    # Matches constraints a="1", b="2"
    assert func("1") == "success"
    assert func("1", b="2") == "success"

    # Mismatch
    with pytest.raises(Exception):
        func("2") # a="2" != "1"

def test_guard_arg_extraction_var_args(keypair):
    """Test *args extraction."""

    # This test verifies that *args are correctly extracted and passed to authorization.
    # Since we constrain "a" but want to allow extra args, we use _allow_unknown=True
    # to opt out of zero-trust mode for this capability.
    #
    # Zero-Trust Design:
    # - If any constraint is defined, unknown fields are rejected by default
    # - Use _allow_unknown=True to explicitly allow unconstrained fields
    # - Use Any() to explicitly allow any value for a specific field

    w_list = Warrant.mint(
        keypair=keypair,
        capabilities=Constraints.for_tool("list_tool", {
            "a": Exact("1"),
            "_allow_unknown": True,  # Allow *args to pass through
        }),
        ttl_seconds=300
    )

    @guard(w_list, tool="list_tool", keypair=keypair)
    def func(a, *args):
        return "success"

    # Call with "1", "2", "3" -> a="1", args=("2", "3")
    # "args" is not constrained but _allow_unknown=True allows it
    assert func("1", "2", "3") == "success"

def test_guard_arg_extraction_keyword_only(warrant, keypair):
    """Test keyword-only arguments."""

    @guard(warrant, tool="test_tool", keypair=keypair)
    def func(a, *, b):
        return "success"

    assert func("1", b="2") == "success"

def test_guard_defaults_applied(warrant, keypair):
    """Test that defaults are applied and checked against constraints."""

    # Warrant requires b="2"
    @guard(warrant, tool="test_tool", keypair=keypair)
    def func(a, b="2"):
        return "success"

    # Calling func("1") implies b="2". Should pass.
    assert func("1") == "success"

    # If we change default to "3", it should fail
    @guard(warrant, tool="test_tool", keypair=keypair)
    def func_bad_default(a, b="3"):
        return "success"

    with pytest.raises(Exception):
        func_bad_default("1") # b="3" != "2"

def test_guard_binding_error(warrant, keypair):
    """Test that binding errors are raised."""

    @guard(warrant, tool="test_tool", keypair=keypair)
    def func(a, b):
        return "success"

    with pytest.raises(TypeError):
        func("1") # Missing b
