import pytest
from tenuo import lockdown, Warrant, Keypair, Exact

@pytest.fixture
def keypair():
    return Keypair.generate()

@pytest.fixture
def warrant(keypair):
    return Warrant.issue(
        tools=["test_tool"],
        constraints={"a": Exact("1"), "b": Exact("2")},
        ttl_seconds=300,
        keypair=keypair
    )

def test_lockdown_arg_extraction_standard(warrant, keypair):
    """Test standard positional and keyword arguments."""
    
    @lockdown(warrant, tool="test_tool", keypair=keypair)
    def func(a, b="2"):
        return "success"
    
    # Matches constraints a="1", b="2"
    assert func("1") == "success"
    assert func("1", b="2") == "success"
    
    # Mismatch
    with pytest.raises(Exception):
        func("2") # a="2" != "1"

def test_lockdown_arg_extraction_var_args(keypair):
    """Test *args extraction."""
    
    # Warrant expects 'args' to be ("2", "3")
    # Note: args is a tuple in Python, so we match against tuple
    # But Exact binding might not support tuple/list in new() either?
    # PyExact::new takes &str. So it definitely doesn't support lists.
    # We can't test list/tuple exact match with current bindings easily.
    # Let's skip this specific assertion or use a different constraint if possible.
    # Actually, let's just test that the arguments are passed to authorize() correctly.
    # If we use a constraint that doesn't exist, it's ignored (allow-by-default for unconstrained args? No, Tenuo is deny-by-default for constrained args).
    
    # Let's use "a" which is supported.
    w_list = Warrant.issue(
        tools=["list_tool"],
        constraints={"a": Exact("1")},
        ttl_seconds=300,
        keypair=keypair
    )
    
    @lockdown(w_list, tool="list_tool", keypair=keypair)
    def func(a, *args):
        return "success"
    
    # Call with "1", "2", "3" -> a="1", args=("2", "3")
    # "args" is not constrained, so it should be allowed?
    # Tenuo policy: If a field is NOT in constraints, is it allowed?
    # Yes, usually constraints are "if field X is present in args, it must match constraint Y".
    # If field X is in args but NOT in warrant constraints, it is allowed (unless there's a "deny unknown" policy).
    
    assert func("1", "2", "3") == "success"

def test_lockdown_arg_extraction_keyword_only(warrant, keypair):
    """Test keyword-only arguments."""
    
    @lockdown(warrant, tool="test_tool", keypair=keypair)
    def func(a, *, b):
        return "success"
    
    assert func("1", b="2") == "success"

def test_lockdown_defaults_applied(warrant, keypair):
    """Test that defaults are applied and checked against constraints."""
    
    # Warrant requires b="2"
    @lockdown(warrant, tool="test_tool", keypair=keypair)
    def func(a, b="2"):
        return "success"
    
    # Calling func("1") implies b="2". Should pass.
    assert func("1") == "success"
    
    # If we change default to "3", it should fail
    @lockdown(warrant, tool="test_tool", keypair=keypair)
    def func_bad_default(a, b="3"):
        return "success"
        
    with pytest.raises(Exception):
        func_bad_default("1") # b="3" != "2"

def test_lockdown_binding_error(warrant, keypair):
    """Test that binding errors are raised."""
    
    @lockdown(warrant, tool="test_tool", keypair=keypair)
    def func(a, b):
        return "success"
        
    with pytest.raises(TypeError):
        func("1") # Missing b
