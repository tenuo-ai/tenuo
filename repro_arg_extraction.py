import inspect
from functools import wraps

def mock_lockdown(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        auth_args = {}
        
        # Current implementation logic
        auth_args.update(kwargs)
        
        for i, arg_val in enumerate(args):
            if i < len(params):
                param_name = params[i]
                if param_name not in auth_args:
                    auth_args[param_name] = arg_val
        
        # Default value logic
        for param_name, param in sig.parameters.items():
            if param_name not in auth_args and param.default is not inspect.Parameter.empty:
                auth_args[param_name] = param.default
                
        return auth_args
    return wrapper

def test_standard():
    @mock_lockdown
    def foo(a, b=2): pass
    
    assert test_standard.foo(1) == {'a': 1, 'b': 2}
    assert test_standard.foo(1, 3) == {'a': 1, 'b': 3}
    print("Standard: OK")

test_standard.foo = mock_lockdown(lambda a, b=2: None)

def test_var_args():
    @mock_lockdown
    def foo(a, *args): pass
    
    # Expected: {'a': 1, 'args': (2, 3)}
    # Actual with current logic: {'a': 1, 'args': 2} (and 3 is ignored/lost)
    result = foo(1, 2, 3)
    print(f"Var args result: {result}")
    
    # This is the bug I suspect
    if result.get('args') != (2, 3):
        print("BUG CONFIRMED: *args not handled correctly")

def test_keyword_only():
    @mock_lockdown
    def foo(a, *, b): pass
    
    # Expected: {'a': 1, 'b': 2}
    result = foo(1, b=2)
    print(f"Keyword only result: {result}")

if __name__ == "__main__":
    test_standard()
    test_var_args()
    test_keyword_only()
