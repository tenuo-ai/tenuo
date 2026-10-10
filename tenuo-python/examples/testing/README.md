# Testing Protected Application Code

This recipe shows how to test application code protected by Tenuo without
bypassing authorization.

Use real authorization decisions for integration-style tests:

- issue a fresh signing key and warrant per test
- wrap protected calls with `warrant_scope()` and `key_scope()`
- use `assert_authorized()` and `assert_denied()` for expected outcomes
- assert stable exception fields such as `error_code` when checking failures
- use `assert_can_grant()` and `assert_cannot_grant()` to test delegation
- use `deterministic_headers()` when you need stable warrant and PoP headers

`allow_all()` is useful for isolated unit tests that do not care about
authorization. Keep it out of production modules and do not use it as the main
test path for protected behavior.

Run this recipe from `tenuo-python/`:

```bash
pytest examples/testing/test_protected_tools.py
```
