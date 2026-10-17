"""Regression coverage for the public testing recipe."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def test_testing_recipe_functions_execute():
    recipe_path = Path(__file__).parents[2] / "examples" / "testing" / "test_protected_tools.py"
    spec = importlib.util.spec_from_file_location("testing_recipe", recipe_path)
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    module.test_allowed_record_executes_with_real_authorization()
    module.test_denied_record_does_not_enter_function_body()
    module.test_missing_capability_uses_stable_error_code()
    module.test_direct_warrant_assertions_cover_allowed_and_denied_args()
    module.test_child_grant_can_narrow_but_cannot_widen_scope()
    module.test_deterministic_headers_are_stable_for_regression_snapshots()
