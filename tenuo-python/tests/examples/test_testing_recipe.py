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

    names = sorted(name for name in dir(module) if name.startswith("test_"))
    assert names
    for name in names:
        getattr(module, name)()
