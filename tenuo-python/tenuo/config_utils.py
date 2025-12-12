"""
Shared configuration utilities for Tenuo integrations.

This module contains helper functions used by both langchain.py and langgraph.py
to avoid code duplication.
"""

from typing import Any

from tenuo import Exact, Pattern, Range, OneOf


def build_constraint(raw: Any) -> Any:
    """
    Convert config constraint dict/value to Tenuo constraint type.
    
    Supported formats:
        "value"                  -> Exact("value")  (raw string/non-dict)
        exact: "value"           -> Exact("value")
        pattern: "/path/*"       -> Pattern("/path/*")
        enum: ["a", "b", "c"]    -> OneOf(["a", "b", "c"])
        min: 0, max: 100         -> Range(0, 100)
    
    Note: After interpolation in SecureGraph, a config like `pattern: "${state.path}"`
    becomes just the string "/uploads/file.txt" (not a dict). This function handles
    that case by treating non-dict values as Exact matches.
    
    The 'validate' field (used for security validation during interpolation) is
    ignored here - it's processed separately before this function is called.
    
    Args:
        raw: Either a dict with constraint spec, or a raw value (post-interpolation)
        
    Returns:
        Tenuo constraint object (Exact, Pattern, Range, or OneOf)
        
    Raises:
        ValueError: If dict format is unrecognized
        
    Examples:
        >>> build_constraint("hello")
        Exact("hello")
        
        >>> build_constraint({"pattern": "/tmp/*"})
        Pattern("/tmp/*")
        
        >>> build_constraint({"enum": ["a", "b"]})
        OneOf(["a", "b"])
        
        >>> build_constraint({"min": 0, "max": 100})
        Range(0, 100)
    """
    # After interpolation, raw might be a string (if entire value was ${state.foo})
    if not isinstance(raw, dict):
        return Exact(raw)
    
    if "exact" in raw:
        return Exact(raw["exact"])
    if "pattern" in raw:
        return Pattern(raw["pattern"])
    if "enum" in raw:
        return OneOf(raw["enum"])
    if "min" in raw or "max" in raw:
        return Range(min_val=raw.get("min"), max_val=raw.get("max"))
    
    raise ValueError(f"Unknown constraint format: {raw}")


__all__ = ["build_constraint"]
