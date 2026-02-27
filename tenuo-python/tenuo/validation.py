"""Validation result with rich feedback."""

from typing import List, Optional


class ValidationResult:
    """Result of warrant validation with rich feedback.

    This class provides detailed information about validation failures
    including reasons and suggestions for fixing issues.
    """

    def __init__(self, success: bool, reason: Optional[str] = None, suggestions: Optional[List[str]] = None):
        self.success = success
        self.reason = reason or ""
        self.suggestions = suggestions or []

    def __bool__(self) -> bool:
        """Allow truthiness checks for backward compatibility."""
        return self.success

    def __repr__(self) -> str:
        if self.success:
            return "ValidationResult(success=True)"
        return f"ValidationResult(success=False, reason='{self.reason}')"

    @classmethod
    def ok(cls) -> "ValidationResult":
        """Create a successful validation result."""
        return cls(success=True)

    @classmethod
    def fail(cls, reason: str, suggestions: Optional[List[str]] = None) -> "ValidationResult":
        """Create a failed validation result with reason and suggestions."""
        return cls(success=False, reason=reason, suggestions=suggestions)
