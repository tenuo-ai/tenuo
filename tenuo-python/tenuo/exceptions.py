"""
Pythonic exceptions for Tenuo operations.
"""


class TenuoError(Exception):
    """Base exception for all Tenuo errors."""
    pass


class WarrantError(TenuoError):
    """Raised when warrant operations fail."""
    pass


class AuthorizationError(TenuoError):
    """Raised when authorization checks fail."""
    pass


class ConstraintError(TenuoError):
    """Raised when constraint validation fails."""
    pass


class ConfigurationError(TenuoError):
    """Raised when configuration is invalid."""
    pass

