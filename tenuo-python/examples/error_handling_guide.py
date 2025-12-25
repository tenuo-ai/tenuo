#!/usr/bin/env python3
"""
Tenuo Error Handling Guide

This example demonstrates comprehensive error handling patterns for Tenuo:
- Common error scenarios
- Recovery strategies
- Best practices
- Production-ready error handling

Key Patterns:
1. Warrant expiration handling
2. PoP signature failures
3. Constraint violations
4. Missing warrant errors
5. Retry strategies (when appropriate)
6. Graceful degradation
"""

import time
from typing import Optional, Callable, Any
from enum import Enum

from tenuo import (
    Warrant,
    SigningKey,
    WarrantViolation,
    warrant_scope,
    key_scope,
    guard,
    Pattern,
    Range,
    TenuoError,
)
from tenuo.exceptions import AuthorizationError

# Alias for backwards compatibility
WarrantError = WarrantViolation


# Placeholder functions for examples
@guard(tool="read_file")
def read_file(path: str) -> str:
    """Simulated file read for examples."""
    return f"Contents of {path}"


@guard(tool="process_payment")
def process_payment(amount: float, currency: str) -> str:
    """Simulated payment processing for examples."""
    return f"Processed payment of {amount} {currency}"

# ============================================================================
# Error Types
# ============================================================================

class ErrorSeverity(Enum):
    """Error severity levels."""
    FATAL = "fatal"  # Cannot recover, must abort
    RETRYABLE = "retryable"  # May succeed on retry
    WARNING = "warning"  # Non-fatal, can continue


class ErrorCategory(Enum):
    """Error categories for handling."""
    WARRANT_EXPIRED = "warrant_expired"
    POP_FAILED = "pop_failed"
    CONSTRAINT_VIOLATION = "constraint_violation"
    MISSING_WARRANT = "missing_warrant"
    INVALID_WARRANT = "invalid_warrant"
    UNKNOWN = "unknown"

# ============================================================================
# Error Classifier
# ============================================================================

class TenuoErrorClassifier:
    """Classifies Tenuo errors for appropriate handling."""
    
    @staticmethod
    def classify(error: Exception) -> tuple[ErrorCategory, ErrorSeverity, str]:
        """
        Classify an error and return category, severity, and recommendation.
        
        Returns:
            (category, severity, recommendation)
        """
        if isinstance(error, WarrantError):
            error_msg = str(error).lower()
            if "expired" in error_msg:
                return (
                    ErrorCategory.WARRANT_EXPIRED,
                    ErrorSeverity.FATAL,
                    "Warrant expired. Task must be resubmitted to gateway for fresh warrant. Do not retry locally."
                )
            elif "invalid" in error_msg or "format" in error_msg:
                return (
                    ErrorCategory.INVALID_WARRANT,
                    ErrorSeverity.FATAL,
                    "Invalid warrant format. Check warrant serialization/deserialization."
                )
            else:
                return (
                    ErrorCategory.INVALID_WARRANT,
                    ErrorSeverity.FATAL,
                    "Warrant error. Check warrant validity."
                )
        
        elif isinstance(error, AuthorizationError):
            error_msg = str(error).lower()
            if "proof-of-possession" in error_msg or "pop" in error_msg:
                return (
                    ErrorCategory.POP_FAILED,
                    ErrorSeverity.FATAL,
                    "PoP signature failed. SigningKey does not match warrant holder. Check signing_key configuration."
                )
            elif "no warrant" in error_msg or "missing" in error_msg:
                return (
                    ErrorCategory.MISSING_WARRANT,
                    ErrorSeverity.FATAL,
                    "No warrant available. Ensure warrant is passed explicitly or set in context."
                )
            elif "does not authorize" in error_msg or "constraint" in error_msg:
                return (
                    ErrorCategory.CONSTRAINT_VIOLATION,
                    ErrorSeverity.FATAL,
                    "Agent is attempting unauthorized action. Log security event and abort task."
                )
            else:
                return (
                    ErrorCategory.CONSTRAINT_VIOLATION,
                    ErrorSeverity.FATAL,
                    "Authorization failed. Check warrant constraints and action parameters."
                )
        
        else:
            return (
                ErrorCategory.UNKNOWN,
                ErrorSeverity.RETRYABLE,
                "Unknown error. May be transient. Consider retry with exponential backoff."
            )

# ============================================================================
# Protected Functions
# ============================================================================


# ============================================================================
# Error Handlers
# ============================================================================

class TenuoErrorHandler:
    """Handles Tenuo errors with appropriate strategies."""
    
    def __init__(self, logger: Optional[Callable] = None):
        self.logger = logger or print
        self.classifier = TenuoErrorClassifier()
    
    def handle(self, error: Exception, context: Optional[dict] = None) -> dict:
        """
        Handle a Tenuo error.
        
        Args:
            error: The exception that occurred
            context: Additional context (warrant_id, tool, etc.)
        
        Returns:
            Dict with error details and handling recommendation
        """
        category, severity, recommendation = self.classifier.classify(error)
        
        error_info = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "category": category.value,
            "severity": severity.value,
            "recommendation": recommendation,
            "context": context or {}
        }
        
        # Log based on severity
        if severity == ErrorSeverity.FATAL:
            self.logger(f"FATAL ERROR [{category.value}]: {error}")
            self.logger(f"  Recommendation: {recommendation}")
        elif severity == ErrorSeverity.RETRYABLE:
            self.logger(f"RETRYABLE ERROR [{category.value}]: {error}")
        else:
            self.logger(f"WARNING [{category.value}]: {error}")
        
        return error_info
    
    def should_retry(self, error: Exception) -> bool:
        """Determine if error is retryable."""
        _, severity, _ = self.classifier.classify(error)
        return severity == ErrorSeverity.RETRYABLE
    
    def should_abort(self, error: Exception) -> bool:
        """Determine if error requires task abortion."""
        _, severity, _ = self.classifier.classify(error)
        return severity == ErrorSeverity.FATAL

# ============================================================================
# Retry Strategies
# ============================================================================

def retry_with_backoff(
    func: Callable,
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    error_handler: Optional[TenuoErrorHandler] = None
) -> Any:
    """
    Retry a function with exponential backoff.
    
    Only retries for retryable errors (not fatal Tenuo errors).
    """
    error_handler = error_handler or TenuoErrorHandler()
    delay = initial_delay
    
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if not error_handler.should_retry(e):
                # Fatal error - don't retry
                raise
            
            if attempt < max_retries - 1:
                print(f"  Retry {attempt + 1}/{max_retries} after {delay}s...")
                time.sleep(delay)
                delay *= backoff_factor
            else:
                # Max retries reached
                raise
    
    raise RuntimeError("Should not reach here")

# ============================================================================
# Safe Execution Wrapper
# ============================================================================

def safe_execute(
    func: Callable,
    error_handler: Optional[TenuoErrorHandler] = None,
    context: Optional[dict] = None
) -> tuple[Optional[Any], Optional[dict]]:
    """
    Safely execute a function with Tenuo error handling.
    
    Returns:
        (result, error_info) - result is None on error, error_info is None on success
    """
    error_handler = error_handler or TenuoErrorHandler()
    
    try:
        result = func()
        return result, None
    except (TenuoError, AuthorizationError, WarrantError) as e:
        error_info = error_handler.handle(e, context)
        return None, error_info
    except Exception as e:
        # Non-Tenuo error
        error_info = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "category": "non_tenuo_error",
            "severity": "unknown",
            "recommendation": "Handle according to application logic"
        }
        return None, error_info

# ============================================================================
# Examples
# ============================================================================

def main():
    print("=" * 60)
    print("Tenuo Error Handling Guide")
    print("=" * 60)
    
    signing_key = SigningKey.generate()
    handler = TenuoErrorHandler()
    
    # ========================================================================
    # Example 1: Warrant Expired
    # ========================================================================
    print("\n1. Warrant Expired Error")
    print("-" * 60)
    
    expired_warrant = (Warrant.mint_builder()
        .capability("read_file", file_path=Pattern("/tmp/*"))
        .holder(signing_key.public_key)
        .ttl(1)  # Very short TTL
        .mint(signing_key))
    
    time.sleep(2)  # Wait for expiration
    
    def try_read():
        with warrant_scope(expired_warrant), key_scope(signing_key):
            return read_file("/tmp/test.txt")
    
    result, error_info = safe_execute(try_read, handler, {"warrant_id": expired_warrant.id})
    if error_info:
        print(f"✓ Correctly handled: {error_info['category']}")
        print(f"  Recommendation: {error_info['recommendation']}")
        print(f"  Should abort: {handler.should_abort(WarrantError('Warrant expired'))}")
    
    # ========================================================================
    # Example 2: Constraint Violation
    # ========================================================================
    print("\n2. Constraint Violation Error")
    print("-" * 60)
    
    restricted_warrant = (Warrant.mint_builder()
        .capability("process_payment",
            amount=Range.max_value(1000.0),
            currency=Pattern("USD|EUR"))
        .holder(signing_key.public_key)
        .ttl(3600)
        .mint(signing_key))
    
    def try_payment():
        with warrant_scope(restricted_warrant), key_scope(signing_key):
            return process_payment(amount=2000.0, currency="USD")  # Exceeds max
    
    result, error_info = safe_execute(try_payment, handler, {"warrant_id": restricted_warrant.id})
    if error_info:
        print(f"✓ Correctly handled: {error_info['category']}")
        print(f"  Recommendation: {error_info['recommendation']}")
        print("  This is a security violation - should abort immediately")
    
    # ========================================================================
    # Example 3: Missing Warrant
    # ========================================================================
    print("\n3. Missing Warrant Error")
    print("-" * 60)
    
    def try_without_warrant():
        # No warrant in context
        return read_file("/tmp/test.txt")
    
    result, error_info = safe_execute(try_without_warrant, handler)
    if error_info:
        print(f"✓ Correctly handled: {error_info['category']}")
        print(f"  Recommendation: {error_info['recommendation']}")
    
    # ========================================================================
    # Example 4: Wrong SigningKey (PoP Failure)
    # ========================================================================
    print("\n4. PoP Failure (Wrong SigningKey)")
    print("-" * 60)
    
    wrong_signing_key = SigningKey.generate()  # Different signing_key
    warrant = (Warrant.mint_builder()
        .capability("read_file", file_path=Pattern("/tmp/*"))
        .holder(signing_key.public_key)  # Bound to original signing_key
        .ttl(3600)
        .mint(signing_key))
    
    def try_with_wrong_signing_key():
        with warrant_scope(warrant), key_scope(wrong_signing_key):
            return read_file("/tmp/test.txt")
    
    result, error_info = safe_execute(try_with_wrong_signing_key, handler)
    if error_info:
        print(f"✓ Correctly handled: {error_info['category']}")
        print(f"  Recommendation: {error_info['recommendation']}")
        print("  This is a security violation - signing_key mismatch")
    
    # ========================================================================
    # Example 5: Error Classification Summary
    # ========================================================================
    print("\n5. Error Classification Summary")
    print("-" * 60)
    
    test_errors = [
        WarrantError("Warrant expired at 2024-01-01T12:00:00Z"),
        AuthorizationError("Proof-of-Possession failed"),
        AuthorizationError("No warrant available for read_file"),
        AuthorizationError("Warrant does not authorize read_file with args {'file_path': '/etc/passwd'}"),
        ValueError("Invalid warrant format"),
    ]
    
    for error in test_errors:
        category, severity, recommendation = handler.classifier.classify(error)
        print(f"\n{type(error).__name__}: {str(error)[:50]}...")
        print(f"  Category: {category.value}")
        print(f"  Severity: {severity.value}")
        print(f"  Retryable: {handler.should_retry(error)}")
        print(f"  Should abort: {handler.should_abort(error)}")
    
    # ========================================================================
    # Best Practices Summary
    # ========================================================================
    print("\n" + "=" * 60)
    print("Error Handling Best Practices")
    print("=" * 60)
    print("""
1. WARRANT EXPIRED:
   - Fatal error - do not retry
   - Task must be resubmitted to gateway for fresh warrant
   - Log security event

2. POP FAILED:
   - Fatal error - do not retry
   - Check signing_key configuration
   - Verify signing_key matches warrant's authorized_holder
   - Log security event

3. CONSTRAINT VIOLATION:
   - Fatal error - do not retry
   - Agent attempting unauthorized action
   - Log security event and abort task
   - Consider alerting security team

4. MISSING WARRANT:
   - Fatal error - do not retry
   - Ensure warrant is passed explicitly or set in context
   - Check middleware/context setup

5. RETRYABLE ERRORS:
   - Only retry non-security errors (network, transient failures)
   - Use exponential backoff
   - Set max retry limits
   - Never retry Tenuo security errors
    """)
    print("=" * 60)

if __name__ == "__main__":
    main()
