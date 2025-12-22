"""
Diagnostic utilities for Tenuo.

This module provides troubleshooting and configuration inspection tools.
"""

from tenuo_core import Warrant  # type: ignore[import-untyped]


def diagnose(warrant: Warrant) -> str:
    """
    Troubleshoot warrant issues.
    
    Provides a detailed diagnosis of a warrant's status, including:
    - Expiration status
    - Delegation depth
    - Tools authorized
    - Clearance level
    
    Args:
        warrant: The warrant to diagnose
        
    Returns:
        Human-readable diagnostic report
        
    Example:
        import tenuo
        
        tenuo.diagnose(warrant)
        # Output:
        # Warrant Diagnosis
        # ==================
        # [OK] Valid for: 0:04:32
        # [OK] Can delegate: 3 levels remaining
        # [OK] Tools: search, read_file
        # [OK] Clearance: INTERNAL
    """
    lines = [
        "Warrant Diagnosis",
        "=" * 50,
        ""
    ]
    
    # Check expiration
    if warrant.is_expired():
        lines.append("[NO] Expired: warrant has expired")
    else:
        lines.append(f"[OK] Valid for: {warrant.ttl_remaining}")
    
    # Check depth
    if warrant.is_terminal():
        lines.append("[WARNING] Terminal: cannot delegate further")
    else:
        # Handle both max_depth and max_issue_depth for compatibility
        max_d = getattr(warrant, 'max_depth', None)
        if max_d is None:
            max_d = getattr(warrant, 'max_issue_depth', None)
        if max_d is not None:
            remaining = max_d - warrant.depth
        lines.append(f"[OK] Can delegate: {remaining} levels remaining")
        else:
            lines.append(f"[OK] Depth: {warrant.depth}")
    
    # Check tools
    if warrant.tools:
        tools_str = ", ".join(warrant.tools)
        lines.append(f"[OK] Tools: {tools_str}")
    else:
        lines.append("[WARNING] No tools authorized")
    
    # Check clearance
    if warrant.clearance is not None:
        lines.append(f"[OK] Clearance: {warrant.clearance}")
    
    # Check type
    lines.append(f"[OK] Type: {warrant.warrant_type}")
    
    return "\n".join(lines)


def info() -> str:
    """
    Show current Tenuo configuration.
    
    Returns:
        Human-readable configuration status
        
    Example:
        import tenuo
        
        print(tenuo.info())
        # Output:
        # Tenuo Configuration
        # ===================
        # [OK] SDK Version: 0.1.0a7
        # [OK] Rust Core: loaded
    """
    lines = [
        "Tenuo Configuration",
        "=" * 50,
        ""
    ]
    
    # SDK version
    try:
        from tenuo import __version__
        lines.append(f"[OK] SDK Version: {__version__}")
    except ImportError:
        lines.append("[WARNING] SDK Version: unknown")
    
    # Rust core status
    try:
        from tenuo_core import WIRE_VERSION  # type: ignore[import-untyped]
        lines.append(f"[OK] Rust Core: loaded (wire version {WIRE_VERSION})")
    except ImportError:
        lines.append("[NO] Rust Core: not loaded")
    
    # Check for configured issuer key
    try:
        from tenuo.config import get_config
        config = get_config()
        if config and hasattr(config, 'issuer_key') and config.issuer_key:
            lines.append("[OK] Issuer Key: configured")
        else:
            lines.append("[WARNING] Issuer Key: not configured")
    except (ImportError, AttributeError):
        lines.append("[WARNING] Issuer Key: status unknown")
    
    return "\n".join(lines)
