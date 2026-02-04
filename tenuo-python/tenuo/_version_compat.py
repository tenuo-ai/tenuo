"""
Runtime version compatibility checking.

This module provides warnings (not errors) when users have versions with known issues.
We prefer to let users try things and warn them, rather than blocking installation.

See docs/compatibility-matrix.md for full details on version compatibility.
"""

import logging
import warnings
from functools import lru_cache
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Known version issues - warn but don't fail
# Format: (min_version_with_issue, max_version_with_issue, issue_description, recommendation)
VERSION_WARNINGS = {
    "openai": [
        (
            (1, 0, 0),
            (1, 5, 999),
            "OpenAI 1.0-1.5 may have httpx compatibility issues causing 'unexpected keyword argument proxies' errors",
            "Upgrade to openai>=1.6 if you encounter this issue",
        ),
    ],
    "crewai": [
        (
            (1, 0, 0),
            (1, 0, 999),
            "CrewAI 1.0.x requires explicit 'backstory' for Agent and 'expected_output' for Task",
            "These fields became optional defaults in 1.1+",
        ),
    ],
    "langchain-core": [
        (
            (0, 2, 0),
            (0, 2, 26),
            "langchain-core 0.2.0-0.2.26 is incompatible with langgraph>=0.2",
            "Upgrade to langchain-core>=0.2.27 if using langgraph",
        ),
    ],
}


def parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """Parse a version string into a tuple of integers."""
    try:
        # Handle versions like "1.2.3", "1.2.3b1", "1.2.3.post1"
        parts = version_str.split(".")
        result = []
        for part in parts[:3]:  # Only take major.minor.patch
            # Extract leading digits
            digits = ""
            for char in part:
                if char.isdigit():
                    digits += char
                else:
                    break
            if digits:
                result.append(int(digits))
        if len(result) < 3:
            result.extend([0] * (3 - len(result)))
        return tuple(result[:3])
    except (ValueError, AttributeError):
        return None


def version_in_range(
    version: Tuple[int, ...],
    min_version: Tuple[int, ...],
    max_version: Tuple[int, ...],
) -> bool:
    """Check if version is within the given range (inclusive)."""
    return min_version <= version <= max_version


@lru_cache(maxsize=32)
def get_package_version(package_name: str) -> Optional[str]:
    """Get installed version of a package."""
    try:
        # Try importlib.metadata first (Python 3.8+)
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version(package_name)
        except PackageNotFoundError:
            return None
    except ImportError:
        # Fallback for older Python
        try:
            import pkg_resources
            return pkg_resources.get_distribution(package_name).version
        except Exception:
            return None


def check_version_compatibility(package_name: str, warn: bool = True) -> list:
    """
    Check if installed package version has known issues.
    
    Args:
        package_name: Name of the package to check
        warn: If True, emit warnings for known issues
        
    Returns:
        List of (issue_description, recommendation) tuples for any issues found
    """
    issues = []
    
    version_str = get_package_version(package_name)
    if version_str is None:
        return issues
    
    version = parse_version(version_str)
    if version is None:
        return issues
    
    warnings_for_package = VERSION_WARNINGS.get(package_name, [])
    
    for min_ver, max_ver, issue, recommendation in warnings_for_package:
        if version_in_range(version, min_ver, max_ver):
            issues.append((issue, recommendation))
            if warn:
                warning_msg = (
                    f"Tenuo compatibility notice: {package_name}=={version_str}\n"
                    f"  Issue: {issue}\n"
                    f"  Recommendation: {recommendation}\n"
                    f"  See: https://tenuo.dev/docs/compatibility-matrix"
                )
                warnings.warn(warning_msg, UserWarning, stacklevel=3)
                logger.info(warning_msg)
    
    return issues


def check_openai_compat():
    """Check OpenAI version compatibility on import."""
    check_version_compatibility("openai")


def check_crewai_compat():
    """Check CrewAI version compatibility on import."""
    check_version_compatibility("crewai")


def check_langchain_compat():
    """Check LangChain version compatibility on import."""
    check_version_compatibility("langchain-core")


def check_langgraph_compat():
    """Check LangGraph version compatibility on import."""
    check_version_compatibility("langchain-core")  # langgraph depends on langchain-core
