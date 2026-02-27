"""
REPL-friendly constraint explanations.

This module adds explain() methods to constraints for interactive debugging.
It provides detailed analysis of why a value passes or fails a constraint.

Usage:
    from tenuo import Subpath
    from tenuo.explain_constraint import explain_constraint

    jail = Subpath("/data")

    # Detailed explanation
    result = explain_constraint(jail, "/data/../etc/passwd")
    print(result)
    # PathAnalysis(
    #   input="/data/../etc/passwd",
    #   normalized="/etc/passwd",
    #   contained=False,
    #   reason="Normalized path escapes root: /etc/passwd is not under /data"
    # )
"""

import ipaddress
import posixpath
from dataclasses import dataclass
from typing import Any, List, Optional
from urllib.parse import unquote, urlparse


@dataclass
class PathAnalysis:
    """Detailed analysis of a path against Subpath constraint."""

    input: str
    normalized: str
    root: str
    contained: bool
    reason: str

    def __repr__(self) -> str:
        return (
            f"PathAnalysis(\n"
            f"  input={self.input!r},\n"
            f"  normalized={self.normalized!r},\n"
            f"  root={self.root!r},\n"
            f"  contained={self.contained},\n"
            f"  reason={self.reason!r}\n"
            f")"
        )


@dataclass
class UrlAnalysis:
    """Detailed analysis of a URL against UrlSafe constraint."""

    input: str
    scheme: str
    host: str
    port: Optional[int]
    resolved_ip: Optional[str]
    is_private: bool
    in_allowlist: Optional[bool]
    safe: bool
    reason: str

    def __repr__(self) -> str:
        return (
            f"UrlAnalysis(\n"
            f"  input={self.input!r},\n"
            f"  scheme={self.scheme!r},\n"
            f"  host={self.host!r},\n"
            f"  port={self.port},\n"
            f"  resolved_ip={self.resolved_ip!r},\n"
            f"  is_private={self.is_private},\n"
            f"  in_allowlist={self.in_allowlist},\n"
            f"  safe={self.safe},\n"
            f"  reason={self.reason!r}\n"
            f")"
        )


@dataclass
class CommandAnalysis:
    """Detailed analysis of a command against Shlex constraint."""

    input: str
    tokens: List[str]
    binary: str
    binary_allowed: bool
    dangerous_tokens: List[str]
    expansion_chars: List[str]
    control_chars: List[str]
    safe: bool
    reason: str

    def __repr__(self) -> str:
        return (
            f"CommandAnalysis(\n"
            f"  input={self.input!r},\n"
            f"  tokens={self.tokens!r},\n"
            f"  binary={self.binary!r},\n"
            f"  binary_allowed={self.binary_allowed},\n"
            f"  dangerous_tokens={self.dangerous_tokens!r},\n"
            f"  expansion_chars={self.expansion_chars!r},\n"
            f"  control_chars={self.control_chars!r},\n"
            f"  safe={self.safe},\n"
            f"  reason={self.reason!r}\n"
            f")"
        )


def explain_constraint(constraint: Any, value: Any) -> Any:
    """
    Get a detailed explanation of why a value passes or fails a constraint.

    Args:
        constraint: A Tenuo constraint (Subpath, UrlSafe, Shlex, etc.)
        value: The value to check

    Returns:
        A dataclass with detailed analysis (PathAnalysis, UrlAnalysis, etc.)

    Example:
        >>> from tenuo import Subpath
        >>> from tenuo.explain_constraint import explain_constraint
        >>>
        >>> jail = Subpath("/data")
        >>> explain_constraint(jail, "/data/../etc/passwd")
        PathAnalysis(
          input='/data/../etc/passwd',
          normalized='/etc/passwd',
          root='/data',
          contained=False,
          reason='Normalized path escapes root: /etc/passwd is not under /data'
        )
    """
    constraint_type = type(constraint).__name__

    if constraint_type == "Subpath" or constraint_type == "PySubpath":
        return _explain_subpath(constraint, value)
    elif constraint_type == "UrlSafe" or constraint_type == "PyUrlSafe":
        return _explain_urlsafe(constraint, value)
    elif constraint_type == "Shlex":
        return _explain_shlex(constraint, value)
    else:
        # Generic constraint
        try:
            result = constraint.matches(value) if hasattr(constraint, "matches") else constraint.contains(value)
            return {
                "constraint": repr(constraint),
                "value": value,
                "result": result,
            }
        except Exception as e:
            return {
                "constraint": repr(constraint),
                "value": value,
                "error": str(e),
            }


def _explain_subpath(constraint: Any, value: Any) -> PathAnalysis:
    """Explain Subpath constraint check."""
    if not isinstance(value, str):
        return PathAnalysis(
            input=str(value),
            normalized="<not a string>",
            root=getattr(constraint, "root", "<unknown>"),
            contained=False,
            reason=f"Value must be a string, got {type(value).__name__}",
        )

    root = getattr(constraint, "root", "/data")

    # Normalize the path
    normalized = posixpath.normpath(value)

    # Ensure normalized path starts with /
    if not normalized.startswith("/"):
        normalized = "/" + normalized

    # Check containment
    # Path must start with root (with trailing slash handling)
    root_check = root.rstrip("/") + "/"
    path_check = normalized.rstrip("/") + "/"

    contained = path_check.startswith(root_check) or normalized == root.rstrip("/")

    if contained:
        reason = f"Path is within root directory {root}"
    else:
        reason = f"Normalized path escapes root: {normalized} is not under {root}"

    return PathAnalysis(input=value, normalized=normalized, root=root, contained=contained, reason=reason)


def _explain_urlsafe(constraint: Any, value: Any) -> UrlAnalysis:
    """Explain UrlSafe constraint check."""
    if not isinstance(value, str):
        return UrlAnalysis(
            input=str(value),
            scheme="",
            host="",
            port=None,
            resolved_ip=None,
            is_private=False,
            in_allowlist=None,
            safe=False,
            reason=f"Value must be a string, got {type(value).__name__}",
        )

    try:
        parsed = urlparse(value)
    except Exception as e:
        return UrlAnalysis(
            input=value,
            scheme="",
            host="",
            port=None,
            resolved_ip=None,
            is_private=False,
            in_allowlist=None,
            safe=False,
            reason=f"Failed to parse URL: {e}",
        )

    scheme = parsed.scheme.lower()
    host = unquote(parsed.hostname or "")
    port = parsed.port

    # Check if host is an IP
    resolved_ip = None
    is_private = False

    try:
        # Try parsing as IP
        ip = ipaddress.ip_address(host)
        resolved_ip = str(ip)
        is_private = ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # Not an IP, might be a hostname
        # Check for decimal IP encoding
        try:
            if host.isdigit():
                decimal_ip = int(host)
                ip = ipaddress.ip_address(decimal_ip)
                resolved_ip = str(ip)
                is_private = ip.is_private or ip.is_loopback or ip.is_link_local
        except (ValueError, OverflowError):
            pass

    # Check allowlist if present
    allow_domains = getattr(constraint, "allow_domains", None)
    in_allowlist = None

    if allow_domains:
        in_allowlist = host in allow_domains or any(
            host.endswith(d.lstrip("*")) for d in allow_domains if d.startswith("*")
        )

    # Determine safety
    safe = True
    reason = "URL is safe"

    if scheme not in ("http", "https"):
        safe = False
        reason = f"Scheme '{scheme}' not allowed (only http/https)"
    elif is_private:
        safe = False
        reason = f"Host resolves to private IP: {resolved_ip}"
    elif allow_domains and not in_allowlist:
        safe = False
        reason = f"Host '{host}' not in allowlist: {allow_domains}"

    return UrlAnalysis(
        input=value,
        scheme=scheme,
        host=host,
        port=port,
        resolved_ip=resolved_ip,
        is_private=is_private,
        in_allowlist=in_allowlist,
        safe=safe,
        reason=reason,
    )


def _explain_shlex(constraint: Any, value: Any) -> CommandAnalysis:
    """Explain Shlex constraint check."""
    import shlex as shlex_module

    if not isinstance(value, str):
        return CommandAnalysis(
            input=str(value),
            tokens=[],
            binary="",
            binary_allowed=False,
            dangerous_tokens=[],
            expansion_chars=[],
            control_chars=[],
            safe=False,
            reason=f"Value must be a string, got {type(value).__name__}",
        )

    # Check for control characters
    control_chars_found = [c for c in constraint.CONTROL_CHARS if c in value]
    if control_chars_found:
        return CommandAnalysis(
            input=value,
            tokens=[],
            binary="",
            binary_allowed=False,
            dangerous_tokens=[],
            expansion_chars=[],
            control_chars=control_chars_found,
            safe=False,
            reason=f"Contains control characters: {control_chars_found!r}",
        )

    # Check for expansion characters
    expansion_chars_found = [c for c in constraint.EXPANSION_CHARS if c in value]
    if expansion_chars_found:
        return CommandAnalysis(
            input=value,
            tokens=[],
            binary="",
            binary_allowed=False,
            dangerous_tokens=[],
            expansion_chars=expansion_chars_found,
            control_chars=[],
            safe=False,
            reason=f"Contains shell expansion characters: {expansion_chars_found!r}",
        )

    # Parse the command
    try:
        lex = shlex_module.shlex(value, posix=True, punctuation_chars=True)
        tokens = list(lex)
    except ValueError as e:
        return CommandAnalysis(
            input=value,
            tokens=[],
            binary="",
            binary_allowed=False,
            dangerous_tokens=[],
            expansion_chars=[],
            control_chars=[],
            safe=False,
            reason=f"Parse error: {e}",
        )

    if not tokens:
        return CommandAnalysis(
            input=value,
            tokens=[],
            binary="",
            binary_allowed=False,
            dangerous_tokens=[],
            expansion_chars=[],
            control_chars=[],
            safe=False,
            reason="Empty command",
        )

    binary = tokens[0]
    bin_name = posixpath.basename(binary)
    binary_allowed = binary in constraint.allowed_bins or bin_name in constraint.allowed_bins

    # Check for dangerous tokens
    dangerous_tokens_found = [t for t in tokens if t in constraint.DANGEROUS_TOKENS]

    # Determine safety
    safe = True
    reason = "Command is safe"

    if not binary_allowed:
        safe = False
        reason = f"Binary '{binary}' not in allowlist: {sorted(constraint.allowed_bins)}"
    elif dangerous_tokens_found:
        safe = False
        reason = f"Contains shell operators: {dangerous_tokens_found}"

    return CommandAnalysis(
        input=value,
        tokens=tokens,
        binary=binary,
        binary_allowed=binary_allowed,
        dangerous_tokens=dangerous_tokens_found,
        expansion_chars=[],
        control_chars=[],
        safe=safe,
        reason=reason,
    )


# Convenience function
explain = explain_constraint

__all__ = [
    "explain_constraint",
    "explain",
    "PathAnalysis",
    "UrlAnalysis",
    "CommandAnalysis",
]
