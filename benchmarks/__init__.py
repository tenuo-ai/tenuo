"""
Tenuo Benchmarks.

Contains benchmark integrations for measuring Tenuo's effectiveness
against prompt injection and other agent security threats.
"""

__all__ = []

# AgentDojo integration (requires agentdojo package)
try:
    from .agentdojo import TenuoAgentDojoHarness  # noqa: F401

    __all__.append("TenuoAgentDojoHarness")
except ImportError:
    pass

# Delegation benchmark (standalone, no external deps)
try:
    from .delegation import DelegationHarness  # noqa: F401

    __all__.append("DelegationHarness")
except ImportError:
    pass
