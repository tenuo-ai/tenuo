"""
Delegation benchmark for Tenuo.

Tests warrant chains and attenuation, Tenuo's core differentiator.
"""

from .scenarios import (
    ManagerAssistantScenario,
    ChainDepthScenario,
    MixedAttackScenario,
    TTLBoundedScenario,
    TemporalScopingScenario,
)
from .harness import DelegationHarness

__all__ = [
    "ManagerAssistantScenario",
    "ChainDepthScenario",
    "MixedAttackScenario",
    "TTLBoundedScenario",
    "TemporalScopingScenario",
    "DelegationHarness",
]

