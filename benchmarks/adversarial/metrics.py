"""
Enhanced metrics for adversarial benchmark.

Provides additional metrics for academic publication:
- Attempts to first bypass (learning curve)
- Strategy diversity
- Reconnaissance efficiency
- Cost estimation
"""

from dataclasses import dataclass
from typing import Optional

from .redteam import AttackResult


@dataclass
class EnhancedMetrics:
    """Enhanced metrics for a single attack result."""
    
    # Learning curve
    attempts_to_bypass: Optional[int] = None  # None if never bypassed
    
    # Strategy analysis
    strategy_count: int = 0
    strategies: list[str] = None
    
    # Reconnaissance efficiency
    recon_probes: int = 0
    recon_useful: bool = False  # Did recon lead to different strategies?
    
    # Cost estimation
    estimated_cost_usd: float = 0.0
    
    # Constraint type
    constraint_type: str = "unknown"


# Cost per 1K tokens (approximate, as of Feb 2026)
MODEL_COSTS = {
    # OpenAI
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4.1-mini": {"input": 0.0004, "output": 0.0016},
    "gpt-5-mini": {"input": 0.00025, "output": 0.002},
    "gpt-5.1": {"input": 0.00125, "output": 0.01},
    # Anthropic
    "claude-sonnet-4": {"input": 0.003, "output": 0.015},
    "claude-opus-4": {"input": 0.015, "output": 0.075},
}

# Approximate tokens per call
TOKENS_PER_PROBE = 500  # Recon probes
TOKENS_PER_ATTEMPT = 800  # Attack attempts


def estimate_cost(
    model: str,
    recon_probes: int,
    attack_attempts: int,
) -> float:
    """
    Estimate API cost for a benchmark run.
    
    Args:
        model: Model name (e.g., "gpt-4o")
        recon_probes: Number of reconnaissance probes
        attempts: Number of attack attempts
        
    Returns:
        Estimated cost in USD
    """
    # Find closest matching model
    model_lower = model.lower()
    costs = None
    for name, c in MODEL_COSTS.items():
        if name in model_lower or model_lower in name:
            costs = c
            break
    
    if costs is None:
        # Default to gpt-4o-mini costs
        costs = MODEL_COSTS["gpt-4o-mini"]
    
    # Estimate tokens
    recon_tokens = recon_probes * TOKENS_PER_PROBE
    attack_tokens = attack_attempts * TOKENS_PER_ATTEMPT
    total_tokens = recon_tokens + attack_tokens
    
    # Assume 50/50 input/output ratio
    input_tokens = total_tokens * 0.6
    output_tokens = total_tokens * 0.4
    
    # Calculate cost
    input_cost = (input_tokens / 1000) * costs["input"]
    output_cost = (output_tokens / 1000) * costs["output"]
    
    return input_cost + output_cost


def calculate_enhanced_metrics(
    result: AttackResult,
    model: str = "gpt-4o-mini",
    constraint_type: str = "unknown",
) -> EnhancedMetrics:
    """
    Calculate enhanced metrics for an attack result.
    
    Args:
        result: The attack result to analyze
        model: Model used for cost estimation
        constraint_type: Type of constraint (CEL, Pattern, Range)
        
    Returns:
        EnhancedMetrics with all calculated values
    """
    metrics = EnhancedMetrics()
    
    # Attempts to bypass (if bypassed)
    if result.success:
        # Find the first successful bypass
        for i, attempt in enumerate(result.attempts, 1):
            if attempt.is_bypass:
                metrics.attempts_to_bypass = i
                break
    
    # Strategy analysis
    metrics.strategies = list(result.strategies_tried)
    metrics.strategy_count = len(result.strategies_tried)
    
    # Recon stats
    metrics.recon_probes = result.recon_probes
    
    # Recon is "useful" if we have probes and tried strategies
    metrics.recon_useful = (
        result.recon_probes > 0 and 
        len(result.strategies_tried) > 2
    )
    
    # Cost estimation
    metrics.estimated_cost_usd = estimate_cost(
        model,
        result.recon_probes,
        result.num_attempts,
    )
    
    metrics.constraint_type = constraint_type
    
    return metrics


def format_metrics_table(
    results: list[AttackResult],
    model: str = "gpt-4o-mini",
) -> str:
    """
    Format metrics as a markdown table.
    
    Args:
        results: List of attack results
        model: Model used for cost estimation
        
    Returns:
        Markdown table string
    """
    lines = [
        "| Scenario | Defended | Attempts | Strategies | Cost |",
        "|----------|----------|----------|------------|------|",
    ]
    
    total_cost = 0.0
    
    for r in results:
        metrics = calculate_enhanced_metrics(r, model)
        defended = "✓" if not r.success else "✗"
        cost = f"${metrics.estimated_cost_usd:.3f}"
        total_cost += metrics.estimated_cost_usd
        
        lines.append(
            f"| {r.scenario} | {defended} | {r.num_attempts} | "
            f"{metrics.strategy_count} | {cost} |"
        )
    
    lines.append(f"| **Total** | | | | **${total_cost:.3f}** |")
    
    return "\n".join(lines)


def constraint_type_from_scenario(scenario_name: str) -> str:
    """Infer constraint type from scenario name."""
    type_map = {
        "email_exfil": "CEL",
        "financial_limit": "Range",
        "path_traversal": "Subpath",
        "url_restriction": "CEL",
        "multi_recipient": "CEL",
        "api_key_exfil": "CEL",
        "tool_confusion": "Tool",
        "unicode_homoglyph": "CEL",
    }
    return type_map.get(scenario_name, "unknown")
