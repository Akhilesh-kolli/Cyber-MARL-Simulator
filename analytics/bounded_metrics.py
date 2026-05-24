"""
analytics/bounded_metrics.py
----------------------------
Bounded, realistic metric scaling functions.
Replaces hard saturation with mathematically principled normalization.
"""

import math

def sigmoid_scale(raw_score: float, midpoint: float = 50.0, steepness: float = 0.05) -> float:
    """
    Sigmoid normalization: smooth S-curve from 0 to ~95.
    
    Args:
        raw_score: unbounded input value
        midpoint: value where output = 50
        steepness: curve steepness (lower = smoother)
    
    Returns:
        normalized value in [0, 95]
    """
    if raw_score <= 0:
        return 0.0
    try:
        normalized = 95.0 / (1.0 + math.exp(-steepness * (raw_score - midpoint)))
        return max(0.0, min(95.0, normalized))
    except (OverflowError, ValueError):
        return 95.0


def logarithmic_scale(raw_score: float, base: float = 10.0, max_val: float = 90.0) -> float:
    """
    Logarithmic compression: rapid initial growth, then diminishing returns.
    
    Args:
        raw_score: unbounded input value
        base: logarithm base
        max_val: asymptotic maximum (default 90)
    
    Returns:
        normalized value in [0, max_val]
    """
    if raw_score <= 0:
        return 0.0
    try:
        normalized = max_val * math.log(raw_score + 1) / math.log(base + 1)
        return max(0.0, min(max_val, normalized))
    except (ValueError, OverflowError):
        return max_val


def percentile_rank(value: float, total_events: int, max_val: float = 85.0) -> float:
    """
    Normalize based on event count percentile.
    Prevents runaway scores in small event sets.
    
    Args:
        value: metric raw value
        total_events: total event count (denominator)
        max_val: asymptotic maximum
    
    Returns:
        normalized percentile value in [0, max_val]
    """
    if total_events <= 0 or value <= 0:
        return 0.0
    percentile = min(100.0, (value / max(total_events, 1)) * 100.0)
    return (percentile / 100.0) * max_val


def entropy_scale(event_counts: dict, max_val: float = 80.0) -> float:
    """
    Shannon entropy-based variability scoring.
    Measures unpredictability across event types.
    
    Args:
        event_counts: dict of {event_type: count}
        max_val: asymptotic maximum
    
    Returns:
        entropy-normalized value in [0, max_val]
    """
    total = sum(event_counts.values())
    if total <= 1:
        return 0.0
    
    entropy = 0.0
    for count in event_counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p + 1e-10)
    
    # Normalize entropy to [0, max_val]
    max_entropy = math.log2(len(event_counts)) if len(event_counts) > 0 else 1.0
    if max_entropy > 0:
        normalized_entropy = (entropy / max_entropy) * max_val
        return max(0.0, min(max_val, normalized_entropy))
    return 0.0


def weighted_composite_score(
    contributions: dict,
    max_val: float = 90.0
) -> float:
    """
    Weighted composite scoring with bounded normalization.
    
    Args:
        contributions: {component_name: (raw_value, weight)}
                      weights must sum to 1.0
        max_val: asymptotic maximum
    
    Returns:
        bounded composite score in [0, max_val]
    """
    if not contributions:
        return 0.0
    
    total_weighted = sum(
        min(100.0, raw) * weight
        for raw, weight in contributions.values()
    )
    
    normalized = sigmoid_scale(total_weighted, midpoint=50.0, steepness=0.05)
    return min(max_val, normalized)


def decay_function(current_value: float, decay_rate: float = 0.05) -> float:
    """
    Exponential decay to prevent sustained saturation.
    Gradually reduces metric when no new events occur.
    
    Args:
        current_value: current metric value
        decay_rate: decay strength [0, 1]
    
    Returns:
        decayed value
    """
    return current_value * (1.0 - decay_rate)


def rolling_average(values: list, window_size: int = 5) -> float:
    """
    Compute rolling average of recent metric values.
    Stabilizes noisy calculations.
    
    Args:
        values: list of historical metric values
        window_size: lookback window
    
    Returns:
        rolling average
    """
    if not values:
        return 0.0
    window = values[-window_size:] if len(values) >= window_size else values
    return sum(window) / len(window)


def clamp_0_100(value: float) -> float:
    """Clamp value to [0, 100] range."""
    return max(0.0, min(100.0, value))


def clamp_0_95(value: float) -> float:
    """Clamp value to [0, 95] range. Reserves 95-100 for catastrophic scenarios."""
    return max(0.0, min(95.0, value))


def boost_to_catastrophic(
    score: float,
    catastrophic_conditions: dict
) -> float:
    """
    Only boost score above 95 if ALL catastrophic conditions met.
    
    Args:
        score: current score in [0, 95]
        catastrophic_conditions: {condition_name: is_active}
    
    Returns:
        score, potentially boosted to [95, 100]
    """
    if not all(catastrophic_conditions.values()):
        return clamp_0_95(score)
    
    # All conditions met: allow climb to 100
    if score >= 90:
        return min(95.0, score + 3.0)
    return clamp_0_95(score)
