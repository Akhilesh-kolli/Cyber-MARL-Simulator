"""
backend/reward_engine.py
------------------------
Deterministic and explainable reward calculation for defender operations
and campaign suppression states.
"""

def calculate_step_reward(
    *,
    is_defender_action: bool,
    defense_success: bool,
    compromised_count: int,
    previous_compromised: int,
    persistence_score: float,
    threat_momentum_score: float,
    successful_defenses: int
) -> tuple:
    """
    Computes defender step reward, returning a tuple (reward_delta, reason_string).
    Guarantees deterministic explainability.
    """
    reward = 0.0
    reasons = []

    if is_defender_action:
        if defense_success:
            # containment reward
            containment_val = 6.0
            prevention_bonus = float(max(0, 12 - compromised_count))
            persistence_penalty = float(persistence_score * 0.15)
            
            step_reward = containment_val + prevention_bonus - persistence_penalty
            reward += step_reward
            reasons.append(f"+{containment_val:.1f} Containment Success")
            if prevention_bonus > 0:
                reasons.append(f"+{prevention_bonus:.1f} Prevention Bonus")
            if persistence_penalty > 0:
                reasons.append(f"-{persistence_penalty:.1f} Persistence Penalty")
        else:
            # defense failure penalty
            penalty = -4.0
            reward += penalty
            reasons.append(f"{penalty:.1f} Containment Failed Penalty")
    
    # Loop-level background checks
    momentum_penalty = float(threat_momentum_score * 0.005)
    persistence_loop_penalty = float(persistence_score * 0.008)
    defense_accumulation_bonus = float(successful_defenses * 0.25)
    
    reward -= momentum_penalty
    reward -= persistence_loop_penalty
    reward += defense_accumulation_bonus
    
    if momentum_penalty > 0:
        reasons.append(f"-{momentum_penalty:.2f} Threat Momentum Penalty")
    if persistence_loop_penalty > 0:
        reasons.append(f"-{persistence_loop_penalty:.2f} Persistence Drag")
    if defense_accumulation_bonus > 0:
        reasons.append(f"+{defense_accumulation_bonus:.2f} Defense History Bonus")
        
    # Active recovery reward
    if compromised_count < previous_compromised:
        recovery_bonus = 8.0
        reward += recovery_bonus
        reasons.append(f"+{recovery_bonus:.1f} Active Node Recovery Bonus")
        
    # Hard bound for step stability
    bounded_reward = max(reward, -3.0)
    if bounded_reward == -3.0 and reward < -3.0:
        reasons.append("Step reward capped at low threshold of -3.0")
        
    reason_str = ", ".join(reasons)
    return round(bounded_reward, 2), reason_str
