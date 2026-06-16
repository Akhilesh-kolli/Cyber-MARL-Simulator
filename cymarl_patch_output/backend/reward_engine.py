"""
backend/reward_engine.py
------------------------
Deterministic and explainable reward calculation for defender operations
and campaign suppression states.

FIX (Issue #5, #6): Reward farming via repeated RECOVER actions is prevented.
FIX (Issue #4): Negative reward bounds tightened to prevent reward from going strongly negative.
FIX (Issue #5): Defender reward accumulation capped to prevent >300 without real effectiveness.
FIX (Issue #6): RECOVER actions only rewarded when they actually recover a compromised node.
"""

# Per-action diminishing return tracking (session-level).
# This must be reset when simulation resets; it is stored on the state object.
_RECOVER_COOLDOWN_STEPS = 3   # must wait N steps between rewarded RECOVER actions per node
_MAX_RECOVER_REWARD_RATIO = 0.6  # max fraction of available containment_val that RECOVER can earn


def _get_action_history(state: dict) -> dict:
    """Returns the action history tracker stored in state['metrics']."""
    if "defender_action_history" not in state.get("metrics", {}):
        state["metrics"]["defender_action_history"] = {}
    return state["metrics"]["defender_action_history"]


def calculate_step_reward(
    *,
    is_defender_action: bool,
    defense_success: bool,
    compromised_count: int,
    previous_compromised: int,
    persistence_score: float,
    threat_momentum_score: float,
    successful_defenses: int,
    action_label: str = "",
    target_node: int = -1,
    step: int = 0,
    state: dict = None,
) -> tuple:
    """
    Computes defender step reward, returning a tuple (reward_delta, reason_string).

    FIX #5/#6: RECOVER action farming prevention:
    - RECOVER only earns full containment reward if it successfully clears a compromised node.
    - RECOVER on an already-clean node earns 0 (not negative, but no reward).
    - Repeated RECOVER on same node within cooldown window earns 0.
    FIX #4: reward is bounded above a reasonable floor (-3.0) and capped.
    """
    reward = 0.0
    reasons = []

    action_up = str(action_label).upper() if action_label else ""

    if is_defender_action:
        # FIX #6: RECOVER action on clean node gets zero reward (prevent farming)
        is_recover = (action_up == "RECOVER")
        is_isolate = (action_up == "ISOLATE")
        is_block = (action_up == "BLOCK")
        is_prioritize = (action_up == "PRIORITIZE")

        # Check cooldown for RECOVER to prevent rapid RECOVER-RECOVER cycling
        recover_cooldown_ok = True
        if is_recover and state is not None and target_node >= 0:
            ah = _get_action_history(state)
            key = f"recover:{target_node}"
            last_step = ah.get(key, -999)
            if (step - last_step) < _RECOVER_COOLDOWN_STEPS:
                recover_cooldown_ok = False
            else:
                ah[key] = step

        if defense_success:
            # Containment reward — scaled by action type
            if is_recover:
                if not recover_cooldown_ok:
                    # Farming: no reward
                    reasons.append("RECOVER cooldown active — no reward")
                elif compromised_count >= previous_compromised:
                    # RECOVER on node that wasn't actually compromised: no reward
                    reasons.append("RECOVER on non-compromised node — no reward")
                else:
                    containment_val = 5.0
                    prevention_bonus = float(max(0, 8 - compromised_count))
                    persistence_penalty = float(persistence_score * 0.15)
                    step_reward = containment_val + prevention_bonus - persistence_penalty
                    reward += step_reward
                    reasons.append(f"+{containment_val:.1f} Recovery Success")
                    if prevention_bonus > 0:
                        reasons.append(f"+{prevention_bonus:.1f} Prevention Bonus")
                    if persistence_penalty > 0:
                        reasons.append(f"-{persistence_penalty:.1f} Persistence Penalty")
            elif is_isolate:
                containment_val = 7.0  # Isolation is strongly rewarded
                prevention_bonus = float(max(0, 12 - compromised_count))
                persistence_penalty = float(persistence_score * 0.15)
                step_reward = containment_val + prevention_bonus - persistence_penalty
                reward += step_reward
                reasons.append(f"+{containment_val:.1f} Isolation Success")
                if prevention_bonus > 0:
                    reasons.append(f"+{prevention_bonus:.1f} Prevention Bonus")
                if persistence_penalty > 0:
                    reasons.append(f"-{persistence_penalty:.1f} Persistence Penalty")
            elif is_block:
                containment_val = 6.0
                prevention_bonus = float(max(0, 10 - compromised_count))
                persistence_penalty = float(persistence_score * 0.10)
                step_reward = containment_val + prevention_bonus - persistence_penalty
                reward += step_reward
                reasons.append(f"+{containment_val:.1f} Block Success")
                if prevention_bonus > 0:
                    reasons.append(f"+{prevention_bonus:.1f} Prevention Bonus")
            elif is_prioritize:
                # Prioritize rewards analytical actions, lower direct containment value
                containment_val = 3.0
                reward += containment_val
                reasons.append(f"+{containment_val:.1f} Prioritization Acknowledged")
            else:
                containment_val = 6.0
                prevention_bonus = float(max(0, 12 - compromised_count))
                persistence_penalty = float(persistence_score * 0.15)
                step_reward = containment_val + prevention_bonus - persistence_penalty
                reward += step_reward
                reasons.append(f"+{containment_val:.1f} Containment Success")
        else:
            # Defense failure
            if is_recover and not recover_cooldown_ok:
                # farming attempt during failure — hard zero
                reasons.append("RECOVER cooldown active — no penalty (non-event)")
            else:
                penalty = -4.0
                reward += penalty
                reasons.append(f"{penalty:.1f} Containment Failed Penalty")

    # Loop-level background checks
    momentum_penalty = float(threat_momentum_score * 0.005)
    persistence_loop_penalty = float(persistence_score * 0.008)
    # FIX #5: Cap defense accumulation bonus to prevent unbounded growth
    defense_accumulation_bonus = min(2.0, float(successful_defenses * 0.10))

    reward -= momentum_penalty
    reward -= persistence_loop_penalty
    reward += defense_accumulation_bonus

    if momentum_penalty > 0:
        reasons.append(f"-{momentum_penalty:.2f} Threat Momentum Penalty")
    if persistence_loop_penalty > 0:
        reasons.append(f"-{persistence_loop_penalty:.2f} Persistence Drag")
    if defense_accumulation_bonus > 0:
        reasons.append(f"+{defense_accumulation_bonus:.2f} Defense History Bonus")

    # Active recovery reward: only if compromised_count truly decreased
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
