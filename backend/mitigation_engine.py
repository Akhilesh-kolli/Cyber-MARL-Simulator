"""
backend/mitigation_engine.py
----------------------------
Handles defender targeting, containment effectiveness, adjacent neighbor cleanup,
and probabilistic mitigation checks.
"""

import numpy as np
from utils.constants import NODE_MAPPING

def get_highest_risk_compromised_node(
    compromised_nodes: list,
    defender_target: int,
    threat_level: str,
    attack_stage: str,
    compromised_assets: set
) -> int:
    """
    Selects target compromised node using RL prediction with heuristic risk fallbacks.
    """
    if not compromised_nodes:
        return -1

    if defender_target in compromised_nodes:
        return defender_target

    priority_targets = []
    for node in compromised_nodes:
        node_risk = 0
        if threat_level == "CRITICAL":
            node_risk += 5
        elif threat_level == "HIGH":
            node_risk += 3

        if attack_stage == "Persistence":
            node_risk += 4
        elif attack_stage == "Lateral Movement":
            node_risk += 2

        if NODE_MAPPING.get(node) in compromised_assets:
            node_risk += 1

        priority_targets.append((node, node_risk))

    return max(priority_targets, key=lambda x: x[1])[0]


def calculate_defense_success_probability(
    compromised_count: int,
    threat_momentum_score: float,
    persistence_score: float,
    successful_defenses: int,
    defense_actions_count: int
) -> float:
    """
    Calculates adaptive probability of successful mitigation.
    """
    prob = (
        0.72
        - (compromised_count * 0.04)
        - (threat_momentum_score * 0.002)
        - (persistence_score * 0.003)
        + (successful_defenses * 0.015)
        + (defense_actions_count * 0.008)
    )
    # Apply baseline bounds
    return float(max(0.35, min(0.88, prob)))


def execute_adjacent_cleanup(
    highest_risk_node: int,
    obs: np.ndarray,
    graph_matrix,
    node_count: int,
    nodes_state: dict
):
    """
    Probabilistically attempts to contain neighbors of the contained node (45% probability).
    """
    for neighbor in range(node_count):
        if graph_matrix[highest_risk_node][neighbor] == 1:
            containment_roll = np.random.random()
            if containment_roll <= 0.45:
                was_compromised = (obs[neighbor] == 1)
                obs[neighbor] = 0
                if was_compromised and neighbor in nodes_state:
                    neigh_node = nodes_state[neighbor]
                    neigh_node["status"] = "contained"
                    neigh_node["last_event"] = "Cleaned up by adjacent neighbor containment"
