"""
backend/simulation_engine.py
----------------------------
Executes steps of the Cyber-MARL simulation, targets vulnerable services,
determines success probabilities, handles defender mitigations, and updates state.

FIX (Issue #8): Infrastructure card status now updated when assets are compromised.
FIX (Issue #9): Network topology node state synchronized with compromised/recovered/isolated.
FIX (Issue #10,#11): Attack Timeline uses real asset names; ATT&CK progression realistic.
FIX (Issue #12,#13): Timeline CVE column no longer receives DEFENDER-ACTION; source/dest populated.
FIX (Issue #23,#24,#25): Executive metrics (Momentum, Volatility, Containment) reflect simulation state.
"""

import time
import numpy as np
from datetime import datetime

from src.marlon.mitre_mapper import map_attack_to_mitre
from src.marlon.real_scan import scan_local_services
from src.marlon.attack_engine import probe_http_service, probe_tcp_service
from src.marlon.dvwa_tester import test_basic_sqli

from utils.constants import (
    NODE_MAPPING, VULNERABILITY_DB, DETECTION_RULES, ASSET_CRITICALITY, REAL_SERVICES,
    SIMULATION_NODES
)
from backend.event_bus import build_canonical_event, push_event
from backend.reward_engine import calculate_step_reward
from backend.risk_engine import (
    calculate_bounded_risk_score, get_next_attack_stage, get_dwell_time,
    get_incident_priority, get_incident_status, get_attacker_profile,
    get_soc_recommendation, get_alert_fatigue_score, get_attack_success_rate,
    get_dominant_technique
)
from backend.mitigation_engine import (
    get_highest_risk_compromised_node, calculate_defense_success_probability,
    execute_adjacent_cleanup
)
from backend.telemetry_engine import update_telemetry_metrics
from backend.graph_engine import generate_network_graph
from analytics.bounded_metrics import sigmoid_scale, clamp_0_95


# ---------------------------------------------------------------------------
# ATT&CK progression chain: realistic multi-stage progression
# ---------------------------------------------------------------------------
# Each stage maps to the MITRE technique most commonly observed at that phase.
_STAGE_TECHNIQUE_MAP = {
    "Reconnaissance":         "T1595",   # Active Scanning
    "Initial Access":         "T1190",   # Exploit Public-Facing Application
    "Execution":              "T1059",   # Command & Scripting Interpreter
    "Persistence":            "T1547",   # Boot/Logon Autostart
    "Privilege Escalation":   "T1055",   # Process Injection
    "Defense Evasion":        "T1562",   # Impair Defenses
    "Credential Access":      "T1003",   # OS Credential Dumping
    "Discovery":              "T1046",   # Network Service Discovery
    "Lateral Movement":       "T1021",   # Remote Services
    "Collection":             "T1005",   # Data from Local System
    "Exfiltration":           "T1041",   # Exfiltration Over C2 Channel
    "Command and Control":    "T1105",   # Ingress Tool Transfer
    "Impact":                 "T1486",   # Data Encrypted for Impact
    "Idle":                   "T1595",
}


def _pick_stage_technique(attack_stage: str, existing_techniques: set) -> str:
    """
    Returns the canonical ATT&CK technique for the current stage.
    If already seen this step, returns the same (realistic repetition).
    Avoids returning UNKNOWN or N/A.
    """
    primary = _STAGE_TECHNIQUE_MAP.get(attack_stage, "T1595")
    return primary


def execute_simulation_step(
    step: int,
    state: dict,
    env,
    attacker_model,
    defender_model,
    obs,
    G,
    dvwa_logged_in: bool
) -> tuple:
    """
    Executes a single step of the MARL simulation.
    Updates the simulation_state dictionary and returns the next observation.
    """
    metrics = state["metrics"]
    nodes_state = state["nodes"]

    # ------------------------------------------
    # Reachable nodes helper for lateral movement
    # ------------------------------------------
    def get_reachable_nodes(obs_state):
        comp_nodes = [i for i in range(env.node_count) if obs_state[i] == 1]
        reachable = set()
        for node in comp_nodes:
            neighbors = list(G.neighbors(node))
            for n in neighbors:
                if obs_state[n] == 0:
                    reachable.add(n)
        return list(reachable)

    def _adapt_obs_for_model(obs_input, model_obj):
        try:
            expected_shape = None
            if hasattr(model_obj, "observation_space"):
                os = getattr(model_obj, "observation_space")
                if hasattr(os, "shape") and os.shape:
                    expected_shape = int(os.shape[0])
            elif hasattr(model_obj, "policy") and hasattr(model_obj.policy, "observation_space"):
                os = model_obj.policy.observation_space
                if hasattr(os, "shape") and os.shape:
                    expected_shape = int(os.shape[0])

            if expected_shape is None:
                return obs_input

            if hasattr(obs_input, "__len__") and len(obs_input) == expected_shape:
                return obs_input

            if expected_shape % env.node_count == 0:
                features_per_node = expected_shape // env.node_count
                new_obs = np.zeros(expected_shape, dtype=np.float32)
                for i in range(env.node_count):
                    base = i * features_per_node
                    try:
                        comp = float(obs_input[i])
                    except Exception:
                        comp = 0.0
                    if features_per_node > 0:
                        new_obs[base + 0] = comp
                    if features_per_node > 1:
                        new_obs[base + 1] = 0.0
                    if features_per_node > 2:
                        new_obs[base + 2] = 0.0
                    if features_per_node > 3:
                        new_obs[base + 3] = 0.0
                    if features_per_node > 4:
                        cvss = None
                        if hasattr(env, "cvss_scores"):
                            try:
                                cvss = env.cvss_scores[i]
                            except Exception:
                                try:
                                    cvss = env.cvss_scores.get(i, None)
                                except Exception:
                                    cvss = None
                        new_obs[base + 4] = float(cvss) / 10.0 if cvss is not None else 0.5
                    if features_per_node > 5:
                        new_obs[base + 5] = float(i in getattr(env, "critical_nodes", set()))
                return new_obs
        except Exception:
            return obs_input
        return obs_input

    # 1. Attacker action prediction
    try:
        att_obs = _adapt_obs_for_model(obs, attacker_model)
    except Exception:
        att_obs = obs
    action, _ = attacker_model.predict(att_obs, deterministic=False)
    reachable_nodes = get_reachable_nodes(obs)
    if len(reachable_nodes) > 0:
        predicted_node = int(action)
        if predicted_node not in reachable_nodes:
            action = np.random.choice(reachable_nodes)

    previous_compromised = int(np.sum(obs))

    # Step the environment
    obs, reward, done, truncated, _ = env.step(action)
    current_compromised = int(np.sum(obs))
    compromised_count = current_compromised

    # 2. Defender action prediction
    def_action = 0
    if not done:
        try:
            def_obs = _adapt_obs_for_model(obs, defender_model)
        except Exception:
            def_obs = obs
        def_action, _ = defender_model.predict(def_obs, deterministic=False)

    # Base telemetry vars
    risk_score_live = metrics.get("risk_score", 0.0)
    threat_level = metrics.get("threat_level", "LOW")
    attack_stage = metrics.get("attack_stage", "Idle")
    mitre_data = None
    defender_target = -1

    # ------------------------------------------
    # Attacker Action execution
    # ------------------------------------------
    node_id = -1
    target_system = "SOC"
    attack_result = None
    detection_info = {}
    vuln_info = {}
    action_text = "Defender Action"
    technique_id = "N/A"
    cvss_score = 0.0
    port = None

    if action < env.node_count:
        metrics["attack_attempts"] += 1
        node_id = int(action)
        target_system = NODE_MAPPING.get(node_id, "Unknown")
        asset_weight = ASSET_CRITICALITY.get(target_system, 1)
        vuln_info = VULNERABILITY_DB.get(target_system, {})
        action_text = f"Attack {target_system}"  # FIX #11: use real asset name

        # Service checks
        real_ports = {0: 5000, 1: 8080, 2: 3307}
        if node_id in real_ports:
            port = real_ports[node_id]
            metrics["ioc_ports"].add(str(port))

            if port in [5000, 8080]:
                attack_result = probe_http_service(port)
                if port == 8080 and dvwa_logged_in:
                    sqli_result = test_basic_sqli()
                    if sqli_result.get("possible_sqli"):
                        attack_result["vulnerability"] = "SQL Injection Detected"
            elif port == 3307:
                attack_result = probe_tcp_service(port)

        # FIX #10: Use stage-driven realistic technique progression (not random T1562 domination)
        technique_id = _pick_stage_technique(attack_stage, metrics["ioc_techniques"])

        # Override with vulnerability-specific technique if available and relevant
        vuln_technique = vuln_info.get("mitre", "")
        if vuln_technique and attack_stage in ("Initial Access", "Execution"):
            technique_id = vuln_technique

        cvss_score = vuln_info.get("cvss", 5.0)
        attack_momentum = min(0.20, metrics["lateral_movement_count"] * 0.015)
        exploit_probability = min(0.90, (cvss_score / 12) + (asset_weight * 0.04) + attack_momentum)

        # Apply probabilities to outcome
        if attack_result:
            if current_compromised > previous_compromised:
                exploit_roll = np.random.random()
                if exploit_roll <= exploit_probability:
                    metrics["successful_attacks"] += 1
                    metrics["compromised_assets"].add(target_system)

                    if node_id in nodes_state:
                        target_node = nodes_state[node_id]
                        target_node["status"] = "compromised"
                        target_node["attacker_present"] = True
                        # FIX #8: infrastructure card status sync
                        target_node["card_status"] = "COMPROMISED"
                        if technique_id not in target_node["techniques"]:
                            target_node["techniques"].append(technique_id)
                        p_str = str(port) if port else "N/A"
                        if p_str not in target_node["ports"]:
                            target_node["ports"].append(p_str)
                        target_node["last_event"] = f"Exploit Succeeded: {technique_id}"
                        target_node["compromise_stage"] = attack_stage
                        target_node["severity"] = vuln_info.get("severity", "LOW")
                else:
                    obs[node_id] = 0
                    current_compromised = int(np.sum(obs))
                    compromised_count = current_compromised

                if "status_code" in attack_result:
                    action_text += f" | HTTP {attack_result['status_code']}"
                    metrics["ioc_ports"].add("80")
                    if "vulnerability" in attack_result:
                        action_text += f" | {attack_result['vulnerability']}"
                elif "port" in attack_result:
                    action_text += f" | Port {attack_result['port']} Open"
                    metrics["ioc_ports"].add(str(attack_result["port"]))
            else:
                action_text += " | Service Unreachable"

        elif current_compromised > previous_compromised:
            metrics["successful_attacks"] += 1
            metrics["compromised_assets"].add(target_system)
            if node_id in nodes_state:
                target_node = nodes_state[node_id]
                target_node["status"] = "compromised"
                target_node["attacker_present"] = True
                # FIX #8: keep infrastructure card in sync
                target_node["card_status"] = "COMPROMISED"
                if technique_id not in target_node["techniques"]:
                    target_node["techniques"].append(technique_id)
                p_str = "N/A"
                if p_str not in target_node["ports"]:
                    target_node["ports"].append(p_str)
                target_node["last_event"] = f"Internal Compromise: {technique_id}"
                target_node["compromise_stage"] = attack_stage
                target_node["severity"] = vuln_info.get("severity", "LOW")

        # Map mitre attacks
        mitre_data = map_attack_to_mitre(action_text)
        if mitre_data:
            action_text += f" | {mitre_data['technique']} {mitre_data['name']} [{mitre_data['tactic']}]"
            mapped_technique = mitre_data.get("technique", "")
            if mapped_technique:
                if mapped_technique not in metrics["technique_counts"]:
                    metrics["technique_counts"][mapped_technique] = 0
                metrics["technique_counts"][mapped_technique] += 1
                metrics["ioc_techniques"].add(mapped_technique)

        # Always register the stage-based technique too
        if technique_id and technique_id not in ("N/A", "UNKNOWN"):
            if technique_id not in metrics["technique_counts"]:
                metrics["technique_counts"][technique_id] = 0
            metrics["technique_counts"][technique_id] += 1
            metrics["ioc_techniques"].add(technique_id)

        attack_name = ""
        if "SQL Injection" in action_text:
            attack_name = "SQL Injection"
            metrics["sqli_detected"] += 1
        elif "Active Scanning" in action_text:
            attack_name = "Active Scanning"
            metrics["recon_events"] += 1
        elif "Service Discovery" in action_text:
            attack_name = "Network Service Discovery"
            metrics["discovery_events"] += 1
        elif "Remote Services" in action_text:
            attack_name = "Remote Services"
            metrics["lateral_movement_count"] += 1

        if attack_name:
            detection_info = DETECTION_RULES.get(attack_name, {})

    # ------------------------------------------
    # Defender Containment execution
    # ------------------------------------------
    is_def_success = False
    action_label = None
    if not done:
        metrics["defense_actions_count"] += 1
        action_text_def = "Defender Action"
        defender_target = int(def_action) % env.node_count
        try:
            action_type_idx = int(def_action) // env.node_count
        except Exception:
            action_type_idx = 0
        ACTION_LABELS = {0: "ISOLATE", 1: "RECOVER", 2: "BLOCK", 3: "PRIORITIZE"}
        action_label = ACTION_LABELS.get(action_type_idx, "ISOLATE")
        if action_label == "ISOLATE":
            metrics["isolation_actions"] = metrics.get("isolation_actions", 0) + 1
        elif action_label == "RECOVER":
            metrics["recovery_actions"] = metrics.get("recovery_actions", 0) + 1
        elif action_label == "BLOCK":
            metrics["block_actions"] = metrics.get("block_actions", 0) + 1
        elif action_label == "PRIORITIZE":
            metrics["priority_actions"] = metrics.get("priority_actions", 0) + 1

        compromised_nodes = [i for i in range(env.node_count) if obs[i] == 1]
        highest_risk_node = get_highest_risk_compromised_node(
            compromised_nodes, defender_target, threat_level, attack_stage, metrics["compromised_assets"]
        )

        if highest_risk_node != -1:
            defense_success_probability = calculate_defense_success_probability(
                compromised_count, metrics["threat_momentum_score"], metrics["persistence_score"],
                metrics["successful_defenses"], metrics["defense_actions_count"]
            )

            defense_roll = np.random.random()
            if defense_roll <= defense_success_probability:
                is_def_success = True
                obs[highest_risk_node] = 0
                contained_asset = NODE_MAPPING.get(highest_risk_node)
                if contained_asset in metrics["compromised_assets"]:
                    metrics["compromised_assets"].remove(contained_asset)

                metrics["successful_defenses"] += 1
                if highest_risk_node in nodes_state:
                    node_state = nodes_state[highest_risk_node]
                    node_state["attacker_present"] = False
                    node_state["defender_action"] = str(action_label).lower() if action_label else "isolate"
                    if action_label == "ISOLATE":
                        node_state["status"] = "contained"
                        node_state["isolated"] = True
                        # FIX #8: sync card status
                        node_state["card_status"] = "ISOLATED"
                        node_state["last_event"] = "Contained by Defender isolation"
                    elif action_label == "RECOVER":
                        node_state["status"] = "healthy"
                        node_state["recovered"] = True
                        # FIX #8: sync card status
                        node_state["card_status"] = "ONLINE"
                        node_state["last_event"] = "Recovered by Defender action"
                    elif action_label == "BLOCK":
                        node_state["blocked"] = True
                        node_state["card_status"] = "BLOCKED"
                        node_state["last_event"] = "Network path blocked by Defender"
                    elif action_label == "PRIORITIZE":
                        node_state["priority"] = True
                        node_state["card_status"] = "PRIORITY"
                        node_state["last_event"] = "Node prioritized by Defender"

                reward += 6
                reward += max(0, 12 - compromised_count)
                reward -= metrics["persistence_score"] * 0.15

                containment_increment = (len(compromised_nodes) * 1.2) + (metrics["critical_alerts"] * 0.2) + (metrics["persistence_score"] * 0.1)
                defense_relief = (metrics["successful_defenses"] * 1.5) + (metrics["defense_actions_count"] * 0.3)
                metrics["containment_pressure_score"] = max(0.0, min(85.0, metrics["containment_pressure_score"] + containment_increment - defense_relief))

                execute_adjacent_cleanup(highest_risk_node, obs, env.graph, env.node_count, nodes_state)

                current_compromised = int(np.sum(obs))
                compromised_count = current_compromised
            else:
                metrics["failed_defenses"] += 1
                reward -= 4
                if highest_risk_node in nodes_state:
                    nodes_state[highest_risk_node]["last_event"] = "Mitigation attempt failed"

    # FIX #9: Sync topology node state — any node in obs[i]==1 that isn't in nodes_state
    # should be marked accordingly. Also ensure "ONLINE" for clean nodes.
    for ni in range(env.node_count):
        if ni in nodes_state:
            nd = nodes_state[ni]
            if obs[ni] == 1 and nd.get("status") not in ("compromised", "contained"):
                nd["status"] = "compromised"
                nd["card_status"] = "COMPROMISED"
            elif obs[ni] == 0 and nd.get("status") == "compromised":
                # obs says clean but state says compromised — trust obs (env is authoritative)
                nd["status"] = "healthy"
                nd["card_status"] = "ONLINE"
            # Ensure any healthy node that has never been touched shows ONLINE
            if nd.get("status") == "healthy" and "card_status" not in nd:
                nd["card_status"] = "ONLINE"

    # 3. Decay & Momentum calculations
    previous_risk = float(metrics["risk_score"])
    logged_techniques = list(metrics["ioc_techniques"])
    dc_compromised = (nodes_state[4]["status"] == "compromised")
    db_or_srv_root = (nodes_state[2]["status"] == "compromised" or nodes_state[3]["status"] == "compromised")

    attack_stage = get_next_attack_stage(
        current_stage=attack_stage,
        step=step,
        compromised_count=compromised_count,
        logged_techniques=logged_techniques,
        dc_compromised=dc_compromised,
        db_or_srv_root=db_or_srv_root,
        persistence_score=metrics["persistence_score"]
    )

    if attack_stage == "Persistence":
        metrics["persistence_score"] += max(1.0, 3.0 - (metrics["successful_defenses"] * 0.08))
    elif attack_stage == "Lateral Movement":
        metrics["persistence_score"] += max(1.0, 2.0 - (metrics["successful_defenses"] * 0.05))
    elif attack_stage == "Initial Access":
        metrics["persistence_score"] += 1.0

    metrics["persistence_score"] = max(0.0, metrics["persistence_score"] - metrics["successful_defenses"] * 0.12 - metrics["defense_actions_count"] * 0.05)
    metrics["attack_stage"] = attack_stage

    estimated_dwell_time = get_dwell_time(compromised_count)
    privilege_escalation_count = 1 if db_or_srv_root else 0
    risk_score_live = calculate_bounded_risk_score(
        nodes=nodes_state,
        lateral_movement_count=metrics["lateral_movement_count"],
        privilege_escalation_count=privilege_escalation_count,
        persistence_score=metrics["persistence_score"],
        containment_failures=metrics["failed_defenses"],
        events=metrics["structured_events"],
        dwell_time=estimated_dwell_time,
        current_stage=attack_stage
    )
    state["risk"]["risk_score"] = risk_score_live
    metrics["risk_score"] = risk_score_live
    risk_delta = int(risk_score_live - previous_risk)

    if risk_score_live < 45:
        threat_level = "LOW"
    elif risk_score_live < 70:
        threat_level = "MEDIUM"
    elif risk_score_live < 90:
        threat_level = "HIGH"
    else:
        threat_level = "CRITICAL"

    if compromised_count >= 5 and metrics["high_severity_events"] >= 8:
        threat_level = "CRITICAL"
    metrics["threat_level"] = threat_level

    from analytics.bounded_metrics import clamp_0_95

    events_list = metrics.get("structured_events") or state.get("events", []) or []
    event_count = max(1, len(events_list))

    tech_counts = {}
    for e in events_list:
        t = e.get("technique")
        if t:
            tech_counts[t] = tech_counts.get(t, 0) + 1
    total_tech_occ = sum(tech_counts.values()) if tech_counts else 0
    technique_reuse = 0.0
    if total_tech_occ > 0:
        repeats = sum((c - 1) for c in tech_counts.values() if c > 1)
        technique_reuse = (repeats / total_tech_occ) * 100.0

    node_list = [e.get("node") for e in events_list if e.get("node")]
    node_reuse = 0.0
    if len(node_list) > 0:
        unique_nodes = len(set(node_list))
        node_reuse = ((len(node_list) - unique_nodes) / len(node_list)) * 100.0

    ioc_ports = metrics.get("ioc_ports", [])
    ioc_techs = metrics.get("ioc_techniques", [])
    ioc_count = len(ioc_ports) + len(ioc_techs)
    ioc_overlap = min(100.0, (ioc_count / event_count) * 100.0)

    stage_counts = {}
    for e in events_list:
        s = e.get("kill_chain") or e.get("event_type") or "Unknown"
        stage_counts[s] = stage_counts.get(s, 0) + 1
    stage_repeats = sum((c - 1) for c in stage_counts.values() if c > 1)
    stage_pattern_similarity = (stage_repeats / event_count) * 100.0

    correlation_raw = (
        (technique_reuse * 0.40)
        + (node_reuse * 0.25)
        + (ioc_overlap * 0.20)
        + (stage_pattern_similarity * 0.15)
    )

    defense_penalty = min(20.0, metrics.get("successful_defenses", 0) * 0.7)
    final_corr = max(0.0, correlation_raw - defense_penalty)
    metrics["threat_correlation_score"] = round(clamp_0_95(final_corr), 2)

    # ─── Threat Momentum ───
    # FIX #2/#23: Momentum must NOT collapse to 0 after exfiltration.
    # Use cumulative attack success and stage pressure as primary drivers.
    momentum_base = 0.0

    if attack_stage in ("Exfiltration", "Command and Control"):
        # FIX #2: Exfiltration stage keeps momentum elevated, not zero
        momentum_base = max(3.0, 6.0 - (metrics.get("successful_defenses", 0) * 0.06))
    elif attack_stage == "Persistence":
        momentum_base = max(1.5, 5.0 - (metrics.get("defense_actions_count", 0) * 0.08))
    elif attack_stage == "Lateral Movement":
        momentum_base = max(1.2, 4.0 - (metrics.get("successful_defenses", 0) * 0.08))
    elif attack_stage == "Execution":
        momentum_base = max(1.0, 3.0 - (metrics.get("successful_defenses", 0) * 0.07))
    else:
        momentum_base = max(0.8, 2.0 - (metrics.get("successful_defenses", 0) * 0.05))

    # Threat level amplifies momentum
    if threat_level == "CRITICAL":
        momentum_base += 1.5
    elif threat_level == "HIGH":
        momentum_base += 0.8

    # FIX #23: Also add contribution from cumulative attack successes (not just last-step)
    cumulative_attack_pressure = min(2.0, metrics.get("successful_attacks", 0) * 0.15)
    momentum_base += cumulative_attack_pressure

    defense_friction = (
        (metrics.get("successful_defenses", 0) * 0.35) +
        (metrics.get("defense_actions_count", 0) * 0.08)
    )

    raw_momentum = max(0.0, momentum_base - defense_friction)
    normalized_momentum = (raw_momentum / max(1.0, momentum_base + 2.5)) * 100.0
    defense_eff = metrics.get("defense_effectiveness", 0.0)
    momentum_dampened = normalized_momentum * (1.0 - (defense_eff / 200.0))
    # FIX #2: Once exfiltration has occurred, maintain a floor on momentum
    if attack_stage in ("Exfiltration", "Command and Control") and momentum_dampened < 15.0:
        momentum_dampened = 15.0
    metrics["threat_momentum_score"] = round(clamp_0_95(momentum_dampened), 2)

    # FIX #24: Threat Volatility must not stay at 0
    # Volatility = how much risk has changed recently (using risk history)
    step_history = metrics.get("step_history", [])
    risk_history = []
    for e in events_list[-10:]:  # last 10 events
        try:
            risk_history.append(float(e.get("risk_delta", 0)))
        except Exception:
            pass
    if len(risk_history) >= 2:
        import statistics
        try:
            vol_raw = statistics.stdev(risk_history) * 5.0
        except Exception:
            vol_raw = abs(risk_delta) * 3.0
    else:
        vol_raw = abs(risk_delta) * 3.0
    # Scale by threat level
    if threat_level == "CRITICAL":
        vol_raw += 20.0
    elif threat_level == "HIGH":
        vol_raw += 10.0
    metrics["threat_volatility_score"] = round(clamp_0_95(vol_raw), 2)

    # FIX #25: Containment Pressure must not stay at 0 during active incident
    if compromised_count > 0 or attack_stage not in ("Idle", "Reconnaissance"):
        # Ensure containment pressure reflects ongoing attack
        cp_floor = min(20.0, compromised_count * 5.0 + metrics.get("failed_defenses", 0) * 2.0)
        if metrics["containment_pressure_score"] < cp_floor:
            metrics["containment_pressure_score"] = cp_floor

    try:
        from analytics.anomaly_engine import update_anomaly_and_volatility
        update_anomaly_and_volatility(state, threat_level)
    except Exception:
        pass

    # 4. Explainable reward evaluation
    is_defender_action = (action_label is not None)
    reward_delta, reward_reason = calculate_step_reward(
        is_defender_action=is_defender_action,
        defense_success=is_def_success,
        compromised_count=compromised_count,
        previous_compromised=previous_compromised,
        persistence_score=metrics["persistence_score"],
        threat_momentum_score=metrics["threat_momentum_score"],
        successful_defenses=metrics["successful_defenses"],
        action_label=action_label or "",
        target_node=int(def_action) % env.node_count if not done else -1,
        step=step,
        state=state,
    )

    metrics["total_reward"] = round(float(metrics.get("total_reward", 0.0) + reward_delta), 2)
    state["simulation"]["reward"] = metrics["total_reward"]

    # 5. Build and publish canonical event
    is_defender_event = (action_label is not None)
    is_attacker = not is_defender_event
    event_severity = threat_level
    event_type = attack_stage if is_attacker else "Mitigation"

    # FIX #11: Use real asset names in event node field (event_bus.py handles Mitigation Node)
    event_node = target_system if is_attacker else NODE_MAPPING.get(defender_target, f"Node-{defender_target}")
    
    # FIX #13: Source and destination properly reflect attack paths
    if is_attacker:
        event_source = "Attacker"
        event_destination = target_system  # Where the attack targeted
    else:
        event_source = "SOC"
        event_destination = NODE_MAPPING.get(defender_target, "Network")

    explanation = (f"{action_text}. Reward Reason: {reward_reason}" if is_attacker
                   else f"Defender {action_label} on {event_node}. Reward Reason: {reward_reason}")

    alert_confidence = 45
    if threat_level == "CRITICAL":
        alert_confidence += 25
    elif threat_level == "HIGH":
        alert_confidence += 15
    elif threat_level == "MEDIUM":
        alert_confidence += 8

    if attack_stage == "Persistence":
        alert_confidence += 12
    elif attack_stage == "Lateral Movement":
        alert_confidence += 8
    elif attack_stage == "Initial Access":
        alert_confidence += 5

    alert_confidence += (len(metrics["ioc_techniques"]) * 1.5) + (len(metrics["ioc_ports"]) * 1.0) + (metrics["critical_alerts"] * 0.6) + (metrics["successful_defenses"] * 0.4) - (metrics["failed_defenses"] * 0.3)
    alert_confidence = max(25, min(int(alert_confidence + np.random.randint(-4, 5)), 100))

    event_summary = f"{attack_stage} event on {target_system}: {action_text}"
    if not is_attacker:
        event_summary = f"SOC {action_label} action on {event_node}"

    # FIX #12: CVE is passed as vuln CVE for attacker events only
    # For defender events, event_bus.py handles DEFENDER-ACTION assignment
    event_cve = vuln_info.get("cve", "N/A") if is_attacker else ""

    # FIX #3: risk_delta for event is the actual computed risk delta (not 0)
    event = build_canonical_event(
        step=step,
        severity=event_severity,
        event_type=event_type,
        node=event_node,
        source=event_source,
        destination=event_destination,
        technique=technique_id if is_attacker else "",
        cve=event_cve,
        risk_delta=risk_delta,   # FIX #3: actual risk delta, not 0
        reward_delta=reward_delta,
        compromise_count=compromised_count,
        message=explanation,
        actor="attacker" if is_attacker else "defender",
        node_id=node_id if is_attacker else defender_target,
        node_type=SIMULATION_NODES.get(node_id, "Unknown") if is_attacker else "Defender",
        service=target_system if is_attacker else "SOC",
        tactic=mitre_data.get("tactic", "") if mitre_data else "",
        mitre_name=mitre_data.get("name", "") if mitre_data else "",
        kill_chain=attack_stage if is_attacker else "Mitigation",
        threat=threat_level,
        port=port,
        cvss=vuln_info.get("cvss", None),
        status="success" if (is_attacker and compromised_count > previous_compromised) or (not is_attacker and is_def_success) else "failed",
        vulnerability=attack_result.get("vulnerability") if attack_result else "",
        detection_signature=detection_info.get("signature", "N/A"),
        detection_severity=detection_info.get("severity", "N/A"),
        detection_confidence=alert_confidence,
        timeline_weight=metrics["threat_momentum_score"] + metrics["persistence_score"] + metrics["threat_correlation_score"],
        explanation=explanation,
        event_summary=event_summary,
        defender_action=action_label if is_defender_event else None,
    )

    push_event(state, event)

    try:
        if is_defender_event:
            metrics["defender_reward"] = round(float(metrics.get("defender_reward", 0.0) + reward_delta), 2)
        else:
            metrics["attacker_reward"] = round(float(metrics.get("attacker_reward", 0.0) + reward_delta), 2)
    except Exception:
        pass

    # 6. Metrics and Aggregations
    metrics["observed_attack_stages"].add(attack_stage)
    metrics["structured_events"].append(event)

    timestamp = datetime.now().strftime("%H:%M:%S")
    # FIX #12: Timeline CVE column uses event CVE (DEFENDER-ACTION filtered out for display)
    # FIX #13: Add Source/Dest columns to timeline
    timeline_cve = event.get("cve", "NOT-APPLICABLE")
    if timeline_cve == "DEFENDER-ACTION":
        timeline_cve = "N/A"  # FIX #12: Don't show DEFENDER-ACTION in CVE column

    # FIX #10: Use stage-appropriate technique, not random T1562
    timeline_technique = event.get("technique", "")
    if timeline_technique.startswith("DEF:") or timeline_technique == "DEFENSIVE-OPS":
        timeline_technique = action_label or "DEFENSIVE-OPS"  # show action label for defender

    metrics["timeline_data"].insert(0, {
        "Time": timestamp,
        "Stage": event.get("kill_chain", attack_stage if is_attacker else "Mitigation"),
        "Threat": event.get("threat", threat_level),
        "Technique": timeline_technique,
        "CVE": timeline_cve,   # FIX #12: clean CVE
        "Summary": event.get("event_summary", event_summary),
        "Event": event.get("event", action_text),
        "Source": event_source,       # FIX #13: source asset
        "Target": event_destination,  # FIX #13: destination asset
    })

    metrics["threat_history"].append(metrics["critical_alerts"])
    metrics["compromise_history"].append(compromised_count)
    metrics["defense_history"].append(metrics["successful_defenses"])
    metrics["momentum_history"].append(metrics["threat_momentum_score"])
    metrics["step_history"].append(step)

    update_telemetry_metrics(state)

    return obs
