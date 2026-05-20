"""
backend/simulation_engine.py
----------------------------
Executes steps of the Cyber-MARL simulation, targets vulnerable services,
determines success probabilities, handles defender mitigations, and updates state.
"""

import time
import numpy as np
from datetime import datetime

from src.marlon.mitre_mapper import map_attack_to_mitre
from src.marlon.real_scan import scan_local_services
from src.marlon.attack_engine import probe_http_service, probe_tcp_service
from src.marlon.dvwa_tester import test_basic_sqli

from utils.constants import (
    NODE_MAPPING, VULNERABILITY_DB, DETECTION_RULES, ASSET_CRITICALITY, REAL_SERVICES
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

    # 1. Attacker action prediction
    action, _ = attacker_model.predict(obs, deterministic=False)
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
        def_action, _ = defender_model.predict(obs, deterministic=False)

    # Base telemetry vars
    risk_score_live = metrics.get("risk_score", 0.0)
    threat_level = metrics.get("threat_level", "LOW")
    attack_stage = metrics.get("attack_stage", "Idle")
    
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
        action_text = f"Attack Node {node_id}"
        
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

        technique_id = vuln_info.get("mitre", "UNKNOWN")
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
                        if technique_id not in target_node["techniques"]:
                            target_node["techniques"].append(technique_id)
                        p_str = str(port) if port else "N/A"
                        if p_str not in target_node["ports"]:
                            target_node["ports"].append(p_str)
                        target_node["last_event"] = f"Exploit Succeeded: {technique_id}"
                        target_node["compromise_stage"] = attack_stage
                        target_node["severity"] = vuln_info.get("severity", "LOW")
                else:
                    # Exploit failed, revert env state compromise
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
            # Internal node lateral movements
            metrics["successful_attacks"] += 1
            metrics["compromised_assets"].add(target_system)
            if node_id in nodes_state:
                target_node = nodes_state[node_id]
                target_node["status"] = "compromised"
                target_node["attacker_present"] = True
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
    if action >= env.node_count:
        metrics["defense_actions_count"] += 1
        action_text = "Defender Action"
        defender_target = int(def_action) % env.node_count
        
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
                    node_state["status"] = "contained"
                    node_state["attacker_present"] = False
                    node_state["defender_action"] = "isolate"
                    node_state["last_event"] = "Contained by Defender isolation"

                # Background reward increment
                reward += 6
                reward += max(0, 12 - compromised_count)
                reward -= metrics["persistence_score"] * 0.15

                metrics["containment_pressure_score"] += (len(compromised_nodes) * 2.5) + (metrics["critical_alerts"] * 0.6) + (metrics["persistence_score"] * 0.2)
                metrics["containment_pressure_score"] = max(0.0, metrics["containment_pressure_score"] - metrics["successful_defenses"] * 0.15)
                
                # Neighbor cleanup
                execute_adjacent_cleanup(highest_risk_node, obs, env.graph, env.node_count, nodes_state)
                
                current_compromised = int(np.sum(obs))
                compromised_count = current_compromised
            else:
                metrics["failed_defenses"] += 1
                reward -= 4
                if highest_risk_node in nodes_state:
                    nodes_state[highest_risk_node]["last_event"] = "Mitigation attempt failed"

    # 3. Decay & Momentum calculations
    previous_risk = float(metrics["risk_score"])
    logged_techniques = list(metrics["ioc_techniques"])
    dc_compromised = (nodes_state[4]["status"] == "compromised")
    db_or_srv_root = (nodes_state[2]["status"] == "compromised" or nodes_state[3]["status"] == "compromised")

    # Sequential attack stage progression
    attack_stage = get_next_attack_stage(
        current_stage=attack_stage,
        step=step,
        compromised_count=compromised_count,
        logged_techniques=logged_techniques,
        dc_compromised=dc_compromised,
        db_or_srv_root=db_or_srv_root,
        persistence_score=metrics["persistence_score"]
    )
    
    # Persistence score updating
    if attack_stage == "Persistence":
        metrics["persistence_score"] += max(1.0, 3.0 - (metrics["successful_defenses"] * 0.08))
    elif attack_stage == "Lateral Movement":
        metrics["persistence_score"] += max(1.0, 2.0 - (metrics["successful_defenses"] * 0.05))
    elif attack_stage == "Initial Access":
        metrics["persistence_score"] += 1.0

    metrics["persistence_score"] = max(0.0, metrics["persistence_score"] - metrics["successful_defenses"] * 0.12 - metrics["defense_actions_count"] * 0.05)
    metrics["attack_stage"] = attack_stage
    
    # Live risk scoring
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

    # Normalize threat level
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

    # Anomaly pressure
    metrics["anomaly_pressure_score"] += (len(metrics["ioc_ports"]) * 1.5) + (len(metrics["ioc_techniques"]) * 2.5) + (metrics["critical_alerts"] * 0.8) + (metrics["high_severity_events"] * 0.5)
    if threat_level == "CRITICAL":
        metrics["anomaly_pressure_score"] += 4
    elif threat_level == "HIGH":
        metrics["anomaly_pressure_score"] += 2
    metrics["anomaly_pressure_score"] = max(0.0, metrics["anomaly_pressure_score"] - metrics["successful_defenses"] * 0.12)

    # Threat Volatility & correlation
    metrics["threat_volatility_score"] = max(0.0, metrics["threat_volatility_score"] + (metrics["threat_momentum_score"] * 0.08) + (metrics["critical_alerts"] * 0.6) + (metrics["high_severity_events"] * 0.4) + (metrics["lateral_movement_count"] * 0.7) - (metrics["successful_defenses"] * 0.18))
    
    correlation_delta = len(metrics["ioc_techniques"]) * 1.8 + len(metrics["ioc_ports"]) * 1.2 + metrics["lateral_movement_count"] * 1.5 + metrics["persistence_score"] * 0.4
    if "Recon" in metrics["observed_attack_stages"] and "Discovery" in metrics["observed_attack_stages"]:
        correlation_delta += 4
    if "Initial Access" in metrics["observed_attack_stages"] and "Lateral Movement" in metrics["observed_attack_stages"]:
        correlation_delta += 6
    if "Persistence" in metrics["observed_attack_stages"]:
        correlation_delta += 8
    if threat_level == "CRITICAL":
        correlation_delta += 8
    elif threat_level == "HIGH":
        correlation_delta += 4
    metrics["threat_correlation_score"] = max(0.0, metrics["threat_correlation_score"] + correlation_delta - metrics["successful_defenses"] * 0.85)

    # Threat Momentum
    if threat_level == "CRITICAL":
        metrics["threat_momentum_score"] += max(1.0, 4.0 - (metrics["successful_defenses"] * 0.15))
    elif threat_level == "HIGH":
        metrics["threat_momentum_score"] += max(1.0, 2.0 - (metrics["successful_defenses"] * 0.08))
    if attack_stage == "Persistence":
        metrics["threat_momentum_score"] += max(2.0, 5.0 - (metrics["defense_actions_count"] * 0.12))
    elif attack_stage == "Lateral Movement":
        metrics["threat_momentum_score"] += max(1.0, 3.0 - (metrics["successful_defenses"] * 0.10))
    metrics["threat_momentum_score"] = max(0.0, metrics["threat_momentum_score"] - metrics["successful_defenses"] * 0.35 - metrics["defense_actions_count"] * 0.05)

    # 4. Explainable reward evaluation
    reward_delta, reward_reason = calculate_step_reward(
        is_defender_action=(action >= env.node_count),
        defense_success=is_def_success,
        compromised_count=compromised_count,
        previous_compromised=previous_compromised,
        persistence_score=metrics["persistence_score"],
        threat_momentum_score=metrics["threat_momentum_score"],
        successful_defenses=metrics["successful_defenses"]
    )
    
    # Accumulate reward and map logs
    metrics["total_reward"] = round(float(metrics.get("total_reward", 0.0) + reward_delta), 2)
    state["simulation"]["reward"] = metrics["total_reward"]
    
    # 5. Build and publish canonical event
    is_attacker = (action < env.node_count)
    event_severity = threat_level
    event_type = attack_stage if is_attacker else "Mitigation"
    event_node = target_system if is_attacker else f"Mitigation Node {defender_target}"
    
    explanation = f"{action_text}. Reward Reason: {reward_reason}" if is_attacker else f"Defender isolation target {defender_target}. Reward Reason: {reward_reason}"

    # Calculate dynamic alert confidence
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

    event = build_canonical_event(
        step=step,
        severity=event_severity,
        event_type=event_type,
        node=event_node,
        source="Attacker" if is_attacker else "SOC",
        destination=event_node if is_attacker else "Clean",
        technique=technique_id if is_attacker else "",
        cve=vuln_info.get("cve", "N/A"),
        risk_delta=risk_delta,
        reward_delta=reward_delta,
        compromise_count=compromised_count,
        message=explanation,
        # Backward compatibility extra fields
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
        explanation=explanation
    )
    
    # Push event through centralized bus
    push_event(state, event)

    # 6. Metrics and Aggregations
    metrics["observed_attack_stages"].add(attack_stage)
    metrics["structured_events"].append(event)
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    metrics["timeline_data"].insert(0, {
        "Time": timestamp,
        "Stage": attack_stage if is_attacker else "Mitigation",
        "Threat": threat_level,
        "Event": action_text,
    })

    metrics["threat_history"].append(metrics["critical_alerts"])
    metrics["compromise_history"].append(compromised_count)
    metrics["defense_history"].append(metrics["successful_defenses"])
    metrics["momentum_history"].append(metrics["threat_momentum_score"])
    metrics["step_history"].append(step)

    # Recalculate operational totals using telemetry engine
    update_telemetry_metrics(state)

    return obs
