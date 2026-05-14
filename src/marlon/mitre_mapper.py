def map_attack_to_mitre(action_text):

    # --------------------------------------------------
    # SQL Injection
    # --------------------------------------------------
    if "SQL Injection Detected" in action_text:

        return {
            "technique": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access"
        }

    # --------------------------------------------------
    # HTTP probing
    # --------------------------------------------------
    elif "HTTP 200" in action_text:

        return {
            "technique": "T1595",
            "name": "Active Scanning",
            "tactic": "Reconnaissance"
        }

    # --------------------------------------------------
    # Port discovery
    # --------------------------------------------------
    elif "Port 3306 Open" in action_text:

        return {
            "technique": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery"
        }

    # --------------------------------------------------
    # Lateral movement
    # --------------------------------------------------
    elif "Attack Node" in action_text:

        return {
            "technique": "T1021",
            "name": "Remote Services",
            "tactic": "Lateral Movement"
        }

    return None
