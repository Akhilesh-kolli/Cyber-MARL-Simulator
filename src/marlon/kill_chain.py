def map_kill_chain(action_text):

    # --------------------------------------------------
    # Initial Access
    # --------------------------------------------------
    if "SQL Injection Detected" in action_text:

        return "Initial Access"

    # --------------------------------------------------
    # Discovery
    # --------------------------------------------------
    if "Port 3306 Open" in action_text:

        return "Discovery"

    # --------------------------------------------------
    # Reconnaissance
    # --------------------------------------------------
    if "HTTP 200" in action_text:

        return "Reconnaissance"

    # --------------------------------------------------
    # Lateral Movement
    # --------------------------------------------------
    if "Attack Node" in action_text:

        return "Lateral Movement"

    # --------------------------------------------------
    # Defense
    # --------------------------------------------------
    if "Defender Action" in action_text:

        return "Defense Evasion"

    return "Unknown"
