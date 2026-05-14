def calculate_threat_level(action_text):

    score = 0

    # --------------------------------------------------
    # HTTP probing
    # --------------------------------------------------
    if "HTTP 200" in action_text:
        score += 1

    # --------------------------------------------------
    # SQL Injection
    # --------------------------------------------------
    if "SQL Injection Detected" in action_text:
        score += 4

    # --------------------------------------------------
    # Service discovery
    # --------------------------------------------------
    if "Port 3306 Open" in action_text:
        score += 2

    # --------------------------------------------------
    # MITRE Initial Access
    # --------------------------------------------------
    if "Initial Access" in action_text:
        score += 3

    # --------------------------------------------------
    # Severity mapping
    # --------------------------------------------------
    if score >= 7:
        return "CRITICAL"

    elif score >= 5:
        return "HIGH"

    elif score >= 3:
        return "MEDIUM"

    return "LOW"
