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
    elif "Port 3307 Open" in action_text:

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

    # --------------------------------------------------
    # Command evaluation / scripting
    # --------------------------------------------------
    elif "PowerShell" in action_text or "command execution" in action_text.lower():

        return {
            "technique": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution"
        }

    # --------------------------------------------------
    # Valid account abuse
    # --------------------------------------------------
    elif "Valid Account" in action_text or "authentication" in action_text.lower():

        return {
            "technique": "T1078",
            "name": "Valid Accounts",
            "tactic": "Initial Access"
        }

    # --------------------------------------------------
    # Credential access
    # --------------------------------------------------
    elif "Credential" in action_text or "password" in action_text.lower():

        return {
            "technique": "T1003",
            "name": "OS Credential Dumping",
            "tactic": "Credential Access"
        }

    # --------------------------------------------------
    # Tool transfer
    # --------------------------------------------------
    elif "Ingress" in action_text or "download" in action_text.lower():

        return {
            "technique": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control"
        }

    # --------------------------------------------------
    # Defense evasion
    # --------------------------------------------------
    elif "evasion" in action_text.lower() or "obfuscation" in action_text.lower():

        return {
            "technique": "T1562",
            "name": "Impair Defenses",
            "tactic": "Defense Evasion"
        }

    # --------------------------------------------------
    # Process injection
    # --------------------------------------------------
    elif "injection" in action_text.lower() and "process" in action_text.lower():

        return {
            "technique": "T1055",
            "name": "Process Injection",
            "tactic": "Defense Evasion"
        }

    # --------------------------------------------------
    # Persistence
    # --------------------------------------------------
    elif "autostart" in action_text.lower() or "startup" in action_text.lower():

        return {
            "technique": "T1547",
            "name": "Boot or Logon Autostart Execution",
            "tactic": "Persistence"
        }

    # --------------------------------------------------
    # Data encryption / impact
    # --------------------------------------------------
    elif "encrypted" in action_text.lower() or "ransom" in action_text.lower():

        return {
            "technique": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact"
        }

    # --------------------------------------------------
    # Brute force
    # --------------------------------------------------
    elif "brute force" in action_text.lower() or "failed login" in action_text.lower():

        return {
            "technique": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access"
        }

    return None
