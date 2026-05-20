"""
utils/constants.py
------------------
Central configuration registry for all cyber range settings,
threat intelligence ranges, risk weights, and vulnerability mappings.
"""

# Simulation Node Roles / Topology Mappings
SIMULATION_NODES = {
    0: "Workstation",
    1: "Firewall",
    2: "Database",
    3: "Server",
    4: "DomainController",
    5: "Workstation",
}

# Node Mapping for backwards/forwards compatibility
NODE_MAPPING = {
    0: "Nginx",
    1: "DVWA",
    2: "MySQL",
    3: "Server",
    4: "Domain-Controller",
    5: "Workstation",
}

# Asset Criticality Weightings for Risk Scoring
ASSET_CRITICALITY = {
    "Nginx": 3,
    "DVWA": 4,
    "MySQL": 5,
    "Server": 3,
    "Domain-Controller": 5,
    "Workstation": 2,
}

# Protocol and port configurations
REAL_SERVICES = {
    "DVWA":  {"port": 8080, "protocol": "HTTP"},
    "MySQL": {"port": 3307, "protocol": "TCP"},
    "Nginx": {"port": 5000, "protocol": "HTTP"},
}

NODE_TO_SERVICE = {
    0: "Nginx",
    1: "DVWA",
    2: "MySQL",
}

# Bounded Sigmoid Risk Stage Thresholds
STAGE_RANGES = {
    "Idle": (0, 20),
    "Reconnaissance": (20, 45),
    "Discovery": (20, 45),
    "Initial Access": (45, 70),
    "Lateral Movement": (70, 90),
    "Privilege Escalation": (70, 90),
    "Persistence": (70, 90),
    "Exfiltration": (90, 100),
}

# MITRE Techniques
VALID_TECHNIQUES = {"T1190", "T1021", "T1046", "T1595"}
INVALID_TECHNIQUE_VALUES = {"N/A", "UNKNOWN", None, ""}

# Vulnerability Database
VULNERABILITY_DB = {
    "DVWA": {
        "cve": "CVE-2023-9999",
        "name": "SQL Injection",
        "cvss": 9.8,
        "mitre": "T1190",
        "severity": "CRITICAL",
    },
    "MySQL": {
        "cve": "CVE-2016-6662",
        "name": "MySQL Remote Root Code Execution",
        "cvss": 8.5,
        "mitre": "T1021",
        "severity": "HIGH",
    },
    "Nginx": {
        "cve": "CVE-2021-23017",
        "name": "Nginx Resolver RCE",
        "cvss": 7.7,
        "mitre": "T1190",
        "severity": "HIGH",
    },
}

# Threat Level Color / Numeric mappings
THREAT_NUMERIC = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Detection rules
DETECTION_RULES = {
    "SQL Injection": {
        "signature": "ET WEB_SERVER SQL Injection Attempt",
        "severity": "HIGH",
        "confidence": 92,
    },
    "Active Scanning": {
        "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
        "severity": "MEDIUM",
        "confidence": 81,
    },
    "Remote Services": {
        "signature": "SIGMA Lateral Movement Remote Service Execution",
        "severity": "HIGH",
        "confidence": 88,
    },
    "Network Service Discovery": {
        "signature": "ET POLICY Internal Network Scan",
        "severity": "LOW",
        "confidence": 73,
    },
}

# Attack severity mapping
ATTACK_SEVERITY = {
    "T1190": "CRITICAL",
    "T1021": "HIGH",
    "T1046": "MEDIUM",
    "T1595": "LOW",
}
