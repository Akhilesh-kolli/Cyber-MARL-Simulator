"""
utils/constants.py
------------------
Central configuration registry for all cyber range settings,
threat intelligence ranges, risk weights, and vulnerability mappings.

FIX: ATTACK_SEVERITY expanded to cover all valid technique IDs.
FIX: INVALID_TECHNIQUE_VALUES updated to exclude DEFENSIVE-OPS from MITRE counts.
"""

# Simulation Node Roles / Topology Mappings
SIMULATION_NODES = {
    0: "Nginx",
    1: "DVWA",
    2: "MySQL",
    3: "Server",
    4: "Domain-Controller",
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
    "Execution": (50, 75),
    "Persistence": (70, 90),
    "Privilege Escalation": (70, 90),
    "Credential Access": (65, 88),
    "Defense Evasion": (65, 90),
    "Lateral Movement": (70, 95),
    "Collection": (75, 97),
    "Exfiltration": (90, 100),
    "Command and Control": (80, 98),
    "Mitigation": (0, 50),
}

# MITRE Techniques — valid technique IDs recognized by the platform
VALID_TECHNIQUES = {
    "T1190", "T1021", "T1046", "T1059", "T1078", "T1003", "T1105",
    "T1562", "T1055", "T1547", "T1486", "T1110", "T1595", "T1041",
    "T1005", "T1057", "T1070", "T1489", "T1565",
}

# FIX: INVALID_TECHNIQUE_VALUES must include all synthetic/non-MITRE placeholders
# so they are filtered out of MITRE analytics.
INVALID_TECHNIQUE_VALUES = {
    "N/A", "UNKNOWN", None, "",
    "DEFENSIVE-OPS", "DEFENDER-ACTION", "NOT-APPLICABLE",
    "DEFENDER",
}

# FIX: Full ATT&CK severity mapping covering all technique IDs used in the simulation
ATTACK_SEVERITY = {
    "T1190": "CRITICAL",  # Exploit Public-Facing Application
    "T1021": "HIGH",      # Remote Services
    "T1046": "MEDIUM",    # Network Service Discovery
    "T1059": "HIGH",      # Command & Scripting Interpreter
    "T1078": "HIGH",      # Valid Accounts
    "T1003": "CRITICAL",  # OS Credential Dumping
    "T1105": "HIGH",      # Ingress Tool Transfer
    "T1562": "MEDIUM",    # Impair Defenses
    "T1055": "HIGH",      # Process Injection
    "T1547": "HIGH",      # Boot/Logon Autostart Execution
    "T1486": "CRITICAL",  # Data Encrypted for Impact
    "T1110": "HIGH",      # Brute Force
    "T1595": "LOW",       # Active Scanning
    "T1041": "HIGH",      # Exfiltration Over C2 Channel
    "T1005": "MEDIUM",    # Data from Local System
    "T1057": "LOW",       # Process Discovery
    "T1070": "MEDIUM",    # Indicator Removal
    "T1489": "CRITICAL",  # Service Stop
    "T1565": "HIGH",      # Data Manipulation
}

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
    "Server": {
        "cve": "CVE-2021-44228",
        "name": "Log4Shell Remote Code Execution",
        "cvss": 10.0,
        "mitre": "T1059",
        "severity": "CRITICAL",
    },
    "Domain-Controller": {
        "cve": "CVE-2020-1472",
        "name": "ZeroLogon Privilege Escalation",
        "cvss": 10.0,
        "mitre": "T1055",
        "severity": "CRITICAL",
    },
    "Workstation": {
        "cve": "CVE-2022-30190",
        "name": "Follina MSDT RCE",
        "cvss": 7.8,
        "mitre": "T1059",
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
    "Process Injection": {
        "signature": "SIGMA Process Injection via Reflective DLL",
        "severity": "HIGH",
        "confidence": 85,
    },
    "Brute Force": {
        "signature": "ET POLICY Failed SSH Login Attempt",
        "severity": "MEDIUM",
        "confidence": 78,
    },
}
