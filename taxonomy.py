"""Shared vocabulary: categories, indicator types, severities, lifecycle, ATT&CK mapping."""

CATEGORIES = [
    "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS", "WEB THREATS",
    "NETWORK THREATS", "VULNERABILITY EXPOSURE", "SOCIAL ENGINEERING",
    "DATA EXPOSURE", "ACCOUNT SECURITY",
]
INDICATOR_TYPES = ["IP ADDRESS", "DOMAIN", "URL", "FILE HASH", "EMAIL/SENDER DOMAIN", "CVE ID"]
SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# The five levels the dashboard must never blur together.
LIFECYCLE = ["OBSERVATION", "INDICATOR", "ALERT", "THREAT", "INCIDENT"]
LIFECYCLE_HELP = {
    "OBSERVATION": "A single raw data point. Low confidence, uncorroborated. Nothing is 'wrong' yet.",
    "INDICATOR": "An observable (IP, domain, hash...) with enough confidence to be worth tracking or blocking.",
    "ALERT": "An indicator that was also seen inside our environment and scored high enough to need triage.",
    "THREAT": "Corroborated by multiple sources, high confidence, mapped to attacker behaviour. A real adversary risk.",
    "INCIDENT": "Impact CONFIRMED by a human analyst. Only this level means 'we were actually affected'.",
}

# Base risk contribution per category (0-40). CVE records use CVSS instead.
CATEGORY_WEIGHT = {
    "RANSOMWARE": 40, "MALWARE": 34, "CREDENTIAL THREATS": 32, "VULNERABILITY EXPOSURE": 30,
    "DATA EXPOSURE": 30, "PHISHING": 28, "WEB THREATS": 26, "ACCOUNT SECURITY": 26,
    "NETWORK THREATS": 22, "SOCIAL ENGINEERING": 22,
}

# MITRE ATT&CK (Enterprise) technique IDs - used for defensive mapping only.
ATTACK_MAP = {
    "PHISHING": [("T1566", "Phishing", "Initial Access"), ("T1204", "User Execution", "Execution")],
    "MALWARE": [("T1204", "User Execution", "Execution"), ("T1059", "Command and Scripting Interpreter", "Execution"), ("T1105", "Ingress Tool Transfer", "Command and Control")],
    "RANSOMWARE": [("T1486", "Data Encrypted for Impact", "Impact"), ("T1490", "Inhibit System Recovery", "Impact")],
    "CREDENTIAL THREATS": [("T1110", "Brute Force", "Credential Access"), ("T1555", "Credentials from Password Stores", "Credential Access")],
    "WEB THREATS": [("T1190", "Exploit Public-Facing Application", "Initial Access"), ("T1189", "Drive-by Compromise", "Initial Access")],
    "NETWORK THREATS": [("T1046", "Network Service Discovery", "Discovery"), ("T1071", "Application Layer Protocol", "Command and Control"), ("T1498", "Network Denial of Service", "Impact")],
    "VULNERABILITY EXPOSURE": [("T1190", "Exploit Public-Facing Application", "Initial Access"), ("T1203", "Exploitation for Client Execution", "Execution")],
    "SOCIAL ENGINEERING": [("T1598", "Phishing for Information", "Reconnaissance"), ("T1566", "Phishing", "Initial Access")],
    "DATA EXPOSURE": [("T1530", "Data from Cloud Storage", "Collection"), ("T1567", "Exfiltration Over Web Service", "Exfiltration")],
    "ACCOUNT SECURITY": [("T1078", "Valid Accounts", "Defense Evasion / Persistence"), ("T1621", "MFA Request Generation", "Credential Access")],
}
