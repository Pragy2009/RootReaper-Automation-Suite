"""
risk_engine.py

Enterprise Risk Analysis Engine

Intelligence layer that converts raw scan findings into:
- Per-vulnerability severity, CVSS score, impact, and remediation
- Per-host asset criticality ranking
- Network-wide risk aggregation
- Identified attack paths (narratives linking services to threats)
- Exposure groupings by attack category
"""

from typing import Dict, List, Any

from utils.logger import log_step, log_info


# -------------------------------------------------------
# Severity keywords
# -------------------------------------------------------

CRITICAL_KEYWORDS = [
    "remote code execution", "rce", "privilege escalation",
    "root access", "unauthenticated", "arbitrary code",
    "command injection", "eternalblue", "ms17-010",
]
HIGH_KEYWORDS = [
    "authentication bypass", "anonymous login", "credential disclosure",
    "smb vulnerable", "exploit", "ms08-067", "sql injection",
    "directory traversal", "path traversal",
]
MEDIUM_KEYWORDS = [
    "weak ssl", "weak encryption", "deprecated", "misconfiguration",
    "information disclosure", "default credential", "weak password",
    "heartbleed", "beast", "poodle",
]
LOW_KEYWORDS = [
    "version detection", "banner", "open port", "ping",
]

CVSS_MAP = {
    "Critical": 9.5,
    "High":     8.0,
    "Medium":   5.5,
    "Low":      2.5,
    "Info":     0.0,
}

IMPACT_MAP = {
    "Critical": "Full system compromise / data breach",
    "High":     "Significant data exposure or service disruption",
    "Medium":   "Partial data exposure or configuration weakness",
    "Low":      "Minimal impact — informational",
    "Info":     "No direct impact",
}


# -------------------------------------------------------
# Asset criticality scoring
# -------------------------------------------------------

# Service → criticality score contribution
SERVICE_CRITICALITY: Dict[str, int] = {
    "ms-wbt-server": 10,   # RDP
    "rdp":           10,
    "microsoft-ds":  8,    # SMB
    "smb":           8,
    "netbios-ssn":   6,
    "mssql":         8,
    "mysql":         7,
    "postgresql":    7,
    "oracle":        8,
    "ftp":           5,
    "telnet":        9,    # unencrypted remote shell
    "vnc":           9,
    "ssh":           5,
    "http":          4,
    "https":         3,
    "smtp":          4,
    "pop3":          4,
    "imap":          4,
    "ldap":          7,
    "kerberos":      8,
    "snmp":          6,
}

PORT_CRITICALITY: Dict[int, int] = {
    3389: 10,   # RDP
    445:  9,    # SMB
    139:  7,    # NetBIOS
    23:   9,    # Telnet
    5900: 9,    # VNC
    1433: 8,    # MSSQL
    3306: 7,    # MySQL
    5432: 7,    # PostgreSQL
    1521: 8,    # Oracle
    389:  7,    # LDAP
    636:  6,    # LDAPS
    88:   8,    # Kerberos
    161:  6,    # SNMP
    22:   5,
    80:   4,
    443:  3,
    21:   5,
    25:   4,
}


def rank_asset_criticality(host_data: Dict[str, Any]) -> str:
    score = 0
    for pinfo in host_data.get("ports", []):
        if pinfo.get("state") != "open":
            continue
        port = pinfo.get("port", 0)
        svc  = (pinfo.get("service") or "").lower()

        score += PORT_CRITICALITY.get(port, 0)
        for keyword, pts in SERVICE_CRITICALITY.items():
            if keyword in svc:
                score = max(score, score + pts)  # don't double-count same port

    if score >= 25:
        return "Critical"
    if score >= 15:
        return "High"
    if score >= 8:
        return "Medium"
    return "Low"


# -------------------------------------------------------
# Attack path analysis
# -------------------------------------------------------

# (label, required_service_keywords_or_ports, vuln_keyword, severity, vector, impact_desc, description)
ATTACK_PATH_RULES = [
    {
        "id":          "smb_eternalblue",
        "title":       "EternalBlue — Critical Network Propagation Risk",
        "ports":       [445, 139],
        "vuln_keywords": ["ms17-010", "eternalblue"],
        "severity":    "Critical",
        "vector":      "Network (SMB 445/139)",
        "impact_desc": "Full remote code execution — attacker gains SYSTEM/root access",
        "description": (
            "MS17-010 (EternalBlue) detected on SMB. This exploit was used by WannaCry and "
            "NotPetya ransomware for rapid network propagation. Immediate patching required."
        ),
    },
    {
        "id":          "rdp_exposed",
        "title":       "RDP Exposed — Remote Access Attack Vector",
        "ports":       [3389],
        "vuln_keywords": [],
        "severity":    "High",
        "vector":      "Network (RDP 3389)",
        "impact_desc": "Remote desktop access — brute-force, credential stuffing, or RDP exploit",
        "description": (
            "Remote Desktop Protocol is directly reachable. Attackers can attempt brute-force "
            "attacks, BlueKeep (CVE-2019-0708), or DejaBlue. Restrict RDP to VPN/bastion host."
        ),
    },
    {
        "id":          "smb_anonymous",
        "title":       "Anonymous SMB Access — Information Gathering",
        "ports":       [445, 139],
        "vuln_keywords": ["anonymous", "null session", "smb-enum"],
        "severity":    "High",
        "vector":      "Network (SMB 445/139)",
        "impact_desc": "Unauthenticated enumeration of shares, users, and domain info",
        "description": (
            "SMB allows unauthenticated (null session) access. Attackers can enumerate "
            "shares, users, and group memberships without credentials."
        ),
    },
    {
        "id":          "ftp_anonymous",
        "title":       "Anonymous FTP Login — File Exfiltration Path",
        "ports":       [21],
        "vuln_keywords": ["ftp-anon", "anonymous ftp", "anonymous login"],
        "severity":    "High",
        "vector":      "Network (FTP 21)",
        "impact_desc": "Unauthenticated file read/write — data exfiltration or backdoor upload",
        "description": (
            "FTP server accepts anonymous logins. Depending on write permissions, an attacker "
            "can exfiltrate sensitive files or upload a web shell."
        ),
    },
    {
        "id":          "telnet_exposed",
        "title":       "Telnet Exposed — Unencrypted Remote Shell",
        "ports":       [23],
        "vuln_keywords": [],
        "severity":    "Critical",
        "vector":      "Network (Telnet 23)",
        "impact_desc": "Credentials transmitted in clear text — trivial interception",
        "description": (
            "Telnet transmits all data including credentials in plaintext. Any network "
            "observer can capture credentials and gain remote shell access."
        ),
    },
    {
        "id":          "vnc_exposed",
        "title":       "VNC Exposed — Remote Graphical Access",
        "ports":       [5900, 5901],
        "vuln_keywords": [],
        "severity":    "High",
        "vector":      "Network (VNC 5900)",
        "impact_desc": "Graphical remote control — brute-force or unauthenticated access",
        "description": (
            "VNC is exposed without a restrictive network policy. Attackers can brute-force "
            "the VNC password or exploit authentication weaknesses for full desktop control."
        ),
    },
    {
        "id":          "web_rce",
        "title":       "Web Application Remote Code Execution",
        "ports":       [80, 443, 8080, 8443, 8000, 8888],
        "vuln_keywords": ["rce", "remote code execution", "shellshock", "struts"],
        "severity":    "Critical",
        "vector":      "Web (HTTP/HTTPS)",
        "impact_desc": "Full server compromise via web application exploit",
        "description": (
            "An RCE vulnerability was detected in the web application. Successful exploitation "
            "allows the attacker to execute arbitrary commands on the server."
        ),
    },
    {
        "id":          "sql_injection",
        "title":       "SQL Injection — Database Compromise Path",
        "ports":       [80, 443, 8080, 8443],
        "vuln_keywords": ["sql injection", "sqli"],
        "severity":    "High",
        "vector":      "Web (HTTP/HTTPS)",
        "impact_desc": "Database exfiltration, authentication bypass, potential RCE",
        "description": (
            "SQL injection detected in the web application. Attackers can dump databases, "
            "bypass authentication, and potentially achieve OS command execution."
        ),
    },
    {
        "id":          "weak_ssl",
        "title":       "Weak SSL/TLS — MITM and Decryption Risk",
        "ports":       [443, 8443],
        "vuln_keywords": ["weak ssl", "poodle", "beast", "heartbleed", "ssl", "tls"],
        "severity":    "Medium",
        "vector":      "Network (TLS)",
        "impact_desc": "Traffic decryption, credential interception via MITM",
        "description": (
            "Weak SSL/TLS configuration detected. Susceptible to POODLE, BEAST, or Heartbleed "
            "attacks that allow decryption of encrypted traffic."
        ),
    },
    {
        "id":          "snmp_exposed",
        "title":       "SNMP Exposed — Network Information Disclosure",
        "ports":       [161],
        "vuln_keywords": [],
        "severity":    "Medium",
        "vector":      "Network (SNMP 161/UDP)",
        "impact_desc": "Network topology disclosure, device configuration leakage",
        "description": (
            "SNMP is accessible. With default community strings (public/private), attackers "
            "can enumerate the full network topology and device configurations."
        ),
    },
]


def _host_open_ports(host_data: Dict[str, Any]) -> set:
    return {
        p["port"] for p in host_data.get("ports", [])
        if p.get("state") == "open"
    }


def _vuln_text(host_data: Dict[str, Any]) -> str:
    texts = []
    for v in host_data.get("vulns", []):
        texts.append((v.get("script") or "") + " " + (v.get("output") or ""))
    for cat_findings in host_data.get("enumeration", {}).get("services", {}).values():
        for f in cat_findings:
            texts.append((f.get("script") or "") + " " + (f.get("output") or ""))
    return " ".join(texts).lower()


def analyze_attack_paths(hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generate attack path narratives for each host based on open ports
    and detected vulnerabilities.
    """
    paths: List[Dict[str, Any]] = []

    for host_data in hosts:
        host       = host_data.get("host", "unknown")
        open_ports = _host_open_ports(host_data)
        vuln_text  = _vuln_text(host_data)

        for rule in ATTACK_PATH_RULES:
            port_match = any(p in open_ports for p in rule["ports"])
            vuln_match = (
                not rule["vuln_keywords"]
                or any(kw in vuln_text for kw in rule["vuln_keywords"])
            )

            if port_match and vuln_match:
                paths.append({
                    "id":          rule["id"],
                    "host":        host,
                    "title":       rule["title"],
                    "severity":    rule["severity"],
                    "vector":      rule["vector"],
                    "impact_desc": rule["impact_desc"],
                    "description": rule["description"],
                })

    return paths


# -------------------------------------------------------
# Severity classification
# -------------------------------------------------------

def classify_severity(text: str) -> str:
    if not text:
        return "Info"
    t = text.lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in t:
            return "Critical"
    for kw in HIGH_KEYWORDS:
        if kw in t:
            return "High"
    for kw in MEDIUM_KEYWORDS:
        if kw in t:
            return "Medium"
    for kw in LOW_KEYWORDS:
        if kw in t:
            return "Low"
    return "Info"


# -------------------------------------------------------
# Per-vulnerability risk enrichment
# -------------------------------------------------------

REMEDIATION_GUIDE: Dict[str, str] = {
    "Critical": (
        "Immediately isolate the affected system. Apply vendor patches. "
        "Disable the vulnerable service if a patch is unavailable."
    ),
    "High": (
        "Apply security patches within 24–72 hours. "
        "Restrict access to the vulnerable service via firewall rules."
    ),
    "Medium": (
        "Review and harden service configuration. "
        "Apply patches in the next maintenance window."
    ),
    "Low":  "Monitor for changes. Schedule update in routine maintenance.",
    "Info": "No action required.",
}


def calculate_vulnerability_risk(vuln: Dict[str, Any]) -> Dict[str, Any]:
    description = (vuln.get("output") or "") + " " + (vuln.get("script") or "")

    # Use existing severity if already set (e.g., by vulnscan), else classify
    severity    = vuln.get("severity") or classify_severity(description)
    cvss_score  = CVSS_MAP.get(severity, 0.0)
    impact      = IMPACT_MAP.get(severity, "Unknown")

    # Derive validation_status and likelihood if not already present
    validation_status = vuln.get("validation_status") or "Potential"
    likelihood        = vuln.get("likelihood")        or "Low"

    vuln["severity"]          = severity
    vuln["cvss_score"]        = cvss_score
    vuln["impact"]            = impact
    vuln["validation_status"] = validation_status
    vuln["likelihood"]        = likelihood
    vuln["remediation"]       = REMEDIATION_GUIDE.get(severity, "Review and patch.")

    return vuln


# -------------------------------------------------------
# Per-host risk aggregation
# -------------------------------------------------------

def calculate_host_risk(host_data: Dict[str, Any]) -> Dict[str, Any]:
    vulns  = host_data.get("vulns", [])
    total  = 0.0
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    enriched = []
    for v in vulns:
        ev       = calculate_vulnerability_risk(v)
        sev      = ev["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        total   += ev["cvss_score"]
        enriched.append(ev)

    host_data["vulns"]          = enriched
    host_data["risk_score"]     = round(total, 2)
    host_data["severity_counts"] = counts
    host_data["risk_level"]     = _risk_level(total)
    host_data["asset_criticality"] = rank_asset_criticality(host_data)

    return host_data


def _risk_level(score: float) -> str:
    if score >= 20:  return "Critical"
    if score >= 10:  return "High"
    if score >= 5:   return "Medium"
    if score >  0:   return "Low"
    return "Secure"


# -------------------------------------------------------
# Exposure grouping
# -------------------------------------------------------

def group_exposures(hosts: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group all vulnerabilities by attack category for the report.
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for host in hosts:
        for v in host.get("vulns", []):
            cat = v.get("category", "General")
            groups.setdefault(cat, []).append(v)
    return groups


# -------------------------------------------------------
# Full risk analysis pipeline
# -------------------------------------------------------

def analyze_risk(hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    log_step("Running enterprise risk analysis engine")

    total_score = 0.0
    sev_totals  = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    enriched    = []

    for host in hosts:
        eh = calculate_host_risk(host)
        total_score += eh["risk_score"]
        for sev, cnt in eh["severity_counts"].items():
            sev_totals[sev] = sev_totals.get(sev, 0) + cnt
        enriched.append(eh)

    attack_paths  = analyze_attack_paths(enriched)
    exposure_map  = group_exposures(enriched)

    log_info(f"Network risk score: {round(total_score, 2)}")
    log_info(f"Attack paths identified: {len(attack_paths)}")

    return {
        "total_hosts":          len(hosts),
        "network_risk_score":   round(total_score, 2),
        "network_risk_level":   _risk_level(total_score),
        "severity_totals":      sev_totals,
        "hosts":                enriched,
        "attack_paths":         attack_paths,
        "exposure_groups":      exposure_map,
    }
