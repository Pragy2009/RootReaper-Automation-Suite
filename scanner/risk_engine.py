"""
risk_engine.py

Enterprise Risk Analysis Engine

Purpose:
Convert raw vulnerability and host audit findings into
enterprise-grade risk scores, severity classifications,
and remediation guidance.

This module is the core intelligence layer of the VAPT framework.
"""

from typing import Dict, List, Any
from utils.logger import log_step, log_info


# -------------------------------
# Severity and CVSS Mapping Rules
# -------------------------------

CRITICAL_KEYWORDS = [
    "remote code execution",
    "rce",
    "privilege escalation",
    "root access",
    "unauthenticated"
]

HIGH_KEYWORDS = [
    "authentication bypass",
    "anonymous login",
    "credential disclosure",
    "smb vulnerable",
    "exploit"
]

MEDIUM_KEYWORDS = [
    "weak ssl",
    "weak encryption",
    "deprecated",
    "misconfiguration"
]

LOW_KEYWORDS = [
    "information disclosure",
    "version detection"
]


CVSS_MAP = {
    "Critical": 9.5,
    "High": 8.0,
    "Medium": 5.5,
    "Low": 2.5,
    "Info": 0.0
}


# -------------------------------
# Severity Classification Engine
# -------------------------------

def classify_severity(text: str) -> str:
    """
    Classify vulnerability severity based on description text
    """

    if not text:
        return "Info"

    text = text.lower()

    for keyword in CRITICAL_KEYWORDS:
        if keyword in text:
            return "Critical"

    for keyword in HIGH_KEYWORDS:
        if keyword in text:
            return "High"

    for keyword in MEDIUM_KEYWORDS:
        if keyword in text:
            return "Medium"

    for keyword in LOW_KEYWORDS:
        if keyword in text:
            return "Low"

    return "Info"


# -------------------------------
# Risk Score Calculation
# -------------------------------

def calculate_vulnerability_risk(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adds severity and risk score to vulnerability
    """

    description = vuln.get("output", "")

    severity = classify_severity(description)

    cvss_score = CVSS_MAP.get(severity, 0.0)

    vuln["severity"] = severity
    vuln["cvss_score"] = cvss_score

    return vuln


# -------------------------------
# Host Risk Aggregation
# -------------------------------

def calculate_host_risk(host_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate overall host risk score
    """

    vulns = host_data.get("vulns", [])

    total_score = 0.0

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    enriched_vulns = []

    for vuln in vulns:

        enriched = calculate_vulnerability_risk(vuln)

        severity = enriched["severity"]

        severity_counts[severity] += 1

        total_score += enriched["cvss_score"]

        enriched_vulns.append(enriched)

    host_data["vulns"] = enriched_vulns

    host_data["risk_score"] = round(total_score, 2)

    host_data["severity_counts"] = severity_counts

    host_data["risk_level"] = calculate_risk_level(total_score)

    return host_data


# -------------------------------
# Risk Level Classification
# -------------------------------

def calculate_risk_level(score: float) -> str:

    if score >= 20:
        return "Critical"

    elif score >= 10:
        return "High"

    elif score >= 5:
        return "Medium"

    elif score > 0:
        return "Low"

    return "Secure"


# -------------------------------
# Network Risk Aggregation
# -------------------------------

def calculate_network_risk(hosts: List[Dict[str, Any]]) -> Dict[str, Any]:

    log_step("Calculating network risk score")

    total_score = 0

    severity_totals = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    enriched_hosts = []

    for host in hosts:

        enriched = calculate_host_risk(host)

        total_score += enriched["risk_score"]

        for severity, count in enriched["severity_counts"].items():

            severity_totals[severity] += count

        enriched_hosts.append(enriched)

    network_risk = {

        "total_hosts": len(hosts),

        "network_risk_score": round(total_score, 2),

        "network_risk_level": calculate_risk_level(total_score),

        "severity_totals": severity_totals,

        "hosts": enriched_hosts
    }

    log_info(f"Network risk score: {network_risk['network_risk_score']}")

    return network_risk


# -------------------------------
# Remediation Engine
# -------------------------------

REMEDIATION_GUIDE = {

    "Critical": "Immediately patch affected systems. Disable vulnerable services. Apply vendor security updates.",

    "High": "Apply security patches and restrict access to vulnerable services.",

    "Medium": "Review configuration and apply security hardening.",

    "Low": "Monitor vulnerability and update when possible.",

    "Info": "No action required."
}


def attach_remediation(host_data: Dict[str, Any]):

    for vuln in host_data.get("vulns", []):

        severity = vuln.get("severity")

        vuln["remediation"] = REMEDIATION_GUIDE.get(severity)

    return host_data


# -------------------------------
# Full Risk Analysis Pipeline
# -------------------------------

def analyze_risk(hosts: List[Dict[str, Any]]) -> Dict[str, Any]:

    log_step("Running enterprise risk analysis engine")

    network_risk = calculate_network_risk(hosts)

    for host in network_risk["hosts"]:

        attach_remediation(host)

    return network_risk