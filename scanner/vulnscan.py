"""
vulnscan.py

Enterprise Vulnerability Scanning Module

Performs detection and (optionally) exploitation-attempt scanning using
Nmap NSE scripts. Returns structured findings enriched with:

- CVE identifiers (regex-extracted from script output)
- Confidence level
- Validation status  (Confirmed / Likely / Potential)
- Likelihood         (High / Medium / Low)
- Impact             (Critical / High / Medium / Low / Info)
- Evidence           (first 400 chars of script output for the report)
- Attack category    (RCE / Auth Bypass / Info Disclosure / etc.)

Run modes:
  --script vuln          (default — detection only)
  --script vuln,exploit  (aggressive — requires authorization)
"""

import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

import nmap

from utils.logger import log_step, log_info, log_warning, log_error

logger = logging.getLogger("enterprise_vapt.vulnscan")


# -------------------------------------------------------
# CVE extraction
# -------------------------------------------------------

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(text: str) -> List[str]:
    if not text:
        return []
    return sorted(set(m.upper() for m in CVE_REGEX.findall(text)))


# -------------------------------------------------------
# Attack category classification
# -------------------------------------------------------

CATEGORY_PATTERNS: List[tuple] = [
    ("Remote Code Execution",   ["remote code execution", "rce", "arbitrary code", "command execution"]),
    ("Privilege Escalation",    ["privilege escalation", "local privilege", "escalat"]),
    ("Authentication Bypass",   ["authentication bypass", "auth bypass", "no authentication", "unauthenticated"]),
    ("Anonymous Access",        ["anonymous login", "anonymous access", "anonymous ftp"]),
    ("Credential Disclosure",   ["credential", "password", "hash", "ntlm"]),
    ("SMB Vulnerability",       ["smb", "ms17-010", "eternalblue", "ms08-067", "samba"]),
    ("SSL/TLS Weakness",        ["ssl", "tls", "weak cipher", "beast", "poodle", "heartbleed"]),
    ("Information Disclosure",  ["information disclosure", "version detection", "banner"]),
    ("Misconfiguration",        ["misconfiguration", "default", "deprecated", "weak encryption"]),
    ("Cross-Site Scripting",    ["xss", "cross-site scripting", "script injection"]),
    ("SQL Injection",           ["sql injection", "sqli"]),
    ("Directory Traversal",     ["directory traversal", "path traversal", "lfi", "rfi"]),
]


def classify_category(text: str) -> str:
    if not text:
        return "General"
    t = text.lower()
    for category, keywords in CATEGORY_PATTERNS:
        if any(k in t for k in keywords):
            return category
    return "General"


# -------------------------------------------------------
# Confidence / validation / likelihood
# -------------------------------------------------------

def calculate_confidence(output: str) -> str:
    if not output:
        return "Low"
    t = output.lower()
    if "vulnerable" in t and "not" not in t[:t.find("vulnerable")]:
        return "High"
    if "likely vulnerable" in t or "appears vulnerable" in t:
        return "Medium"
    if "unknown" in t or "check" in t:
        return "Low"
    return "Medium"


def derive_validation_status(output: str, confidence: str) -> str:
    """
    Confirmed  — script explicitly states exploitation succeeded or host is vulnerable
    Likely     — script says "likely" / "appears" vulnerable
    Potential  — script flagged something but certainty is low
    """
    if not output:
        return "Potential"
    t = output.lower()
    if any(phrase in t for phrase in [
        "state: vulnerable",
        "vulnerable and exploitable",
        "successfully exploited",
        "exploit successful",
    ]):
        return "Confirmed"
    if confidence == "High":
        return "Confirmed"
    if confidence == "Medium":
        return "Likely"
    return "Potential"


def derive_likelihood(confidence: str, cves: List[str], validation_status: str) -> str:
    if validation_status == "Confirmed":
        return "High"
    if cves and confidence in {"High", "Medium"}:
        return "High"
    if confidence == "Medium" or cves:
        return "Medium"
    return "Low"


# -------------------------------------------------------
# Normalize a single NSE script result
# -------------------------------------------------------

def normalize_script_output(
    host: str,
    port: Any,
    protocol: str,
    script: str,
    output: str,
) -> Dict[str, Any]:
    cves       = extract_cves(output)
    confidence = calculate_confidence(output)
    val_status = derive_validation_status(output, confidence)
    likelihood = derive_likelihood(confidence, cves, val_status)
    category   = classify_category(f"{script} {output}")
    evidence   = (output or "")[:400].strip()

    return {
        "host":              host,
        "port":              port,
        "protocol":          protocol,
        "script":            script,
        "output":            output,
        "cves":              cves,
        "confidence":        confidence,
        "validation_status": val_status,
        "likelihood":        likelihood,
        "category":          category,
        "evidence":          evidence,
        "source":            "nmap_nse",
    }


# -------------------------------------------------------
# Parse Nmap results for a single host
# -------------------------------------------------------

def parse_nmap_vuln_results(
    nm: nmap.PortScanner,
    host: str,
) -> List[Dict[str, Any]]:
    vulnerabilities: List[Dict[str, Any]] = []

    if host not in nm.all_hosts():
        return vulnerabilities

    try:
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                scripts = nm[host][proto][port].get("script") or {}
                for script_name, output in scripts.items():
                    vulnerabilities.append(
                        normalize_script_output(host, port, proto, script_name, output)
                    )

        for hs in nm[host].get("hostscript") or []:
            vulnerabilities.append(
                normalize_script_output(
                    host, None, "host",
                    hs.get("id", ""),
                    hs.get("output", ""),
                )
            )

    except Exception as e:
        log_error(f"Parsing failed for {host}: {e}")

    return vulnerabilities


# -------------------------------------------------------
# Single-host vulnerability scan
# -------------------------------------------------------

def scan_host_vulnerabilities(
    host: str,
    run_exploits: bool = False,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Scan a single host for vulnerabilities.

    run_exploits=True adds --script exploit — only use with written
    authorization from the target owner.
    """
    script_set = "vuln,exploit" if run_exploits else "vuln"
    mode_label = "EXPLOIT MODE" if run_exploits else "detection only"
    log_step(f"Vuln scan on {host} [{mode_label}]")

    nm   = nmap.PortScanner()
    args = (
        f"-sV --script {script_set} "
        f"-T4 --max-retries 2 --host-timeout 5m"
    )

    try:
        nm.scan(hosts=host, arguments=args, timeout=timeout)
    except nmap.PortScannerError as e:
        log_error(f"Nmap error on {host}: {e}")
        return {"host": host, "vulnerabilities": [], "error": str(e)}
    except Exception as e:
        log_error(f"Scan error on {host}: {e}")
        return {"host": host, "vulnerabilities": [], "error": str(e)}

    vulns = parse_nmap_vuln_results(nm, host)
    log_info(f"{host}: {len(vulns)} vulnerability finding(s)")

    return {
        "host":          host,
        "vulnerabilities": vulns,
        "scan_status":   "complete",
        "exploit_mode":  run_exploits,
    }


# -------------------------------------------------------
# Parallel scan engine
# -------------------------------------------------------

def scan_vulns_parallel(
    hosts: List[str],
    run_exploits: bool = False,
    max_workers: int = 4,
) -> List[Dict[str, Any]]:
    """
    Parallel vulnerability scanning across multiple hosts.
    """
    log_step(f"Starting vulnerability scan on {len(hosts)} host(s)")

    if not hosts:
        log_warning("No hosts provided")
        return []

    results: List[Dict[str, Any]] = []
    worker_count = min(max_workers, len(hosts))

    with ThreadPoolExecutor(max_workers=worker_count) as exe:
        futures = {
            exe.submit(scan_host_vulnerabilities, host, run_exploits): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                log_error(f"Scan failed for {host}: {e}")
                results.append({"host": host, "vulnerabilities": [], "error": str(e)})

    log_step("Vulnerability scanning complete")
    return results


# -------------------------------------------------------
# Utility: flatten to a single list
# -------------------------------------------------------

def flatten_vulnerabilities(
    scan_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    flat: List[Dict[str, Any]] = []
    for hr in scan_results:
        flat.extend(hr.get("vulnerabilities", []))
    return flat
