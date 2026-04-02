"""
vulnscan.py

Enterprise Vulnerability Scanning Module

Purpose:
- Detect vulnerabilities using Nmap NSE scripts
- Extract CVE identifiers automatically
- Normalize vulnerability data for risk engine
- Cross-platform, safe, and scalable

This module performs detection only, not exploitation.
"""

import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

import nmap

from utils.logger import (
    log_step,
    log_info,
    log_warning,
    log_error
)

logger = logging.getLogger("enterprise_vapt.vulnscan")


# ---------------------------------------------------
# CVE Extraction
# ---------------------------------------------------

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(text: str) -> List[str]:
    """
    Extract CVE IDs from vulnerability output
    """

    if not text:
        return []

    matches = CVE_REGEX.findall(text)

    return list(set(matches))


# ---------------------------------------------------
# Normalize Script Output
# ---------------------------------------------------

def normalize_script_output(host: str, port: int, protocol: str, script: str, output: str) -> Dict[str, Any]:
    """
    Convert raw NSE script output into structured vulnerability object
    """

    cves = extract_cves(output)

    vuln = {

        "host": host,

        "port": port,

        "protocol": protocol,

        "script": script,

        "output": output,

        "cves": cves,

        "confidence": calculate_confidence(output),

        "source": "nmap_nse"

    }

    return vuln


# ---------------------------------------------------
# Confidence Calculation
# ---------------------------------------------------

def calculate_confidence(output: str) -> str:
    """
    Estimate vulnerability confidence level
    """

    if not output:
        return "Low"

    text = output.lower()

    if "vulnerable" in text:
        return "High"

    if "likely vulnerable" in text:
        return "Medium"

    if "unknown" in text:
        return "Low"

    return "Medium"


# ---------------------------------------------------
# Parse Nmap Results
# ---------------------------------------------------

def parse_nmap_vuln_results(nm: nmap.PortScanner, host: str) -> List[Dict[str, Any]]:
    """
    Parse Nmap NSE script results into normalized vulnerabilities
    """

    vulnerabilities = []

    if host not in nm.all_hosts():

        return vulnerabilities

    try:

        for proto in nm[host].all_protocols():

            ports = nm[host][proto].keys()

            for port in ports:

                scripts = nm[host][proto][port].get("script")

                if scripts:

                    for script_name, output in scripts.items():

                        vuln = normalize_script_output(
                            host,
                            port,
                            proto,
                            script_name,
                            output
                        )

                        vulnerabilities.append(vuln)

        # Host-level scripts
        host_scripts = nm[host].get("hostscript", [])

        for script in host_scripts:

            vuln = normalize_script_output(
                host,
                None,
                "host",
                script.get("id"),
                script.get("output")
            )

            vulnerabilities.append(vuln)

    except Exception as e:

        log_error(f"Parsing failed for {host}: {e}")

    return vulnerabilities


# ---------------------------------------------------
# Single Host Scan
# ---------------------------------------------------

def scan_host_vulnerabilities(host: str, timeout: int = 300) -> Dict[str, Any]:
    """
    Perform vulnerability scan on single host
    """

    log_step(f"Scanning vulnerabilities on {host}")

    scanner = nmap.PortScanner()

    args = "-sV --script vuln -T4 --max-retries 2 --host-timeout 5m"

    try:

        scanner.scan(hosts=host, arguments=args, timeout=timeout)

    except nmap.PortScannerError as e:

        log_error(f"Nmap error on {host}: {e}")

        return {

            "host": host,

            "vulnerabilities": [],

            "error": str(e)

        }

    except Exception as e:

        log_error(f"Unexpected scan error on {host}: {e}")

        return {

            "host": host,

            "vulnerabilities": [],

            "error": str(e)

        }

    vulns = parse_nmap_vuln_results(scanner, host)

    log_info(f"{host}: {len(vulns)} vulnerabilities detected")

    return {

        "host": host,

        "vulnerabilities": vulns,

        "scan_status": "complete"

    }


# ---------------------------------------------------
# Parallel Scan Engine
# ---------------------------------------------------

def scan_vulns_parallel(hosts: List[str], max_workers: int = 4) -> List[Dict[str, Any]]:
    """
    Perform parallel vulnerability scanning across multiple hosts
    """

    log_step(f"Starting vulnerability scan on {len(hosts)} hosts")

    results = []

    if not hosts:

        log_warning("No hosts provided for vulnerability scan")

        return results

    worker_count = min(max_workers, len(hosts))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:

        futures = {

            executor.submit(scan_host_vulnerabilities, host): host

            for host in hosts

        }

        for future in as_completed(futures):

            host = futures[future]

            try:

                result = future.result()

                results.append(result)

            except Exception as e:

                log_error(f"Scan failed for {host}: {e}")

                results.append({

                    "host": host,

                    "vulnerabilities": [],

                    "error": str(e)

                })

    log_step("Vulnerability scanning complete")

    return results


# ---------------------------------------------------
# Flatten Results for Risk Engine
# ---------------------------------------------------

def flatten_vulnerabilities(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert scan results into flat vulnerability list
    """

    flat = []

    for host in scan_results:

        for vuln in host.get("vulnerabilities", []):

            flat.append(vuln)

    return flat