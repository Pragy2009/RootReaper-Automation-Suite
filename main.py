"""
main.py

Enterprise VAPT Automation Framework
Full orchestration engine

Pipeline:
Environment Validation
↓
Subnet Detection
↓
Host Discovery
↓
Port Scan
↓
Vulnerability Scan
↓
Host Audit
↓
Threat Intelligence
↓
Risk Analysis
↓
Report Generation
"""

import sys
import json
from datetime import datetime

# Utils
from utils.logger import (
    log_step,
    log_info,
    log_error,
    log_success,
    log_section,
    show_table
)

from utils.os_detect import get_environment_info
from utils.dependency_check import validate_environment

# Scanner modules
from scanner.network import get_subnet
from scanner.discovery import discover_hosts, extract_ips
from scanner.portscan import scan_hosts_parallel
from scanner.vulnscan import scan_vulns_parallel
from scanner.host_audit import run_host_audit
from scanner.threat_intel import fetch_latest_critical_cves
from scanner.risk_engine import analyze_risk
from scanner.report_engine import generate_report


# ------------------------------------------
# Environment Display
# ------------------------------------------

def show_environment():

    log_section("Environment Information")

    info = get_environment_info()

    table_data = [(k, str(v)) for k, v in info.items()]

    show_table(
        "System Environment",
        ["Property", "Value"],
        table_data
    )

    return info


# ------------------------------------------
# Subnet Selection
# ------------------------------------------

def select_subnet():

    log_section("Subnet Detection")

    subnet = get_subnet()

    if subnet is None:
        log_error("Failed to detect subnet")
        sys.exit(1)

    show_table(
        "Detected Subnet",
        ["ID", "Subnet"],
        [(1, subnet)]
    )

    choice = input("Use this subnet? (Y/n): ").strip().lower()

    if choice == "n":
        subnet = input("Enter subnet manually (example: 192.168.1.0/24): ")

    log_success(f"Using subnet: {subnet}")

    return subnet


# ------------------------------------------
# Host Selection
# ------------------------------------------

def select_hosts(subnet):

    log_section("Host Discovery")

    hosts_struct = discover_hosts(subnet)

    if not hosts_struct:

        log_error("No live hosts found")
        sys.exit(1)

    table_data = []

    for i, host in enumerate(hosts_struct, start=1):

        table_data.append(
            (i, host["ip"], host.get("hostname", ""), host["status"])
        )

    show_table(
        "Live Hosts",
        ["ID", "IP", "Hostname", "Status"],
        table_data
    )

    choice = input(
        "Enter host IDs (comma separated) or 'all': "
    ).strip()

    if choice.lower() == "all":

        selected = extract_ips(hosts_struct)

    else:

        selected = []

        for idx in choice.split(","):

            try:

                selected.append(
                    hosts_struct[int(idx.strip()) - 1]["ip"]
                )

            except:
                pass

    log_success(f"Selected hosts: {selected}")

    return selected


# ------------------------------------------
# Port Selection
# ------------------------------------------

def select_ports():

    log_section("Port Selection")

    ports = input(
        "Enter ports (example: 21,22,80 or 1-1024 or 'all'): "
    ).strip()

    if ports.lower() == "all":
        ports = "1-65535"

    log_success(f"Selected ports: {ports}")

    return ports


# ------------------------------------------
# Main Execution Pipeline
# ------------------------------------------

def run_vapt():

    start_time = datetime.now()

    log_step("Starting Enterprise VAPT Framework")

    # Validate environment
    log_section("Dependency Validation")

    if not validate_environment():

        log_error("Dependency validation failed")
        sys.exit(1)

    log_success("Environment validated")

    # Environment info
    env_info = show_environment()

    # Subnet
    subnet = select_subnet()

    # Hosts
    hosts = select_hosts(subnet)

    # Ports
    ports = select_ports()

    # ------------------------------------------
    # Port Scan
    # ------------------------------------------

    log_section("Port Scanning")

    port_results = scan_hosts_parallel(hosts, ports)

    # ------------------------------------------
    # Vulnerability Scan
    # ------------------------------------------

    log_section("Vulnerability Scanning")

    vuln_results = scan_vulns_parallel(hosts)

    # ------------------------------------------
    # Host Audit
    # ------------------------------------------

    log_section("Host Security Audit")

    host_audit = run_host_audit()

    log_info(host_audit)

    # ------------------------------------------
    # Threat Intelligence
    # ------------------------------------------

    log_section("Threat Intelligence")

    cves = fetch_latest_critical_cves()

    log_info(f"Fetched {len(cves)} critical CVEs")

    # ------------------------------------------
    # Merge Results for Risk Analysis
    # ------------------------------------------

    log_section("Risk Analysis")

    combined_hosts = []

    for host in port_results:

        host_ip = host.get("host")

        vulns = []

        for v in vuln_results:

            if v.get("host") == host_ip:

                vulns = v.get("vulnerabilities", [])

        host["vulns"] = vulns

        combined_hosts.append(host)

    risk_analysis = analyze_risk(combined_hosts)

    log_success("Risk analysis complete")

    # ------------------------------------------
    # Report Generation
    # ------------------------------------------

    log_section("Report Generation")

    report_paths = generate_report(
    risk_analysis["hosts"],
    vuln_results,
    env_info
    )

    # Save additional intelligence safely
    try:
        with open("output/threat_intel.json", "w") as f:
            json.dump(cves, f, indent=4)

        with open("output/host_audit.json", "w") as f:
            json.dump(host_audit, f, indent=4)

    except Exception as e:
        log_error(f"Failed to save auxiliary files: {e}")

    end_time = datetime.now()
    duration = end_time - start_time

    log_success(f"Scan completed in {duration}")

    # SAFE handling of report paths
    if report_paths and isinstance(report_paths, dict):

        html_path = report_paths.get("html")

        if html_path:
            log_success(f"Report saved: {html_path}")
        else:
            log_error("HTML report path missing.")

    else:
        log_error("Report generation failed.")


# ------------------------------------------
# Entry Point
# ------------------------------------------

if __name__ == "__main__":

    try:

        run_vapt()

    except KeyboardInterrupt:

        log_error("Scan interrupted by user")

        sys.exit(0)

    except Exception as e:

        log_error(f"Fatal error: {e}")

        sys.exit(1)