"""
main.py

RootReaper Enterprise VAPT Automation Framework
Full orchestration pipeline

Pipeline:
  Environment Validation
        ↓
  Subnet Detection
        ↓
  Host Discovery
        ↓
  Port Scan  (aggressive: banner + default scripts)
        ↓
  Service Enumeration  (SMB / FTP / SSH / RDP / HTTP)
        ↓
  Vulnerability Scan   (NSE vuln scripts; optionally + exploit)
        ↓
  Web Application Scan (Nikto + HTTP headers + SSL/TLS)
        ↓
  Host Audit           (local firewall / AV / misconfigs)
        ↓
  Threat Intelligence  (NVD latest critical CVEs)
        ↓
  Risk Analysis        (severity, CVSS, attack paths, asset criticality)
        ↓
  Report Generation    (JSON + HTML dashboard + PDF)
"""

import sys
import json
from datetime import datetime

from utils.logger import (
    log_step, log_info, log_error, log_success,
    log_section, log_warning, show_table,
)
from utils.os_detect import get_environment_info
from utils.dependency_check import validate_environment

from scanner.network import get_subnet
from scanner.discovery import discover_hosts, extract_ips
from scanner.portscan import scan_hosts_parallel
from scanner.enumeration import run_enumeration
from scanner.vulnscan import scan_vulns_parallel
from scanner.webscan import run_web_scans
from scanner.host_audit import run_host_audit
from scanner.threat_intel import fetch_latest_critical_cves
from scanner.risk_engine import analyze_risk
from scanner.report_engine import generate_report


# --------------------------------------------------
# Step helpers
# --------------------------------------------------

def show_environment():
    log_section("Environment Information")
    info = get_environment_info()
    show_table(
        "System Environment",
        ["Property", "Value"],
        [(k, str(v)) for k, v in info.items()],
    )
    return info


def select_subnet():
    log_section("Subnet Detection")
    subnet = get_subnet()
    if subnet is None:
        log_error("Failed to detect subnet")
        sys.exit(1)
    show_table("Detected Subnet", ["ID", "Subnet"], [(1, subnet)])
    choice = input("Use this subnet? (Y/n): ").strip().lower()
    if choice == "n":
        subnet = input("Enter subnet (e.g. 192.168.1.0/24): ").strip()
    log_success(f"Using subnet: {subnet}")
    return subnet


def select_hosts(subnet):
    log_section("Host Discovery")
    hosts_struct = discover_hosts(subnet)
    if not hosts_struct:
        log_error("No live hosts found")
        sys.exit(1)
    show_table(
        "Live Hosts",
        ["ID", "IP", "Hostname", "Status"],
        [(i, h["ip"], h.get("hostname", ""), h["status"])
         for i, h in enumerate(hosts_struct, 1)],
    )
    choice = input("Enter host IDs (comma-separated) or 'all': ").strip()
    if choice.lower() == "all":
        selected = extract_ips(hosts_struct)
    else:
        selected = []
        for idx in choice.split(","):
            try:
                selected.append(hosts_struct[int(idx.strip()) - 1]["ip"])
            except Exception:
                pass
    if not selected:
        log_error("No valid hosts selected")
        sys.exit(1)
    log_success(f"Selected hosts: {selected}")
    return selected


def select_ports():
    log_section("Port Selection")
    ports = input(
        "Enter ports (e.g. 21,22,80 | 1-1024 | 'all' [1-65535]): "
    ).strip()
    if ports.lower() == "all":
        ports = "1-65535"
    log_success(f"Scanning ports: {ports}")
    return ports


def prompt_exploit_mode() -> bool:
    """
    Ask the operator whether to enable exploit-mode NSE scripts.
    Requires explicit acknowledgement of authorization.
    """
    log_section("Exploit Mode")
    log_warning(
        "Exploit-mode runs Nmap --script exploit which attempts known exploits.\n"
        "  Only use this against systems you own or have WRITTEN authorization to test.\n"
        "  Unauthorized exploitation is illegal."
    )
    ans = input(
        "Enable exploit-mode? Confirm you have authorization (yes/NO): "
    ).strip().lower()
    enabled = ans == "yes"
    if enabled:
        log_success("Exploit mode ENABLED — proceeding with written-authorization assumption")
    else:
        log_info("Exploit mode disabled — detection only")
    return enabled


# --------------------------------------------------
# Main pipeline
# --------------------------------------------------

def run_vapt():
    start_time = datetime.now()
    log_step("Starting RootReaper Enterprise VAPT Framework")

    # 1. Dependency validation
    log_section("Dependency Validation")
    if not validate_environment():
        log_error("Dependency validation failed — aborting")
        sys.exit(1)
    log_success("Environment validated")

    # 2. Environment info
    env_info = show_environment()

    # 3. Subnet + host + port selection
    subnet = select_subnet()
    hosts  = select_hosts(subnet)
    ports  = select_ports()

    # 4. Exploit mode prompt
    run_exploits = prompt_exploit_mode()

    # --------------------------------------------------
    # 5. Port scanning
    # --------------------------------------------------
    log_section("Port Scanning")
    port_results = scan_hosts_parallel(hosts, ports)

    # --------------------------------------------------
    # 6. Service enumeration (SMB / FTP / SSH / RDP / HTTP)
    # --------------------------------------------------
    log_section("Service Enumeration")
    enum_results = run_enumeration(port_results)

    # Attach enumeration data to port_results for downstream use
    enum_by_host = {e["host"]: e for e in enum_results}
    for pr in port_results:
        pr["enumeration"] = enum_by_host.get(pr.get("host"), {})

    # --------------------------------------------------
    # 7. Vulnerability scanning
    # --------------------------------------------------
    log_section("Vulnerability Scanning")
    vuln_results = scan_vulns_parallel(hosts, run_exploits=run_exploits)

    # --------------------------------------------------
    # 8. Web application scanning
    # --------------------------------------------------
    log_section("Web Application Scanning")
    web_results = run_web_scans(port_results)

    # Attach web findings per host
    web_by_host: dict = {}
    for wr in web_results:
        h = wr.get("host")
        web_by_host.setdefault(h, []).extend(wr.get("all_findings", []))

    # --------------------------------------------------
    # 9. Host audit (local machine)
    # --------------------------------------------------
    log_section("Host Security Audit")
    host_audit = run_host_audit()
    log_info(str(host_audit))

    # --------------------------------------------------
    # 10. Threat intelligence
    # --------------------------------------------------
    log_section("Threat Intelligence")
    cves = fetch_latest_critical_cves(limit=10)
    log_info(f"Fetched {len(cves)} critical CVE(s)")

    # --------------------------------------------------
    # 11. Merge results for risk analysis
    # --------------------------------------------------
    log_section("Risk Analysis")

    combined_hosts = []
    for pr in port_results:
        host_ip = pr.get("host")

        # Merge vulnerability findings
        vulns = []
        for vr in vuln_results:
            if vr.get("host") == host_ip:
                vulns = vr.get("vulnerabilities", [])
                break

        # Merge web findings as additional vulnerabilities
        for wf in web_by_host.get(host_ip, []):
            finding_text = wf.get("finding") or wf.get("detail", "")
            vulns.append({
                "host":     host_ip,
                "port":     wf.get("port"),
                "protocol": "tcp",
                "script":   wf.get("type") or wf.get("tool", "web"),
                "output":   finding_text,
                "cves":     [wf["cve"]] if wf.get("cve") else [],
                "source":   wf.get("source", "webscan"),
                "category": wf.get("category", "web"),
                "severity": wf.get("severity", "Medium"),
            })

        pr["vulns"] = vulns
        combined_hosts.append(pr)

    risk_analysis = analyze_risk(combined_hosts)
    log_success("Risk analysis complete")

    # --------------------------------------------------
    # 12. Save auxiliary data
    # --------------------------------------------------
    try:
        with open("output/threat_intel.json", "w", encoding="utf-8") as f:
            json.dump(cves, f, indent=4)
        with open("output/host_audit.json",   "w", encoding="utf-8") as f:
            json.dump(host_audit, f, indent=4)
    except Exception as e:
        log_error(f"Failed to save auxiliary files: {e}")

    # --------------------------------------------------
    # 13. Report generation
    # --------------------------------------------------
    log_section("Report Generation")

    report_paths = generate_report(
        hosts               = risk_analysis["hosts"],
        vuln_results        = vuln_results,
        environment         = env_info,
        attack_paths        = risk_analysis.get("attack_paths", []),
        exposure_groups     = risk_analysis.get("exposure_groups", {}),
        network_risk_level  = risk_analysis.get("network_risk_level", "Unknown"),
        network_risk_score  = risk_analysis.get("network_risk_score", 0),
    )

    # --------------------------------------------------
    # 14. Summary
    # --------------------------------------------------
    duration = datetime.now() - start_time
    log_success(f"Scan completed in {duration}")

    if report_paths and isinstance(report_paths, dict):
        if report_paths.get("html"):
            log_success(f"HTML report : {report_paths['html']}")
        if report_paths.get("pdf"):
            log_success(f"PDF  report : {report_paths['pdf']}")
        if report_paths.get("json"):
            log_success(f"JSON report : {report_paths['json']}")
    else:
        log_error("Report generation failed")

    # Print attack path summary to console
    attack_paths = risk_analysis.get("attack_paths", [])
    if attack_paths:
        log_section("Attack Path Summary")
        show_table(
            "Identified Attack Paths",
            ["Severity", "Host", "Title"],
            [(ap["severity"], ap["host"], ap["title"]) for ap in attack_paths],
        )


# --------------------------------------------------
# Entry point
# --------------------------------------------------

if __name__ == "__main__":
    try:
        run_vapt()
    except KeyboardInterrupt:
        log_error("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        log_error(f"Fatal error: {e}")
        sys.exit(1)
