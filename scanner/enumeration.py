"""
enumeration.py

Service-specific enumeration using targeted Nmap NSE scripts.

Coverage:
- SMB  : shares, users, security mode, MS17-010, MS08-067, CVE-2020-0796
- FTP  : anonymous login, bounce, syst banner
- SSH  : auth methods, host keys, algorithm weakness
- RDP  : encryption level, MS12-020
- HTTP : headers, methods, robots.txt, title, auth finder
- HTTPS: all HTTP checks + SSL cert, cipher enumeration, BEAST/POODLE/ticketbleed

Detection only — no exploitation.
"""

import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

from utils.logger import log_step, log_info, log_warning, log_error


# -------------------------------------------------------
# NSE script sets per service category
# -------------------------------------------------------

SERVICE_SCRIPTS: Dict[str, str] = {
    "smb": (
        "smb-enum-shares,smb-enum-users,smb-security-mode,"
        "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2020-0796,"
        "smb2-security-mode"
    ),
    "ftp": "ftp-anon,ftp-bounce,ftp-syst",
    "ssh": "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos",
    "rdp": "rdp-enum-encryption,rdp-vuln-ms12-020",
    "http": (
        "http-headers,http-methods,http-title,http-robots.txt,"
        "http-server-header,http-auth-finder,http-open-redirect"
    ),
    "https": (
        "http-headers,http-methods,http-title,http-robots.txt,"
        "ssl-cert,ssl-enum-ciphers,tls-ticketbleed,ssl-heartbleed"
    ),
}

# Static port → category mapping (catches unlabelled services)
PORT_CATEGORY_MAP: Dict[int, str] = {
    21:   "ftp",
    22:   "ssh",
    80:   "http",
    139:  "smb",
    443:  "https",
    445:  "smb",
    3389: "rdp",
    8080: "http",
    8443: "https",
    8000: "http",
    8888: "http",
    9443: "https",
}

# Service-name substrings → category
SVC_CATEGORY_MAP: Dict[str, str] = {
    "ftp":   "ftp",
    "ssh":   "ssh",
    "http":  "http",
    "https": "https",
    "ssl":   "https",
    "smb":   "smb",
    "netbios": "smb",
    "microsoft-ds": "smb",
    "rdp":   "rdp",
    "ms-wbt-server": "rdp",
}


def _resolve_category(port: int, service_name: str) -> Optional[str]:
    if port in PORT_CATEGORY_MAP:
        return PORT_CATEGORY_MAP[port]
    svc = (service_name or "").lower()
    for key, cat in SVC_CATEGORY_MAP.items():
        if key in svc:
            return cat
    return None


# -------------------------------------------------------
# Single-host enumeration
# -------------------------------------------------------

def enumerate_host(
    host: str,
    open_ports: List[Dict[str, Any]],
    timeout: int = 180,
) -> Dict[str, Any]:
    """
    Run targeted NSE enumeration on a host grouped by service category.
    Returns structured findings per category.
    """
    log_step(f"Enumerating services on {host}")

    result: Dict[str, Any] = {"host": host, "services": {}}

    # Group open ports by service category
    groups: Dict[str, List[int]] = {}
    for pinfo in open_ports:
        if pinfo.get("state") != "open":
            continue
        port = pinfo["port"]
        cat = _resolve_category(port, pinfo.get("service", ""))
        if cat:
            groups.setdefault(cat, []).append(port)

    if not groups:
        log_info(f"No enumerable services detected on {host}")
        return result

    for category, ports in groups.items():
        scripts = SERVICE_SCRIPTS.get(category)
        if not scripts:
            continue

        ports_str = ",".join(str(p) for p in sorted(set(ports)))
        args = f"-sV --script {scripts} -p {ports_str} -T4 --host-timeout 3m"

        log_info(f"  [{category.upper()}] {host}:{ports_str}")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=host, arguments=args, timeout=timeout)

            findings: List[Dict[str, Any]] = []

            if host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        pdata = nm[host][proto][port]
                        for script_name, output in (pdata.get("script") or {}).items():
                            findings.append({
                                "port":     int(port),
                                "script":   script_name,
                                "output":   output,
                                "category": category,
                                "host":     host,
                            })

                for hs in nm[host].get("hostscript") or []:
                    findings.append({
                        "port":     None,
                        "script":   hs.get("id"),
                        "output":   hs.get("output"),
                        "category": category,
                        "host":     host,
                    })

            result["services"][category] = findings
            log_info(f"  [{category.upper()}] {len(findings)} findings on {host}")

        except Exception as e:
            log_error(f"Enumeration [{category}] failed for {host}: {e}")
            result["services"][category] = []

    return result


# -------------------------------------------------------
# Parallel enumeration across multiple hosts
# -------------------------------------------------------

def run_enumeration(
    port_results: List[Dict[str, Any]],
    max_workers: int = 4,
) -> List[Dict[str, Any]]:
    """
    Run service-specific enumeration across all discovered hosts in parallel.
    """
    log_step(f"Starting service enumeration on {len(port_results)} host(s)")

    targets = [
        (hd.get("host"), hd.get("ports", []))
        for hd in port_results
        if hd.get("host") and hd.get("ports")
    ]

    if not targets:
        log_warning("No hosts with open ports for enumeration")
        return []

    all_results: List[Dict[str, Any]] = []
    worker_count = min(max_workers, len(targets))

    with ThreadPoolExecutor(max_workers=worker_count) as exe:
        futures = {
            exe.submit(enumerate_host, host, ports): host
            for host, ports in targets
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                all_results.append(future.result())
            except Exception as e:
                log_error(f"Enumeration failed for {host}: {e}")
                all_results.append({"host": host, "services": {}})

    log_step("Service enumeration complete")
    return all_results


# -------------------------------------------------------
# Utility: flatten into a single findings list
# -------------------------------------------------------

def flatten_enum_findings(
    enum_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    flat: List[Dict[str, Any]] = []
    for host_result in enum_results:
        for findings in host_result.get("services", {}).values():
            flat.extend(findings)
    return flat
