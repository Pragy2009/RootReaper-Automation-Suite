"""
scanner/portscan.py

Purpose:
- Perform cross-platform, enterprise-minded port & service scanning using nmap (python-nmap wrapper).
- Choose safe defaults, fall back to connect scan on non-privileged environments.
- Parse and return structured results suitable for reporting.

Notes:
- Requires nmap binary installed and python-nmap library available in venv.
- Does not perform exploitation.
"""

import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Union, Dict, Any

import nmap

from utils.os_detect import is_linux, get_environment_info
from utils.logger import log_step, log_info, log_warning, log_error

logger = logging.getLogger("enterprise_vapt.portscan")


def _is_privileged() -> bool:
    """
    Returns True if process looks privileged (root on Linux).
    On Windows, assume user installed nmap and allowed raw sockets if needed.
    """
    try:
        if is_linux():
            return os.geteuid() == 0
    except Exception:
        pass
    return False


def _build_nmap_args(ports: Union[str, List[int]]):
    """
    Construct nmap argument string based on privileges and chosen ports.
    """
    privileged = _is_privileged()

    # If ports is a list, convert to comma separated string
    if isinstance(ports, list):
        ports_arg = ",".join(str(p) for p in ports)
    else:
        ports_arg = str(ports)

    # Use SYN scan if privileged, otherwise TCP connect scan (-sT)
    scan_type = "-sS" if privileged else "-sT"

    # -sV to detect service/version, -Pn skip host discovery (we already discovered), -T4 speed
    args = f"{scan_type} -sV -O -p {ports_arg} -T4 --min-rate 50"

    return args


def _parse_nmap_result(nm: nmap.PortScanner, host: str) -> Dict[str, Any]:
    """
    Convert python-nmap result for a single host into structured dict.
    """
    host_entry = {
        "host": host,
        "state": None,
        "os_fingerprint": None,
        "ports": [],
        "host_scripts": []
    }

    if host not in nm.all_hosts():
        host_entry["state"] = "unknown"
        return host_entry

    host_state = nm[host].state()
    host_entry["state"] = host_state

    # OS fingerprint if available
    try:
        if "osmatch" in nm[host]:
            host_entry["os_fingerprint"] = nm[host]["osmatch"]
    except Exception:
        pass

    for proto in nm[host].all_protocols():
        proto_ports = nm[host][proto].keys()
        for port in sorted(proto_ports):
            pinfo = nm[host][proto][port]
            script_outputs = pinfo.get("script", {}) or {}
            host_entry["ports"].append({
                "port": int(port),
                "protocol": proto,
                "state": pinfo.get("state"),
                "service": pinfo.get("name"),
                "product": pinfo.get("product"),
                "version": pinfo.get("version"),
                "extrainfo": pinfo.get("extrainfo"),
                "scripts": script_outputs
            })

    # host-level scripts (hostscript)
    try:
        host_scripts = nm[host].get("hostscript", [])
        for hs in host_scripts:
            # hostscript entries are dicts with 'id' and 'output'
            host_entry["host_scripts"].append(hs)
    except Exception:
        pass

    return host_entry


def scan_host(host: str, ports: Union[str, List[int]] = "1-65535", timeout: int = 300) -> Dict[str, Any]:
    """
    Scan single host for specified ports (string like '1-1024' or list of ints).
    Returns parsed dict with ports and service info.
    """
    log_step(f"Port scanning host: {host}")

    if not nmap.PortScanner().nmap_version():  # quick check
        log_warning("nmap binary may not be accessible; ensure nmap is installed and in PATH")

    nm = nmap.PortScanner()  # create new scanner instance for thread-safety

    args = _build_nmap_args(ports)

    try:
        nm.scan(hosts=host, arguments=args, timeout=timeout)
    except nmap.PortScannerError as e:
        log_error(f"nmap error while scanning {host}: {e}")
        return {"host": host, "error": str(e)}
    except Exception as e:
        log_error(f"Unexpected error during portscan for {host}: {e}")
        return {"host": host, "error": str(e)}

    parsed = _parse_nmap_result(nm, host)
    log_info(f"Completed portscan for {host}: {len(parsed.get('ports',[]))} ports parsed")
    return parsed


def scan_hosts_parallel(hosts: List[str], ports: Union[str, List[int]] = "1-1024", workers: int = 4) -> List[Dict[str, Any]]:
    """
    High-level routine to scan many hosts concurrently.
    Returns list of parsed host scan results.
    """
    results = []
    log_step(f"Starting parallel portscan for {len(hosts)} host(s) with {workers} worker(s)")

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(scan_host, host, ports): host for host in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                log_error(f"scan failed for {host}: {e}")
                results.append({"host": host, "error": str(e)})

    log_step("Parallel portscan finished")
    return results