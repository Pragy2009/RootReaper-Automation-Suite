"""
discovery.py

Enterprise Host Discovery Module

Purpose:
- Discover live hosts on subnet
- Uses Nmap for reliable enterprise detection
- Falls back to socket probing if needed
- Cross-platform compatible

Supports:
Linux, Windows, macOS
"""

import ipaddress
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

import nmap

from utils.logger import log_step, log_info, log_error, log_warning


# -----------------------------
# Primary Method: Nmap Discovery
# -----------------------------

def discover_hosts_nmap(subnet, timeout=60):
    """
    Uses Nmap ping scan (-sn) to detect live hosts.
    Most reliable enterprise method.
    """

    log_step(f"Running Nmap host discovery on {subnet}")

    live_hosts = []

    try:

        nm = nmap.PortScanner()

        nm.scan(
            hosts=subnet,
            arguments="-sn -T4",
            timeout=timeout
        )

        for host in nm.all_hosts():

            state = nm[host].state()

            if state == "up":

                live_hosts.append({
                    "ip": host,
                    "hostname": nm[host].hostname(),
                    "status": state
                })

        log_info(f"Nmap discovered {len(live_hosts)} live hosts")

        return live_hosts

    except Exception as e:

        log_error(f"Nmap discovery failed: {e}")

        return []


# -----------------------------
# Fallback Method: Socket Probe
# -----------------------------

COMMON_PORTS = [22, 80, 443, 445, 3389]


def probe_host(ip):
    """
    Attempts socket connection on common ports
    """

    for port in COMMON_PORTS:

        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(0.5)

            result = sock.connect_ex((ip, port))

            sock.close()

            if result == 0:

                return {
                    "ip": ip,
                    "hostname": None,
                    "status": "up"
                }

        except:
            pass

    return None


def discover_hosts_socket(subnet, max_threads=100):
    """
    Fallback host discovery without Nmap.
    Uses socket probing.
    """

    log_warning("Using fallback socket discovery")

    live_hosts = []

    network = ipaddress.IPv4Network(subnet, strict=False)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:

        futures = []

        for ip in network.hosts():

            futures.append(
                executor.submit(probe_host, str(ip))
            )

        for future in as_completed(futures):

            result = future.result()

            if result:

                live_hosts.append(result)

    log_info(f"Socket discovery found {len(live_hosts)} hosts")

    return live_hosts


# -----------------------------
# Main Enterprise Discovery Function
# -----------------------------

def discover_hosts(subnet):
    """
    Enterprise host discovery pipeline

    Steps:
    1. Try Nmap discovery
    2. If fails, fallback to socket probing
    """

    log_step("Starting host discovery pipeline")

    # Primary method
    hosts = discover_hosts_nmap(subnet)

    if hosts:
        return hosts

    # Fallback method
    log_warning("Nmap discovery returned no hosts, trying fallback")

    hosts = discover_hosts_socket(subnet)

    return hosts


# -----------------------------
# Utility: Extract only IPs
# -----------------------------

def extract_ips(hosts):
    """
    Extract plain IP list from structured host list
    """

    return [host["ip"] for host in hosts]
