"""
host_audit.py

Enterprise host security audit module.
Integrates your original code with enhancements.
"""

import socket
import subprocess
import platform
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import log_step, log_info


# ---------------------------------------------------
# Local Port Scan
# ---------------------------------------------------

def scan_local_ports(port_range=(1, 1024)):

    log_step("Scanning localhost open ports")

    ip = "127.0.0.1"
    open_ports = []

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)

            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                return port

        except:
            pass

        return None

    with ThreadPoolExecutor(max_workers=200) as executor:

        futures = [
            executor.submit(check_port, port)
            for port in range(port_range[0], port_range[1])
        ]

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort()

    log_info(f"Found {len(open_ports)} open localhost ports")

    return open_ports


# ---------------------------------------------------
# Firewall Status
# ---------------------------------------------------

def get_firewall_status():

    log_step("Checking firewall status")

    os_type = platform.system().lower()

    try:

        if os_type == "windows":

            output = subprocess.check_output(
                ["netsh", "advfirewall", "show", "allprofiles"]
            ).decode()

            return "ON" if "State ON" in output else "OFF"

        elif os_type == "linux":

            try:
                output = subprocess.check_output(
                    ["ufw", "status"],
                    stderr=subprocess.STDOUT
                ).decode()

            except subprocess.CalledProcessError as e:
                output = e.output.decode()

            return output.strip()

        else:
            return "Unsupported OS"

    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------
# Security Software Detection
# ---------------------------------------------------

def detect_security_software():

    log_step("Detecting security software")

    keywords = [
        "defender", "avast", "avg", "kaspersky",
        "bitdefender", "mcafee", "norton",
        "crowdstrike", "sentinel", "malwarebytes"
    ]

    results = []

    for proc in psutil.process_iter(["name"]):
        try:
            name = proc.info["name"]
            if name:
                name = name.lower()

                for keyword in keywords:
                    if keyword in name:
                        results.append(name)

        except:
            pass

    return list(set(results))


# ---------------------------------------------------
# Misconfiguration Checks
# ---------------------------------------------------

def check_host_misconfigurations():

    log_step("Checking host misconfigurations")

    findings = []

    if platform.system().lower() == "windows":

        try:
            output = subprocess.check_output(
                'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA',
                shell=True
            ).decode()

            if "0x0" in output:
                findings.append("UAC disabled")

        except:
            pass

    return findings


# ---------------------------------------------------
# Full Host Audit
# ---------------------------------------------------

def run_host_audit():

    log_step("Running host audit")

    return {
        "open_ports": scan_local_ports(),
        "firewall": get_firewall_status(),
        "security_software": detect_security_software(),
        "misconfigurations": check_host_misconfigurations()
    }