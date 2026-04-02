"""
network.py

Purpose:
Detect local IP and subnet in cross-platform way.
Works on Linux, Windows, and macOS.
"""

import socket
import ipaddress
from utils.logger import log_step, log_info, log_error


def get_local_ip():
    """
    Detects local IP address by connecting to external endpoint.
    Does not send data.
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # connect to public DNS (no packets actually sent)
        sock.connect(("8.8.8.8", 80))

        ip = sock.getsockname()[0]

        sock.close()

        log_info(f"Local IP detected: {ip}")

        return ip

    except Exception as e:

        log_error(f"Failed to detect local IP: {e}")

        return None


def get_subnet():
    """
    Calculates subnet based on local IP.
    Default assumes /24 subnet.
    """

    log_step("Detecting subnet")

    ip = get_local_ip()

    if ip is None:
        return None

    try:

        network = ipaddress.IPv4Network(ip + "/24", strict=False)

        subnet = str(network)

        log_info(f"Subnet detected: {subnet}")

        return subnet

    except Exception as e:

        log_error(f"Subnet detection failed: {e}")

        return None
