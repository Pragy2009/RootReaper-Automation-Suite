"""
os_detect.py

Purpose:
Detect operating system and check required tools availability.
Cross-platform compatible (Windows, Linux, Mac).
"""

import platform
import shutil
import sys


def get_os():
    """
    Returns the operating system name.
    Example: Windows, Linux, Darwin
    """
    return platform.system()


def get_os_version():
    """
    Returns OS version info
    """
    return platform.version()


def get_architecture():
    """
    Returns system architecture
    Example: x86_64, AMD64
    """
    return platform.machine()


def get_python_version():
    """
    Returns Python version string
    """
    return sys.version.split()[0]


def is_windows():
    """
    Returns True if running on Windows
    """
    return get_os() == "Windows"


def is_linux():
    """
    Returns True if running on Linux
    """
    return get_os() == "Linux"


def is_mac():
    """
    Returns True if running on macOS
    """
    return get_os() == "Darwin"


def is_nmap_installed():
    """
    Checks if Nmap is installed and accessible
    """
    return shutil.which("nmap") is not None


def get_environment_info():
    """
    Returns full environment info as dictionary
    Useful for logging and reporting
    """
    return {
        "os": get_os(),
        "os_version": get_os_version(),
        "architecture": get_architecture(),
        "python_version": get_python_version(),
        "nmap_installed": is_nmap_installed()
    }
