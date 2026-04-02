"""
dependency_check.py

Validates required external binaries and Python modules.
Does NOT auto-install silently (enterprise safe).
"""

import shutil
import importlib
from utils.logger import log_info, log_error


REQUIRED_PYTHON_MODULES = [
    "nmap",
    "psutil",
    "requests",
    "jinja2"
]

REQUIRED_BINARIES = [
    "nmap"
]


def check_python_modules():

    missing = []

    for module in REQUIRED_PYTHON_MODULES:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)

    if missing:
        log_error(f"Missing Python modules: {missing}")
        log_error("Install using: pip install -r requirements.txt")
        return False

    log_info("All Python dependencies satisfied")
    return True


def check_binaries():

    missing = []

    for binary in REQUIRED_BINARIES:
        if shutil.which(binary) is None:
            missing.append(binary)

    if missing:
        log_error(f"Missing system tools: {missing}")
        return False

    log_info("All required binaries available")
    return True


def validate_environment():

    return (
        check_python_modules()
        and check_binaries()
    )