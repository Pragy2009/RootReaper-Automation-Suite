"""
webscan.py

Web application scanning module.

Covers:
- Nikto web vulnerability scanner integration
- HTTP security header analysis (missing headers, information leakage)
- SSL/TLS weakness detection (weak protocols, ciphers, expired certs)

Detection-only — no exploitation.
"""

import ssl
import socket
import shutil
import subprocess
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

import requests
import urllib3

from utils.logger import log_step, log_info, log_warning, log_error

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# -------------------------------------------------------
# Constants
# -------------------------------------------------------

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443}

REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

LEAKY_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
]

WEAK_CIPHERS = {"RC4", "DES", "NULL", "EXPORT", "MD5", "ANON"}

BROWSER_UA = "Mozilla/5.0 (compatible; RootReaperVAPT/1.0)"


# -------------------------------------------------------
# Web service detection
# -------------------------------------------------------

def detect_web_ports(port_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify HTTP/HTTPS services from port scan results.
    Returns a list of web targets with host, port, and ssl flag.
    """
    targets: List[Dict[str, Any]] = []

    for host_data in port_results:
        host = host_data.get("host")
        if not host:
            continue

        for pinfo in host_data.get("ports", []):
            if pinfo.get("state") != "open":
                continue

            port    = pinfo.get("port", 0)
            service = (pinfo.get("service") or "").lower()
            product = (pinfo.get("product") or "").lower()

            is_ssl = (
                port in {443, 8443, 9443}
                or "https" in service
                or "ssl"   in service
                or "tls"   in service
            )

            is_web = (
                port in WEB_PORTS
                or "http"   in service
                or "web"    in service
                or "apache" in product
                or "nginx"  in product
                or "iis"    in product
                or "tomcat" in product
            )

            if is_web:
                targets.append({
                    "host":    host,
                    "port":    port,
                    "ssl":     is_ssl,
                    "service": service,
                    "product": pinfo.get("product", ""),
                    "version": pinfo.get("version", ""),
                })

    log_info(f"Detected {len(targets)} web service(s) across {len(port_results)} host(s)")
    return targets


# -------------------------------------------------------
# Nikto scan
# -------------------------------------------------------

def run_nikto(
    host: str,
    port: int,
    use_ssl: bool = False,
    timeout: int = 120,
) -> List[Dict[str, Any]]:
    """
    Execute Nikto against a web target and parse structured findings.
    Silently skips if Nikto binary is not found.
    """
    nikto_bin = shutil.which("nikto") or shutil.which("nikto.pl")
    if not nikto_bin:
        log_warning(f"Nikto not found — skipping web scan on {host}:{port}")
        return []

    scheme = "https" if use_ssl else "http"
    log_step(f"Running Nikto on {scheme}://{host}:{port}")

    # -Tuning: 1=interesting files, 2=misconfiguration, 4=XSS, 6=DoS (detection only), 9=SQL injection
    cmd = [
        nikto_bin, "-h", host, "-p", str(port),
        "-nointeractive", "-Tuning", "1 2 4 9 b",
        "-maxtime", str(timeout),
    ]
    if use_ssl:
        cmd += ["-ssl"]

    findings: List[Dict[str, Any]] = []

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
        raw = proc.stdout + proc.stderr

        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            text = line.lstrip("+ ").strip()
            if not text or "Start Time" in text or "End Time" in text:
                continue

            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", line, re.IGNORECASE)
            cve = cve_match.group(0).upper() if cve_match else None

            severity = "High" if cve else "Medium"

            findings.append({
                "host":     host,
                "port":     port,
                "tool":     "nikto",
                "finding":  text,
                "cve":      cve,
                "severity": severity,
                "category": "web",
                "source":   "nikto",
            })

        log_info(f"Nikto: {len(findings)} issues on {scheme}://{host}:{port}")

    except subprocess.TimeoutExpired:
        log_warning(f"Nikto timed out on {host}:{port}")
    except Exception as e:
        log_error(f"Nikto error on {host}:{port}: {e}")

    return findings


# -------------------------------------------------------
# HTTP security header analysis
# -------------------------------------------------------

def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:120] if m else None


def analyze_http_headers(
    host: str,
    port: int,
    use_ssl: bool = False,
) -> Dict[str, Any]:
    """
    Fetch HTTP response headers and evaluate security posture.
    Returns findings list with severity and category.
    """
    scheme = "https" if use_ssl else "http"
    url    = f"{scheme}://{host}:{port}/"

    result: Dict[str, Any] = {
        "host":            host,
        "port":            port,
        "url":             url,
        "missing_headers": [],
        "leaky_headers":   [],
        "server_info":     None,
        "page_title":      None,
        "status_code":     None,
        "findings":        [],
    }

    try:
        resp = requests.get(
            url,
            timeout=10,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": BROWSER_UA},
        )

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Missing security headers
        for hdr in REQUIRED_SECURITY_HEADERS:
            if hdr.lower() not in headers_lower:
                result["missing_headers"].append(hdr)
                sev = "Medium" if hdr in {
                    "Content-Security-Policy",
                    "Strict-Transport-Security",
                } else "Low"
                result["findings"].append({
                    "type":     "missing_header",
                    "detail":   f"Missing security header: {hdr}",
                    "severity": sev,
                    "category": "web_config",
                })

        # Information-leaking headers
        for hdr in LEAKY_HEADERS:
            val = resp.headers.get(hdr)
            if val:
                result["leaky_headers"].append(f"{hdr}: {val}")
                result["server_info"] = result["server_info"] or val
                result["findings"].append({
                    "type":     "leaky_header",
                    "detail":   f"Information disclosure via {hdr}: {val}",
                    "severity": "Low",
                    "category": "information_disclosure",
                })

        # Unencrypted HTTP
        if not use_ssl and port in {80, 8080, 8000}:
            result["findings"].append({
                "type":     "plaintext_http",
                "detail":   "Service accessible over unencrypted HTTP — credentials transmitted in clear text",
                "severity": "Medium",
                "category": "encryption",
            })

        # HTTPS without HSTS
        if use_ssl and "strict-transport-security" not in headers_lower:
            result["findings"].append({
                "type":     "missing_hsts",
                "detail":   "HTTPS service missing Strict-Transport-Security — HSTS downgrade attack possible",
                "severity": "Medium",
                "category": "web_config",
            })

        result["status_code"] = resp.status_code
        result["page_title"]  = _extract_title(resp.text)

    except requests.exceptions.ConnectionError:
        result["findings"].append({
            "type":     "connection_error",
            "detail":   f"Could not connect to {url}",
            "severity": "Info",
            "category": "connectivity",
        })
    except Exception as e:
        log_warning(f"Header analysis failed for {url}: {e}")

    return result


# -------------------------------------------------------
# SSL/TLS weakness detection
# -------------------------------------------------------

def check_ssl_tls(host: str, port: int) -> Dict[str, Any]:
    """
    Connect via SSL/TLS and inspect protocol version, cipher, and certificate.
    """
    result: Dict[str, Any] = {
        "host":      host,
        "port":      port,
        "protocol":  None,
        "cipher":    None,
        "cert_info": {},
        "issues":    [],
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with ctx.wrap_socket(
            socket.create_connection((host, port), timeout=10),
            server_hostname=host,
        ) as sock:

            cert    = sock.getpeercert()
            cipher  = sock.cipher()
            protocol = sock.version()

            result["protocol"] = protocol
            result["cipher"]   = cipher[0] if cipher else None

            # Weak protocol
            if protocol in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
                result["issues"].append({
                    "type":     "weak_protocol",
                    "detail":   f"Weak SSL/TLS protocol negotiated: {protocol} — vulnerable to POODLE/BEAST",
                    "severity": "High",
                })

            # Weak cipher
            if cipher:
                cipher_name = cipher[0] or ""
                if any(w in cipher_name.upper() for w in WEAK_CIPHERS):
                    result["issues"].append({
                        "type":     "weak_cipher",
                        "detail":   f"Weak cipher suite in use: {cipher_name}",
                        "severity": "High",
                    })

            # Certificate validity
            if cert:
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    now       = datetime.utcnow()
                    if not_after < now:
                        result["issues"].append({
                            "type":     "expired_cert",
                            "detail":   f"SSL certificate expired: {not_after_str}",
                            "severity": "High",
                        })
                    elif (not_after - now).days < 30:
                        result["issues"].append({
                            "type":     "expiring_cert",
                            "detail":   f"SSL certificate expires in <30 days: {not_after_str}",
                            "severity": "Medium",
                        })

                result["cert_info"] = {
                    "subject":  dict(x[0] for x in cert.get("subject", [])),
                    "issuer":   dict(x[0] for x in cert.get("issuer",  [])),
                    "not_after": not_after_str,
                }

    except ssl.SSLError as e:
        result["issues"].append({
            "type":     "ssl_error",
            "detail":   f"SSL handshake error: {e}",
            "severity": "Medium",
        })
    except Exception:
        pass

    return result


# -------------------------------------------------------
# Orchestrator
# -------------------------------------------------------

def run_web_scans(port_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run the full web scanning pipeline (headers + SSL + Nikto) across
    all detected web services. Returns per-service result objects.
    """
    web_targets = detect_web_ports(port_results)

    if not web_targets:
        log_info("No web services detected — skipping web scanning")
        return []

    all_results: List[Dict[str, Any]] = []

    for target in web_targets:
        host     = target["host"]
        port     = target["port"]
        use_ssl  = target["ssl"]

        host_web: Dict[str, Any] = {
            "host":            host,
            "port":            port,
            "ssl":             use_ssl,
            "nikto_findings":  [],
            "header_findings": {},
            "ssl_findings":    {},
            "all_findings":    [],
        }

        # 1. HTTP header analysis
        header_result = analyze_http_headers(host, port, use_ssl)
        host_web["header_findings"] = header_result
        host_web["all_findings"].extend(header_result.get("findings", []))

        # 2. SSL/TLS check (HTTPS only)
        if use_ssl:
            ssl_result = check_ssl_tls(host, port)
            host_web["ssl_findings"] = ssl_result
            host_web["all_findings"].extend(ssl_result.get("issues", []))

        # 3. Nikto
        nikto = run_nikto(host, port, use_ssl)
        host_web["nikto_findings"] = nikto
        host_web["all_findings"].extend(nikto)

        total = len(host_web["all_findings"])
        scheme = "https" if use_ssl else "http"
        log_info(f"Web scan complete: {scheme}://{host}:{port} — {total} finding(s)")

        all_results.append(host_web)

    return all_results
