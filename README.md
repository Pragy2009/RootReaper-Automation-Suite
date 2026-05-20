# RootReaper Automation Suite

A production-style, cross-platform **Vulnerability Assessment and Penetration Testing (VAPT)** automation framework that orchestrates multiple security tools, enriches findings with threat intelligence, and generates executive-grade reports.

> Built to simulate how real enterprise security platforms move from raw scan output to actionable security intelligence.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Pipeline](#pipeline)
- [Module Reference](#module-reference)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [External Tools Setup](#external-tools-setup)
- [Usage](#usage)
- [Exploit Mode](#exploit-mode)
- [Output & Reports](#output--reports)
- [Example Session](#example-session)
- [Troubleshooting](#troubleshooting)
- [Security Disclaimer](#security-disclaimer)
- [Author](#author)

---

## Overview

Traditional tools like Nmap and Nikto dump raw text output — useful, but not actionable on their own.

RootReaper solves this by:

- Orchestrating tool execution end-to-end
- Parsing and normalising all outputs into structured data
- Correlating vulnerabilities and mapping attack paths
- Ranking asset criticality and scoring risk (CVSS-aligned)
- Generating a dashboard-style HTML report with charts, evidence, and CVE links
- Exporting a print-ready PDF for client/professor delivery

---

## Features

### Scanning & Enumeration

| Capability | Detail |
|---|---|
| Host discovery | Nmap ping scan (`-sn`) with socket-probe fallback |
| Port scanning | SYN/TCP scan, banner grab, default NSE scripts, OS detection, version intensity 7 |
| Service enumeration | Targeted NSE scripts per service — SMB, FTP, SSH, RDP, HTTP/HTTPS |
| Vulnerability scanning | `--script vuln` (detection) or `--script vuln,exploit` (exploit mode) |
| Web application scanning | Nikto integration, HTTP security header analysis, SSL/TLS weakness detection |
| Host audit | Local firewall status, AV detection, misconfiguration checks (UAC, etc.) |
| Threat intelligence | NVD API — latest Critical CVEs with CVSS scores and NVD links |

### Intelligence Layer

- **Asset criticality ranking** — scores each host by exposed services (RDP, SMB, Telnet = high risk)
- **Attack path analysis** — 10 built-in rules: EternalBlue, RDP exposure, anonymous FTP, Telnet, VNC, web RCE, SQLi, weak SSL, SNMP, and more
- **Validation status** — every finding is tagged `Confirmed`, `Likely`, or `Potential`
- **Likelihood scoring** — `High / Medium / Low` based on CVE presence and NSE confidence
- **Exposure grouping** — vulnerabilities grouped by attack category (RCE, Auth Bypass, Info Disclosure, etc.)
- **CVE extraction** — regex extraction of CVE IDs from all NSE script output
- **CVSS-aligned scoring** — Critical 9.5 / High 8.0 / Medium 5.5 / Low 2.5

### Reporting

- **Interactive HTML dashboard** — Chart.js severity donut, host risk bar chart, risk heatmap (Impact × Likelihood), collapsible evidence panels, CVE NVD links, per-host remediation priority tables
- **PDF export** — print-ready report via weasyprint
- **JSON export** — machine-readable full findings for downstream tooling

---

## Architecture

```
main.py  (orchestrator)
├── utils/
│   ├── logger.py            Rich console output
│   ├── os_detect.py         Platform/environment detection
│   └── dependency_check.py  Validates required + optional binaries
└── scanner/
    ├── network.py           Local subnet detection
    ├── discovery.py         Live host discovery (nmap / socket fallback)
    ├── portscan.py          Parallel port + banner + OS scan
    ├── enumeration.py       Service-specific NSE enumeration (SMB/FTP/SSH/RDP/HTTP)
    ├── vulnscan.py          Parallel vuln scan — NSE vuln (+exploit) scripts
    ├── webscan.py           Nikto + HTTP header analysis + SSL/TLS checks
    ├── host_audit.py        Local host security audit
    ├── threat_intel.py      NVD API — latest critical CVEs
    ├── risk_engine.py       Severity, CVSS, attack paths, asset criticality
    └── report_engine.py     JSON + HTML dashboard + PDF generation
```

---

## Pipeline

```
Environment Validation
        ↓
Subnet Detection  →  User confirms or overrides
        ↓
Host Discovery    →  User selects targets
        ↓
Port Selection    →  User enters port range
        ↓
Exploit Mode?     →  User confirms authorization
        ↓
Port Scan         (banner grab, OS detection, default NSE scripts)
        ↓
Service Enumeration  (SMB, FTP, SSH, RDP, HTTP/HTTPS — targeted NSE)
        ↓
Vulnerability Scan   (NSE vuln scripts; optionally + exploit)
        ↓
Web Application Scan (Nikto + HTTP headers + SSL/TLS)
        ↓
Host Audit           (local machine checks)
        ↓
Threat Intelligence  (NVD — latest Critical CVEs)
        ↓
Risk Analysis        (CVSS scoring, attack paths, asset criticality)
        ↓
Report Generation    (HTML dashboard + JSON + PDF)
```

---

## Module Reference

### scanner/enumeration.py

Runs targeted Nmap NSE scripts grouped by service type:

| Service | NSE Scripts |
|---|---|
| SMB (139/445) | `smb-enum-shares`, `smb-enum-users`, `smb-security-mode`, `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-vuln-cve-2020-0796` |
| FTP (21) | `ftp-anon`, `ftp-bounce`, `ftp-syst` |
| SSH (22) | `ssh-auth-methods`, `ssh-hostkey`, `ssh2-enum-algos` |
| RDP (3389) | `rdp-enum-encryption`, `rdp-vuln-ms12-020` |
| HTTP (80/8080) | `http-headers`, `http-methods`, `http-title`, `http-robots.txt`, `http-auth-finder` |
| HTTPS (443/8443) | All HTTP scripts + `ssl-cert`, `ssl-enum-ciphers`, `tls-ticketbleed`, `ssl-heartbleed` |

### scanner/webscan.py

- **Nikto** — common web vulnerabilities, misconfigurations, outdated software
- **HTTP header analysis** — checks for 7 required security headers (CSP, HSTS, X-Frame-Options, etc.), flags information-leaking headers (Server, X-Powered-By, etc.)
- **SSL/TLS checks** — weak protocols (SSLv2/3, TLS 1.0/1.1), weak ciphers (RC4, DES, NULL, EXPORT), expired/expiring certificates

### scanner/risk_engine.py

**Attack path rules** — automatically triggered when matching ports + vuln keywords are found:

| Rule | Trigger | Severity |
|---|---|---|
| EternalBlue | SMB 445 + ms17-010 keyword | Critical |
| RDP Exposure | Port 3389 open | High |
| Anonymous SMB | SMB + null session keyword | High |
| Anonymous FTP | Port 21 + ftp-anon keyword | High |
| Telnet Exposed | Port 23 open | Critical |
| VNC Exposed | Port 5900 open | High |
| Web RCE | HTTP ports + RCE keyword | Critical |
| SQL Injection | HTTP ports + SQLi keyword | High |
| Weak SSL | HTTPS ports + SSL keyword | Medium |
| SNMP Exposure | Port 161 open | Medium |

---

## Tech Stack

| Component | Library / Tool |
|---|---|
| Language | Python 3.9+ |
| Network scanning | Nmap + python-nmap |
| Web scanning | Nikto |
| Console output | Rich, Colorama |
| HTTP requests | Requests |
| HTML templating | Jinja2 |
| PDF export | Weasyprint |
| Report charts | Chart.js (CDN, client-side) |
| Threat intel | NVD API v2 |
| Host audit | psutil, subprocess |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Pragy2009/RootReaper-Automation-Suite.git
cd RootReaper-Automation-Suite
```

### 2. Create a virtual environment

**Windows**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

---

## External Tools Setup

These must be installed separately — they are not pip packages.

### Nmap (required)

**Linux / Kali**
```bash
sudo apt install nmap
```

**macOS**
```bash
brew install nmap
```

**Windows**
Download the installer from [nmap.org/download.html](https://nmap.org/download.html) and ensure `nmap` is in your `PATH`.

### Nikto (optional — enables web scanning)

**Linux / Kali**
```bash
sudo apt install nikto
```

**macOS**
```bash
brew install nikto
```

> If Nikto is not found, the web scanning stage will skip Nikto and still run HTTP header + SSL/TLS analysis.

### Weasyprint (optional — enables PDF export)

```bash
pip install weasyprint
```

> If weasyprint is not installed, the HTML and JSON reports are still generated. Only the PDF step is skipped.

---

## Usage

RootReaper is an interactive CLI — it guides you through each step:

```bash
python main.py
```

You will be prompted to:

1. Confirm or override the detected subnet
2. Select target hosts from the discovered list (or `all`)
3. Enter a port range (`21,22,80` / `1-1024` / `all`)
4. Confirm exploit mode (see below)

---

## Exploit Mode

During startup the tool asks:

```
Enable exploit mode? Confirm you have authorization (yes/NO):
```

- **NO (default)** — runs `--script vuln` — detection only, no exploitation attempts
- **yes** — runs `--script vuln,exploit` — attempts known exploits via Nmap NSE

> **Only type `yes` if you have written authorization to test the target systems.**
> Unauthorized exploitation is illegal under the Computer Fraud and Abuse Act (CFAA),
> the Computer Misuse Act (CMA), and equivalent laws worldwide.

---

## Output & Reports

All output is written to the `output/` directory (created automatically):

| File | Description |
|---|---|
| `output/report.html` | Interactive dashboard with charts, attack paths, evidence, CVE links |
| `output/report.pdf` | Print-ready PDF (requires weasyprint) |
| `output/report.json` | Full machine-readable findings |
| `output/threat_intel.json` | Latest Critical CVEs from NVD |
| `output/host_audit.json` | Local host audit results |

### HTML Report sections

- **Executive summary** — total hosts, vulnerability counts by severity, overall risk level + score
- **Severity distribution chart** — Chart.js donut chart
- **Host risk bar chart** — risk score per host
- **Risk heatmap** — Impact × Likelihood matrix
- **Attack paths** — auto-generated narratives for identified attack vectors
- **Host details** — per-host open ports, service fingerprints, vulnerability table with evidence, CVE links, remediation priorities
- **Threat intelligence** — latest Critical CVEs with CVSS scores and NVD links

---

## Example Session

```
[STEP] Starting RootReaper Enterprise VAPT Framework

=== Dependency Validation ===
[SUCCESS] Environment validated

=== Subnet Detection ===
Detected Subnet: 192.168.1.0/24
Use this subnet? (Y/n): Y

=== Host Discovery ===
┌────┬───────────────┬──────────┬────────┐
│ ID │ IP            │ Hostname │ Status │
├────┼───────────────┼──────────┼────────┤
│ 1  │ 192.168.1.1   │ router   │ up     │
│ 2  │ 192.168.1.105 │          │ up     │
└────┴───────────────┴──────────┴────────┘
Enter host IDs (comma-separated) or 'all': all

=== Port Selection ===
Enter ports: 1-1024

=== Exploit Mode ===
Enable exploit mode? Confirm you have authorization (yes/NO): NO

[STEP] Port scanning...
[STEP] Service enumeration (SMB/FTP/SSH)...
[STEP] Vulnerability scanning...
[STEP] Web application scanning...
[STEP] Threat intelligence...
[STEP] Risk analysis...
[SUCCESS] HTML report → output/report.html
[SUCCESS] JSON report → output/report.json

=== Attack Path Summary ===
┌──────────┬───────────────┬──────────────────────────────────────────┐
│ Severity │ Host          │ Title                                    │
├──────────┼───────────────┼──────────────────────────────────────────┤
│ Critical │ 192.168.1.105 │ EternalBlue — Critical Propagation Risk  │
│ High     │ 192.168.1.105 │ RDP Exposed — Remote Access Attack Vector│
└──────────┴───────────────┴──────────────────────────────────────────┘
```

---

## Troubleshooting

### Nmap not found
```bash
nmap -v
```
If the command fails, reinstall Nmap and ensure it is in your system `PATH`.

### Permission errors on Linux (raw socket / OS detection)
```bash
sudo python3 main.py
```
SYN scan (`-sS`) and OS detection (`-O`) require root on Linux. The tool falls back to TCP connect scan (`-sT`) automatically when not privileged, but OS detection will be limited.

### PDF not generating
Ensure weasyprint is installed:
```bash
pip install weasyprint
```
On Linux, weasyprint may also require system libraries:
```bash
sudo apt install libpango-1.0-0 libpangoft2-1.0-0
```

### Nikto not found
Web scanning will skip the Nikto step but still run HTTP header and SSL/TLS analysis. To enable full web scanning:
```bash
sudo apt install nikto      # Linux
brew install nikto           # macOS
```

### NVD API rate limits
The NVD public API has a rate limit of 5 requests per 30 seconds without an API key. If threat intelligence fetching fails, the report is still generated without that section.

---

## Security Disclaimer

This tool is intended **solely for authorized security testing and educational purposes**.

- Only scan systems you own or have **explicit written permission** to test
- Exploit mode (`--script exploit`) must never be used without authorization
- The author is not responsible for any misuse or damage caused by this tool

Applicable laws include but are not limited to:
- Computer Fraud and Abuse Act (CFAA) — USA
- Computer Misuse Act (CMA) — UK
- Information Technology Act — India
- Similar legislation in all jurisdictions

---

## Author

**Pragy Jha**
B.Tech CSE — Cyber Security & Digital Forensics

---

## Contributions

Contributions, issues, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Open a Pull Request