# 🔥 RootReaper Automation Suite

A production-style, cross-platform **Vulnerability Assessment and Penetration Testing (VAPT)** automation framework that integrates multiple security tools, correlates findings, and generates structured, actionable reports.

🚀 **RootReaper Automation Suite** is designed to simulate how enterprise-grade security platforms perform automated scanning, vulnerability intelligence, and reporting.

A production-style, cross-platform **Vulnerability Assessment and Penetration Testing (VAPT)** automation framework that integrates multiple security tools, correlates findings, and generates structured, actionable reports.

This project is designed to simulate how real-world security tools orchestrate scans and produce intelligence instead of raw outputs.

---

# 📌 Table of Contents

* Overview
* Features
* Architecture
* Tech Stack
* Installation
* Setup External Tools
* Usage
* Workflow (Step-by-Step)
* Output & Reports
* Example Run
* Troubleshooting
* Future Enhancements
* Security Disclaimer

---

# 🧠 Overview

Traditional security tools like Nmap or Nikto generate **raw scan outputs**.

This framework solves that problem by:

* Automating tool execution
* Parsing outputs into structured data
* Correlating vulnerabilities
* Assigning severity levels
* Generating readable reports

👉 Think of this as a **mini enterprise-grade vulnerability scanner**.

---

# 🚀 Features

### 🔎 Scanning

* Network scanning (ports, services, OS detection)
* Web vulnerability scanning
* Extensible for additional tools

### ⚙️ Automation

* Central orchestration engine
* Sequential + modular scanning pipeline

### 🧠 Intelligence Layer

* CVE mapping (extendable)
* Severity classification
* Duplicate vulnerability filtering

### 📄 Reporting

* Clean HTML reports
* Optional PDF export
* Structured findings with recommendations

---

# 🧱 Architecture

```
User Input
    ↓
Orchestrator
    ↓
[ Nmap Scan ] → [ Parser ]
    ↓
[ Web Scan ] → [ Parser ]
    ↓
Correlation Engine
    ↓
Report Generator
    ↓
Final Output (HTML/PDF)
```

### Core Components

| Module   | Responsibility                    |
| -------- | --------------------------------- |
| scanner/ | Runs external tools               |
| parser/  | Extracts structured data          |
| core/    | Logic, orchestration, correlation |
| reports/ | Templates + output                |
| utils/   | Helper functions                  |

---

# 🛠️ Tech Stack

* Python 3.9+
* Nmap (network scanning)
* Nikto (web scanning)
* Jinja2 (templating)
* Pandas (data processing)

---

# ⚙️ Installation

### 1. Clone Repository

```bash
git clone https://github.com/your-username/vapt-framework.git
cd vapt-framework
```

### 2. Create Virtual Environment

```bash
python -m venv venv
```

Activate:

**Windows**

```bash
venv\Scripts\activate
```

**Linux / Mac**

```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🧰 Setup External Tools

These tools must be installed separately (not via pip):

## Install Nmap

**Linux**

```bash
sudo apt install nmap
```

**Mac**

```bash
brew install nmap
```

**Windows**

* Download from: [https://nmap.org/download.html](https://nmap.org/download.html)

---

## Install Nikto

```bash
sudo apt install nikto
```

---

## Optional: Nessus / OpenVAS

Used for advanced vulnerability scanning.

---

# ▶️ Usage

## Basic Scan

```bash
python main.py --target example.com --mode basic
```

## Web Scan

```bash
python main.py --target example.com --mode web
```

## Full Scan

```bash
python main.py --target example.com --mode full
```

---

# ⚙️ CLI Arguments

| Argument | Description         |
| -------- | ------------------- |
| --target | Target domain or IP |
| --mode   | basic / web / full  |
| --output | html / pdf          |

---

# 🔄 Workflow (Detailed)

### Step 1: Input

User provides:

* Target (IP/domain)
* Scan mode

### Step 2: Network Scan

* Nmap scans open ports and services
* Output saved in XML format

### Step 3: Parsing

* XML parsed using lxml
* Extract:

  * Ports
  * Services
  * Versions

### Step 4: Web Scan

* Triggered if HTTP/HTTPS detected
* Nikto scans for vulnerabilities

### Step 5: Correlation Engine

* Matches services with known vulnerabilities
* Assigns severity

### Step 6: Report Generation

* Data passed into HTML templates
* Optional PDF conversion

---

# 📊 Output & Reports

Generated in:

```
/reports/output/
```

## Report Includes

* Scan summary
* Open ports
* Vulnerabilities
* Severity levels
* Recommendations

---

# 🧪 Example Run

```bash
python main.py --target scanme.nmap.org --mode full
```

Output:

```
[+] Running Nmap scan...
[+] Parsing results...
[+] Running web scan...
[+] Generating report...
[✔] Report saved to /reports/output/
```

---

# 🐞 Troubleshooting

### Nmap not found

```bash
nmap -v
```

If not installed, install Nmap.

### Permission issues (Linux)

```bash
sudo python main.py --target <target>
```

### PDF not generating

Install wkhtmltopdf:

```bash
sudo apt install wkhtmltopdf
```

---

# 🚀 Future Enhancements

* AI-based vulnerability prioritization
* Multi-threaded scanning
* Web dashboard (React/Next.js)
* REST API (FastAPI)
* CVE database integration

---

# ⚠️ Security Disclaimer

This tool is intended **only for educational purposes and authorized testing**.

Do NOT scan systems without explicit permission.

---

# 🧠 Why RootReaper?

Unlike basic scripts that just execute tools, RootReaper focuses on:

* Intelligent orchestration
* Data normalization
* Vulnerability correlation
* Actionable reporting

👉 It bridges the gap between **tool execution** and **security intelligence**.

---

# 👨‍💻 Author

Pragy Jha
B.Tech CSE (Cyber Security & Digital Forensics)

---

# ⭐ Contribution

Contributions are welcome!

1. Fork the repo
2. Create a new branch
3. Commit changes
4. Submit a PR
