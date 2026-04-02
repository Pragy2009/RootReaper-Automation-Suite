"""
report_engine.py

Enterprise Report Generation Engine

Purpose:
Generate enterprise-grade reports in JSON and HTML format
from VAPT scan results.

Supports:
- Risk analysis integration
- Vulnerability details
- Host audit data
- Threat intelligence integration
- Executive summary

Output:
output/report.json
output/report.html
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any

from jinja2 import Template

from utils.logger import (
    log_step,
    log_info,
    log_success,
    log_error
)

OUTPUT_DIR = "output"


def ensure_output_directory():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        log_info(f"Created output directory: {OUTPUT_DIR}")


def load_threat_intel():
    try:
        with open("output/threat_intel.json") as f:
            return json.load(f)
    except:
        return []


def generate_executive_summary(hosts: List[Dict[str, Any]]) -> Dict[str, Any]:

    total_hosts = len(hosts)
    total_vulns = 0

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for host in hosts:
        vulns = host.get("vulns", [])
        total_vulns += len(vulns)

        for vuln in vulns:
            severity = vuln.get("severity", "Info")
            if severity in severity_counts:
                severity_counts[severity] += 1

    return {
        "total_hosts": total_hosts,
        "total_vulnerabilities": total_vulns,
        "severity_breakdown": severity_counts,
        "generated_at": datetime.utcnow().isoformat()
    }


def generate_json_report(report_data: Dict[str, Any]) -> str:

    ensure_output_directory()

    file_path = os.path.join(OUTPUT_DIR, "report.json")

    try:
        with open(file_path, "w") as f:
            json.dump(report_data, f, indent=4)

        log_success(f"JSON report generated: {file_path}")
        return file_path

    except Exception as e:
        log_error(f"Failed to write JSON report: {e}")
        return None


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>Enterprise VAPT Report</title>
<style>
body { font-family: Arial; margin: 40px; }
.Critical { background-color: #ff4d4d; color: white; }
.High { background-color: #ff944d; }
.Medium { background-color: #ffd24d; }
.Low { background-color: #d9ff66; }
.Info { background-color: #e6f2ff; }
table { border-collapse: collapse; width: 100%%; margin-bottom: 20px; }
th, td { border: 1px solid #ccc; padding: 8px; }
</style>
</head>
<body>

<h1>Enterprise VAPT Security Report</h1>

<h2>Executive Summary</h2>
<p>Total Hosts: {{ summary.total_hosts }}</p>
<p>Total Vulnerabilities: {{ summary.total_vulnerabilities }}</p>

<h3>Severity Breakdown</h3>
<table>
<tr><th>Severity</th><th>Count</th></tr>
{% for severity, count in summary.severity_breakdown.items() %}
<tr class="{{ severity }}">
<td>{{ severity }}</td>
<td>{{ count }}</td>
</tr>
{% endfor %}
</table>

<h2>Threat Intelligence</h2>
<table>
<tr><th>CVE ID</th><th>Description</th></tr>
{% for cve in threat_intel %}
<tr>
<td>{{ cve.id }}</td>
<td>{{ cve.description }}</td>
</tr>
{% endfor %}
</table>

<h2>Host Details</h2>
{% for host in hosts %}

<h3>Host: {{ host.host }}</h3>

<h4>Open Ports</h4>
<table>
<tr>
<th>Port</th><th>Protocol</th><th>State</th>
<th>Service</th><th>Product</th><th>Version</th>
</tr>
{% for port in host.ports %}
<tr>
<td>{{ port.port }}</td>
<td>{{ port.protocol }}</td>
<td>{{ port.state }}</td>
<td>{{ port.service }}</td>
<td>{{ port.product }}</td>
<td>{{ port.version }}</td>
</tr>
{% endfor %}
</table>

<h4>Vulnerabilities</h4>
<table>
<tr>
<th>Port</th><th>Script</th><th>Severity</th>
<th>CVSS</th><th>Remediation</th>
</tr>
{% for vuln in host.vulns %}
<tr class="{{ vuln.severity }}">
<td>{{ vuln.port }}</td>
<td>{{ vuln.script }}</td>
<td>{{ vuln.severity }}</td>
<td>{{ vuln.cvss_score }}</td>
<td>{{ vuln.remediation }}</td>
</tr>
{% endfor %}
</table>

{% endfor %}

</body>
</html>
"""


def generate_html_report(report_data: Dict[str, Any]) -> str:

    ensure_output_directory()

    file_path = os.path.join(OUTPUT_DIR, "report.html")

    try:
        template = Template(HTML_TEMPLATE)

        html = template.render(
            summary=report_data["summary"],
            hosts=report_data["hosts"],
            threat_intel=report_data.get("threat_intel", [])
        )

        with open(file_path, "w") as f:
            f.write(html)

        log_success(f"HTML report generated: {file_path}")
        return file_path

    except Exception as e:
        log_error(f"Failed to generate HTML report: {e}")
        return None


def generate_report(hosts, vuln_results, environment):

    log_step("Generating enterprise report")

    summary = generate_executive_summary(hosts)

    report_data = {
        "summary": summary,
        "hosts": hosts,
        "environment": environment,
        "threat_intel": load_threat_intel(),
        "generated_at": datetime.utcnow().isoformat()
    }

    json_path = generate_json_report(report_data)
    html_path = generate_html_report(report_data)

    if not json_path or not html_path:
        return None

    log_success("Report generation complete")

    return {
        "json": json_path,
        "html": html_path
    }