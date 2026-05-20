"""
report_engine.py

Enterprise VAPT Report Generation Engine

Outputs:
  output/report.json  — machine-readable full findings
  output/report.html  — interactive dashboard (Chart.js, collapsible evidence)
  output/report.pdf   — print-ready PDF via weasyprint (optional)
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

from jinja2 import Template

from utils.logger import log_step, log_info, log_success, log_error, log_warning

OUTPUT_DIR = "output"


# -------------------------------------------------------
# Helpers
# -------------------------------------------------------

def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_threat_intel() -> list:
    try:
        with open(os.path.join(OUTPUT_DIR, "threat_intel.json")) as f:
            return json.load(f)
    except Exception:
        return []


def generate_executive_summary(hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    total_vulns = 0

    for host in hosts:
        for v in host.get("vulns", []):
            total_vulns += 1
            sev = v.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

    return {
        "total_hosts":         len(hosts),
        "total_vulnerabilities": total_vulns,
        "severity_breakdown":  counts,
        "generated_at":        datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


# -------------------------------------------------------
# JSON report
# -------------------------------------------------------

def generate_json_report(report_data: Dict[str, Any]) -> Optional[str]:
    ensure_output_dir()
    path = os.path.join(OUTPUT_DIR, "report.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, default=str)
        log_success(f"JSON report → {path}")
        return path
    except Exception as e:
        log_error(f"JSON report failed: {e}")
        return None


# -------------------------------------------------------
# HTML template
# -------------------------------------------------------

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RootReaper VAPT Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#2d3436;font-size:14px}

/* ---- HEADER ---- */
header{background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);color:#fff;padding:32px 48px}
header h1{font-size:1.9rem;letter-spacing:2px;font-weight:700}
header .subtitle{font-size:.85rem;opacity:.65;margin-top:6px}
header .badges{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
.risk-badge{padding:5px 18px;border-radius:20px;font-weight:700;font-size:.85rem}
.rb-Critical{background:#d63031;color:#fff}
.rb-High{background:#e17055;color:#fff}
.rb-Medium{background:#fdcb6e;color:#2d3436}
.rb-Low{background:#55efc4;color:#2d3436}
.rb-Secure{background:#00b894;color:#fff}

/* ---- LAYOUT ---- */
.container{max-width:1440px;margin:0 auto;padding:28px 40px}

/* ---- SECTION TITLES ---- */
.sec-title{font-size:1.15rem;font-weight:700;color:#2d3436;border-left:4px solid #6c5ce7;padding-left:12px;margin:36px 0 14px}

/* ---- METRIC CARDS ---- */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:28px}
.card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 10px rgba(0,0,0,.07)}
.card .lbl{font-size:.72rem;text-transform:uppercase;letter-spacing:1px;color:#636e72;margin-bottom:6px}
.card .val{font-size:2rem;font-weight:800}
.card.c-crit .val{color:#d63031}
.card.c-high .val{color:#e17055}
.card.c-med  .val{color:#f39c12}
.card.c-low  .val{color:#00b894}
.card.c-info .val{color:#6c5ce7}
.card{border-top:4px solid #dfe6e9}
.card.c-crit{border-top-color:#d63031}
.card.c-high{border-top-color:#e17055}
.card.c-med {border-top-color:#fdcb6e}
.card.c-low {border-top-color:#55efc4}
.card.c-info{border-top-color:#6c5ce7}

/* ---- CHARTS ---- */
.charts{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px}
@media(max-width:860px){.charts{grid-template-columns:1fr}}
.chart-box{background:#fff;border-radius:12px;padding:22px;box-shadow:0 2px 10px rgba(0,0,0,.07)}
.chart-box h4{font-size:.78rem;text-transform:uppercase;letter-spacing:1px;color:#636e72;margin-bottom:14px}
.chart-box canvas{max-height:270px}

/* ---- HEATMAP ---- */
.heatmap-wrap{background:#fff;border-radius:12px;padding:22px;box-shadow:0 2px 10px rgba(0,0,0,.07);overflow-x:auto}
.heatmap-wrap table{width:100%;border-collapse:separate;border-spacing:4px}
.heatmap-wrap th{background:#2d3436;color:#fff;padding:10px 14px;font-size:.78rem;text-align:center;border-radius:6px}
.heatmap-wrap td{padding:12px 10px;text-align:center;font-weight:700;font-size:.8rem;border-radius:6px}
.hm-c{background:#d63031;color:#fff}
.hm-h{background:#e17055;color:#fff}
.hm-m{background:#fdcb6e;color:#2d3436}
.hm-l{background:#55efc4;color:#2d3436}
.hm-i{background:#dfe6e9;color:#636e72}

/* ---- ATTACK PATHS ---- */
.ap-card{background:#fff;border-radius:10px;padding:16px 20px;margin:10px 0;
         border-left:5px solid #6c5ce7;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.ap-head{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.ap-title{font-weight:700;font-size:.95rem}
.ap-meta{font-size:.82rem;color:#636e72;line-height:1.6}
.ap-desc{font-size:.84rem;color:#4a4a4a;margin-top:6px;line-height:1.5}

/* ---- HOST CARDS ---- */
.host-card{background:#fff;border-radius:12px;margin:16px 0;box-shadow:0 2px 10px rgba(0,0,0,.07);overflow:hidden}
.host-hdr{background:#2d3436;color:#fff;padding:16px 22px;display:flex;justify-content:space-between;align-items:center;cursor:pointer}
.host-hdr h3{font-size:1rem;font-weight:700}
.host-hdr .hmeta{font-size:.8rem;opacity:.65;margin-top:3px}
.host-badges{display:flex;gap:8px;flex-wrap:wrap}
.host-body{padding:22px}

.crit-badge,.sev-badge,.vs-badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:.73rem;font-weight:700}
.cb-Critical,.sb-Critical{background:#d63031;color:#fff}
.cb-High,.sb-High{background:#e17055;color:#fff}
.cb-Medium,.sb-Medium{background:#fdcb6e;color:#2d3436}
.cb-Low,.sb-Low{background:#55efc4;color:#2d3436}
.cb-Secure,.sb-Secure,.sb-Info{background:#dfe6e9;color:#636e72}

.vs-Confirmed{background:#d63031;color:#fff}
.vs-Likely{background:#e17055;color:#fff}
.vs-Potential{background:#fdcb6e;color:#2d3436}

/* ---- TABLES ---- */
.tbl{width:100%;border-collapse:collapse;margin:10px 0;font-size:.83rem}
.tbl th{background:#f8f9fa;padding:9px 11px;text-align:left;font-weight:600;color:#636e72;
        font-size:.72rem;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #dee2e6}
.tbl td{padding:9px 11px;border-bottom:1px solid #f1f3f5;vertical-align:top}
.tbl tr:hover td{background:#fafbfc}
.port-open{color:#00b894;font-weight:700}

/* ---- EVIDENCE ---- */
details summary{cursor:pointer;font-size:.78rem;color:#6c5ce7;font-weight:600;margin-top:5px}
details pre{background:#1e272e;color:#a29bfe;padding:10px 12px;border-radius:6px;
            font-size:.76rem;white-space:pre-wrap;word-break:break-all;
            max-height:180px;overflow-y:auto;margin-top:5px}

/* ---- CVE LINKS ---- */
a.cve{color:#6c5ce7;text-decoration:none;font-weight:600;font-size:.8rem}
a.cve:hover{text-decoration:underline}

/* ---- THREAT INTEL ---- */
.ti-card{background:#fff;border-radius:10px;padding:14px 18px;margin:10px 0;
         border-left:5px solid #d63031;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.ti-id{font-weight:700;color:#d63031;font-size:.95rem}
.ti-score{font-size:.82rem;color:#636e72;margin-left:12px}
.ti-desc{font-size:.83rem;color:#4a4a4a;margin-top:5px;line-height:1.5}
.ti-affected{font-size:.78rem;color:#636e72;margin-top:5px}

/* ---- EXPOSURE GROUPS ---- */
.exp-group{background:#fff;border-radius:10px;padding:16px 20px;margin:10px 0;
           box-shadow:0 1px 6px rgba(0,0,0,.06)}
.exp-group h4{font-size:.88rem;font-weight:700;color:#2d3436;margin-bottom:8px;
              border-bottom:2px solid #f1f3f5;padding-bottom:6px}

/* ---- SUB HEADERS ---- */
.sub-hdr{font-size:.75rem;text-transform:uppercase;letter-spacing:1px;
         color:#636e72;margin:18px 0 8px;font-weight:700}

/* ---- FOOTER ---- */
footer{background:#2d3436;color:#636e72;text-align:center;padding:22px;
       margin-top:60px;font-size:.82rem;line-height:1.8}

/* ---- PRINT ---- */
@media print{
  .charts,.host-hdr{display:none}
  .host-card{break-inside:avoid}
}
</style>
</head>
<body>

<!-- ================================================ HEADER -->
<header>
  <h1>&#x1F480; RootReaper VAPT Security Report</h1>
  <div class="subtitle">
    Generated {{ summary.generated_at }} &nbsp;|&nbsp;
    Environment: {{ environment.os }} &nbsp;|&nbsp;
    Nmap: {{ environment.nmap_installed }}
  </div>
  <div class="badges">
    <span class="risk-badge rb-{{ network_risk_level }}">
      Network Risk: {{ network_risk_level }}
    </span>
    <span class="risk-badge" style="background:#636e72;color:#fff">
      Score: {{ network_risk_score }}
    </span>
    <span class="risk-badge" style="background:#2980b9;color:#fff">
      {{ summary.total_hosts }} Host(s)
    </span>
    <span class="risk-badge" style="background:#8e44ad;color:#fff">
      {{ summary.total_vulnerabilities }} Finding(s)
    </span>
  </div>
</header>

<div class="container">

<!-- ================================================ EXEC SUMMARY -->
<div class="sec-title">Executive Summary</div>

<p style="line-height:1.7;color:#4a4a4a;margin-bottom:18px">
This report presents the findings of an automated Vulnerability Assessment and Penetration Testing
(VAPT) engagement conducted against <strong>{{ summary.total_hosts }}</strong> host(s).
A total of <strong>{{ summary.total_vulnerabilities }}</strong> vulnerability findings were identified.
The network carries an overall risk level of
<strong class="sev-badge sb-{{ network_risk_level }}">{{ network_risk_level }}</strong>
with a composite risk score of <strong>{{ network_risk_score }}</strong>.
All findings are ranked by exploitability and business impact.
</p>

<div class="cards">
  <div class="card c-crit">
    <div class="lbl">Critical</div>
    <div class="val">{{ summary.severity_breakdown.Critical }}</div>
    <div style="font-size:.78rem;color:#636e72">Findings</div>
  </div>
  <div class="card c-high">
    <div class="lbl">High</div>
    <div class="val">{{ summary.severity_breakdown.High }}</div>
    <div style="font-size:.78rem;color:#636e72">Findings</div>
  </div>
  <div class="card c-med">
    <div class="lbl">Medium</div>
    <div class="val">{{ summary.severity_breakdown.Medium }}</div>
    <div style="font-size:.78rem;color:#636e72">Findings</div>
  </div>
  <div class="card c-low">
    <div class="lbl">Low</div>
    <div class="val">{{ summary.severity_breakdown.Low }}</div>
    <div style="font-size:.78rem;color:#636e72">Findings</div>
  </div>
  <div class="card c-info">
    <div class="lbl">Hosts</div>
    <div class="val">{{ summary.total_hosts }}</div>
    <div style="font-size:.78rem;color:#636e72">Targets</div>
  </div>
  {% if attack_paths %}
  <div class="card" style="border-top-color:#e84393">
    <div class="lbl">Attack Paths</div>
    <div class="val" style="color:#e84393">{{ attack_paths|length }}</div>
    <div style="font-size:.78rem;color:#636e72">Identified</div>
  </div>
  {% endif %}
</div>

<!-- ================================================ CHARTS -->
<div class="charts">
  <div class="chart-box">
    <h4>Severity Distribution</h4>
    <canvas id="chartSev"></canvas>
  </div>
  <div class="chart-box">
    <h4>Host Risk Scores</h4>
    <canvas id="chartHost"></canvas>
  </div>
</div>

<!-- ================================================ RISK HEATMAP -->
<div class="sec-title">Risk Heatmap (Impact vs. Likelihood)</div>
<div class="heatmap-wrap">
  <table>
    <tr>
      <th style="width:140px">Impact \ Likelihood</th>
      <th>High</th>
      <th>Medium</th>
      <th>Low</th>
    </tr>
    <tr>
      <th>Critical</th>
      <td class="hm-c">CRITICAL</td>
      <td class="hm-c">CRITICAL</td>
      <td class="hm-h">HIGH</td>
    </tr>
    <tr>
      <th>High</th>
      <td class="hm-c">CRITICAL</td>
      <td class="hm-h">HIGH</td>
      <td class="hm-m">MEDIUM</td>
    </tr>
    <tr>
      <th>Medium</th>
      <td class="hm-h">HIGH</td>
      <td class="hm-m">MEDIUM</td>
      <td class="hm-l">LOW</td>
    </tr>
    <tr>
      <th>Low</th>
      <td class="hm-m">MEDIUM</td>
      <td class="hm-l">LOW</td>
      <td class="hm-i">INFO</td>
    </tr>
  </table>
</div>

<!-- ================================================ ATTACK PATHS -->
{% if attack_paths %}
<div class="sec-title">Identified Attack Paths</div>
{% for ap in attack_paths %}
<div class="ap-card">
  <div class="ap-head">
    <span class="sev-badge sb-{{ ap.severity }}">{{ ap.severity }}</span>
    <span class="ap-title">{{ ap.title }}</span>
  </div>
  <div class="ap-meta">
    <strong>Host:</strong> {{ ap.host }} &nbsp;&nbsp;
    <strong>Vector:</strong> {{ ap.vector }} &nbsp;&nbsp;
    <strong>Impact:</strong> {{ ap.impact_desc }}
  </div>
  <div class="ap-desc">{{ ap.description }}</div>
</div>
{% endfor %}
{% endif %}

<!-- ================================================ HOST DETAILS -->
<div class="sec-title">Detailed Host Findings</div>

{% for host in hosts %}
<div class="host-card">
  <div class="host-hdr">
    <div>
      <h3>{{ host.host }}</h3>
      <div class="hmeta">
        OS: {{ host.os_fingerprint[0].name if host.os_fingerprint else 'Unknown' }}
        &nbsp;|&nbsp; {{ host.ports | selectattr('state','eq','open') | list | length }} open port(s)
        &nbsp;|&nbsp; {{ host.vulns | length }} finding(s)
        &nbsp;|&nbsp; Risk Score: {{ host.risk_score }}
      </div>
    </div>
    <div class="host-badges">
      <span class="crit-badge cb-{{ host.asset_criticality }}">{{ host.asset_criticality }} ASSET</span>
      <span class="sev-badge sb-{{ host.risk_level }}">{{ host.risk_level }} RISK</span>
    </div>
  </div>
  <div class="host-body">

    <!-- Open Ports -->
    <div class="sub-hdr">Open Ports &amp; Services</div>
    <table class="tbl">
      <tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Banner / Info</th></tr>
      {% for p in host.ports %}{% if p.state == 'open' %}
      <tr>
        <td><strong>{{ p.port }}</strong></td>
        <td>{{ p.protocol }}</td>
        <td class="port-open">{{ p.state }}</td>
        <td>{{ p.service or '-' }}</td>
        <td>{{ p.product or '-' }}</td>
        <td>{{ p.version or '-' }}</td>
        <td style="font-size:.77rem;color:#636e72">{{ (p.scripts.get('banner','') if p.scripts else '')[:80] }}</td>
      </tr>
      {% endif %}{% endfor %}
    </table>

    <!-- Vulnerabilities -->
    {% if host.vulns %}
    <div class="sub-hdr">Vulnerability Findings</div>
    <table class="tbl">
      <tr>
        <th>Port</th><th>Script / Finding</th><th>Category</th>
        <th>Severity</th><th>CVSS</th><th>Status</th><th>Likelihood</th>
        <th>CVEs</th><th>Remediation</th>
      </tr>
      {% for v in host.vulns %}
      <tr>
        <td>{{ v.port or 'host' }}</td>
        <td>
          <strong>{{ v.script }}</strong>
          {% if v.evidence %}
          <details>
            <summary>&#x1F50D; View Evidence</summary>
            <pre>{{ v.evidence }}</pre>
          </details>
          {% endif %}
        </td>
        <td style="font-size:.78rem">{{ v.category or '-' }}</td>
        <td><span class="sev-badge sb-{{ v.severity }}">{{ v.severity }}</span></td>
        <td><strong>{{ v.cvss_score }}</strong></td>
        <td><span class="vs-badge vs-{{ v.validation_status }}">{{ v.validation_status }}</span></td>
        <td>{{ v.likelihood }}</td>
        <td>
          {% for cve in v.cves %}
          <a class="cve" href="https://nvd.nist.gov/vuln/detail/{{ cve }}" target="_blank">{{ cve }}</a><br>
          {% endfor %}
        </td>
        <td style="font-size:.78rem;line-height:1.5">{{ v.remediation }}</td>
      </tr>
      {% endfor %}
    </table>

    <!-- Remediation priority summary -->
    <div class="sub-hdr">Remediation Priority</div>
    <table class="tbl" style="max-width:700px">
      <tr><th>Priority</th><th>Count</th><th>Action</th></tr>
      {% if host.severity_counts.Critical > 0 %}
      <tr><td><span class="sev-badge sb-Critical">Critical</span></td>
          <td>{{ host.severity_counts.Critical }}</td>
          <td>Immediate — isolate and patch within 24 hours</td></tr>
      {% endif %}
      {% if host.severity_counts.High > 0 %}
      <tr><td><span class="sev-badge sb-High">High</span></td>
          <td>{{ host.severity_counts.High }}</td>
          <td>Patch within 72 hours — restrict service access now</td></tr>
      {% endif %}
      {% if host.severity_counts.Medium > 0 %}
      <tr><td><span class="sev-badge sb-Medium">Medium</span></td>
          <td>{{ host.severity_counts.Medium }}</td>
          <td>Harden configuration — patch in next maintenance window</td></tr>
      {% endif %}
      {% if host.severity_counts.Low > 0 %}
      <tr><td><span class="sev-badge sb-Low">Low</span></td>
          <td>{{ host.severity_counts.Low }}</td>
          <td>Monitor — schedule update during routine maintenance</td></tr>
      {% endif %}
    </table>

    {% else %}
    <p style="color:#00b894;margin-top:14px;font-weight:600">&#x2714; No vulnerabilities detected on this host.</p>
    {% endif %}

  </div><!-- /host-body -->
</div><!-- /host-card -->
{% endfor %}

<!-- ================================================ THREAT INTEL -->
{% if threat_intel %}
<div class="sec-title">Threat Intelligence — Latest Critical CVEs</div>
{% for cve in threat_intel %}
<div class="ti-card">
  <div>
    <a class="cve" href="{{ cve.nvd_url }}" target="_blank">{{ cve.id }}</a>
    {% if cve.cvss_score %}
    <span class="ti-score">CVSS: <strong>{{ cve.cvss_score }}</strong></span>
    {% endif %}
    {% if cve.published %}
    <span class="ti-score">Published: {{ cve.published }}</span>
    {% endif %}
  </div>
  <div class="ti-desc">{{ cve.description }}</div>
  {% if cve.affected %}
  <div class="ti-affected">Affected: {{ cve.affected | join(' &nbsp;|&nbsp; ') }}</div>
  {% endif %}
</div>
{% endfor %}
{% endif %}

</div><!-- /container -->

<footer>
  <p>RootReaper VAPT Automation Suite &nbsp;|&nbsp; Generated {{ summary.generated_at }}</p>
  <p>Author: Pragy Jha &nbsp;|&nbsp; B.Tech CSE (Cyber Security &amp; Digital Forensics)</p>
  <p style="margin-top:6px;font-size:.75rem;color:#4a4a4a">
    This report is confidential and intended solely for authorized use.
    Unauthorized scanning of systems is illegal.
  </p>
</footer>

<script>
// Severity pie chart
new Chart(document.getElementById('chartSev'), {
  type: 'doughnut',
  data: {
    labels: ['Critical','High','Medium','Low','Info'],
    datasets: [{
      data: [
        {{ summary.severity_breakdown.Critical }},
        {{ summary.severity_breakdown.High }},
        {{ summary.severity_breakdown.Medium }},
        {{ summary.severity_breakdown.Low }},
        {{ summary.severity_breakdown.Info }}
      ],
      backgroundColor: ['#d63031','#e17055','#fdcb6e','#55efc4','#dfe6e9'],
      borderWidth: 3,
      borderColor: '#fff'
    }]
  },
  options: {
    plugins: { legend: { position:'right' } },
    cutout: '58%'
  }
});

// Host risk bar chart
new Chart(document.getElementById('chartHost'), {
  type: 'bar',
  data: {
    labels: [{% for h in hosts %}'{{ h.host }}'{% if not loop.last %},{% endif %}{% endfor %}],
    datasets: [{
      label: 'Risk Score',
      data:  [{% for h in hosts %}{{ h.risk_score }}{% if not loop.last %},{% endif %}{% endfor %}],
      backgroundColor: [
        {% for h in hosts %}
        '{% if h.risk_level == "Critical" %}#d63031
         {% elif h.risk_level == "High" %}#e17055
         {% elif h.risk_level == "Medium" %}#fdcb6e
         {% else %}#55efc4{% endif %}'
        {% if not loop.last %},{% endif %}
        {% endfor %}
      ],
      borderRadius: 6
    }]
  },
  options: {
    indexAxis: 'y',
    plugins: { legend:{ display:false } },
    scales: { x:{ beginAtZero:true, grid:{ color:'#f1f3f5' } } }
  }
});
</script>
</body>
</html>
"""


# -------------------------------------------------------
# PDF export
# -------------------------------------------------------

def generate_pdf_report(html_path: str) -> Optional[str]:
    pdf_path = os.path.join(OUTPUT_DIR, "report.pdf")
    try:
        from weasyprint import HTML as WP_HTML
        WP_HTML(filename=html_path).write_pdf(pdf_path)
        log_success(f"PDF report → {pdf_path}")
        return pdf_path
    except ImportError:
        log_warning("weasyprint not installed — skipping PDF export (pip install weasyprint)")
        return None
    except Exception as e:
        log_error(f"PDF generation failed: {e}")
        return None


# -------------------------------------------------------
# HTML report
# -------------------------------------------------------

def generate_html_report(report_data: Dict[str, Any]) -> Optional[str]:
    ensure_output_dir()
    path = os.path.join(OUTPUT_DIR, "report.html")
    try:
        tmpl = Template(HTML_TEMPLATE)
        html = tmpl.render(
            summary              = report_data["summary"],
            hosts                = report_data["hosts"],
            environment          = report_data.get("environment", {}),
            threat_intel         = report_data.get("threat_intel", []),
            attack_paths         = report_data.get("attack_paths", []),
            exposure_groups      = report_data.get("exposure_groups", {}),
            network_risk_level   = report_data.get("network_risk_level", "Unknown"),
            network_risk_score   = report_data.get("network_risk_score", 0),
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        log_success(f"HTML report → {path}")
        return path
    except Exception as e:
        log_error(f"HTML report failed: {e}")
        return None


# -------------------------------------------------------
# Main entry point
# -------------------------------------------------------

def generate_report(
    hosts: List[Dict[str, Any]],
    vuln_results: List[Dict[str, Any]],
    environment: Dict[str, Any],
    attack_paths: List[Dict[str, Any]] = None,
    exposure_groups: Dict[str, Any]    = None,
    network_risk_level: str            = "Unknown",
    network_risk_score: float          = 0.0,
) -> Optional[Dict[str, str]]:

    log_step("Generating enterprise VAPT report")

    summary = generate_executive_summary(hosts)

    report_data = {
        "summary":            summary,
        "hosts":              hosts,
        "environment":        environment,
        "threat_intel":       load_threat_intel(),
        "attack_paths":       attack_paths or [],
        "exposure_groups":    exposure_groups or {},
        "network_risk_level": network_risk_level,
        "network_risk_score": network_risk_score,
        "generated_at":       summary["generated_at"],
    }

    json_path = generate_json_report(report_data)
    html_path = generate_html_report(report_data)

    if not html_path:
        return None

    pdf_path = generate_pdf_report(html_path)

    log_success("Report generation complete")

    return {
        "json": json_path,
        "html": html_path,
        "pdf":  pdf_path,
    }
