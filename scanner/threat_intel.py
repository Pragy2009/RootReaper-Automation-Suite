"""
threat_intel.py

Threat intelligence feed from the NVD (National Vulnerability Database) API v2.
Returns latest Critical CVEs enriched with CVSS scores and NVD links.
"""

import requests
from utils.logger import log_info, log_warning, log_error

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"


def _extract_cvss(cve: dict) -> tuple:
    """
    Extract CVSS v3.1 (preferred) or v3.0 score and vector from a NVD CVE entry.
    Returns (score, vector, severity).
    """
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return (
                data.get("baseScore"),
                data.get("vectorString"),
                data.get("baseSeverity"),
            )

    # Fall back to v2
    v2_entries = metrics.get("cvssMetricV2", [])
    if v2_entries:
        data = v2_entries[0].get("cvssData", {})
        return (
            data.get("baseScore"),
            data.get("vectorString"),
            v2_entries[0].get("baseSeverity"),
        )

    return (None, None, None)


def _extract_affected(cve: dict) -> list:
    """Extract a short list of affected products (CPE names)."""
    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor  = parts[3]
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 else "*"
                    label = f"{vendor}/{product} {version}".replace("*", "any")
                    if label not in affected:
                        affected.append(label)
                if len(affected) >= 5:
                    break
            if len(affected) >= 5:
                break
        if len(affected) >= 5:
            break
    return affected


def fetch_latest_critical_cves(limit: int = 10) -> list:
    """
    Fetch the most recent Critical CVEs from NVD API v2.
    Returns enriched list with CVSS scores, vectors, and NVD links.
    """
    log_info(f"Fetching latest {limit} critical CVEs from NVD")

    params = {
        "cvssV3Severity":  "CRITICAL",
        "resultsPerPage":  limit,
        "startIndex":      0,
    }

    headers = {"User-Agent": "RootReaperVAPT/1.0"}

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=20,
        )

        if response.status_code != 200:
            log_warning(f"NVD API returned HTTP {response.status_code}")
            return []

        data = response.json()
        results = []

        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id  = cve_obj.get("id", "")

            # English description
            description = next(
                (
                    d.get("value", "")
                    for d in cve_obj.get("descriptions", [])
                    if d.get("lang") == "en"
                ),
                "No description available.",
            )

            cvss_score, cvss_vector, cvss_severity = _extract_cvss(cve_obj)
            affected = _extract_affected(cve_obj)

            published = cve_obj.get("published", "")[:10]  # YYYY-MM-DD

            results.append({
                "id":           cve_id,
                "description":  description[:300],
                "cvss_score":   cvss_score,
                "cvss_vector":  cvss_vector,
                "cvss_severity": cvss_severity or "CRITICAL",
                "published":    published,
                "affected":     affected,
                "nvd_url":      NVD_DETAIL_URL.format(cve_id=cve_id),
            })

        log_info(f"Fetched {len(results)} critical CVE(s)")
        return results

    except Exception as e:
        log_error(f"CVE fetch failed: {e}")
        return []
