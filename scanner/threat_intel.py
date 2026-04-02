"""
threat_intel.py

Fetch threat intelligence from NVD API.
"""

import requests
from utils.logger import log_info, log_error


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_latest_critical_cves(limit=5):

    log_info("Fetching latest critical CVEs")

    params = {
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": limit
    }

    headers = {
        "User-Agent": "EnterpriseVAPT/1.0"
    }

    try:

        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=15
        )

        if response.status_code != 200:
            return []

        data = response.json()

        results = []

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})

            results.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value")
            })

        return results

    except Exception as e:

        log_error(f"CVE fetch failed: {e}")
        return []