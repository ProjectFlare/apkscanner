"""National Vulnerability Database (NVD/NIST) REST API client.

Fetches CVSS v3.x severity scores, metrics, attack vector strings, and CWE
classifications for specific CVE identifiers.
"""

from typing import Any

import requests


def _extract_cvss_metrics(metrics: dict[str, Any]) -> tuple[str, str, str] | None:
    """Extracts CVSS v3.1 or v3.0 base score, severity, and vector string from metrics.

    Args:
        metrics (dict[str, Any]): The metrics dictionary from NVD API.

    Returns:
        tuple[str, str, str] | None: A tuple of (score, severity, vector) or None if not found.
    """
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = str(cvss_data.get("baseScore", "N/A"))
            severity = str(cvss_data.get("baseSeverity", "N/A"))
            vector = str(cvss_data.get("vectorString", "N/A"))
            return score, severity, vector
    return None


def _extract_cwes(weaknesses: list[dict[str, Any]]) -> list[str]:
    """Extracts English CWE identifiers from weaknesses list.

    Args:
        weaknesses (list[dict[str, Any]]): Weaknesses array from NVD API.

    Returns:
        list[str]: A list of CWE ID strings.
    """
    cwes: list[str] = []
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                val = desc.get("value")
                if val:
                    cwes.append(val)
    return cwes


def lookup_nvd_cve(cve_id: str) -> str:
    """Fetches full CVE details from the NVD/NIST REST API.

    Args:
        cve_id (str): The CVE identifier (e.g. CVE-2024-1234).

    Returns:
        str: Formatted result string containing CVSS v3 score, vector, CWE, and dates.

    Raises:
        RuntimeError: If the NVD API query fails.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10.0)
        if res.status_code == 404:
            return f"CVE not found in NVD: {cve_id}"
        if res.status_code != 200:
            raise RuntimeError(f"NVD API returned HTTP {res.status_code}")

        data = res.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"CVE not found in NVD: {cve_id}"

        cve_data = vulns[0].get("cve", {})
        published = cve_data.get("published", "Unknown")
        last_modified = cve_data.get("lastModified", "Unknown")
        source_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # Extract CVSS metrics
        metrics = cve_data.get("metrics", {})
        cvss = _extract_cvss_metrics(metrics)

        lines = [f"CVE: {cve_id} (Source: {source_link})"]
        if cvss:
            score, severity, vector = cvss
            lines.append(f"CVSS v3 Base Score: {score} ({severity})")
            lines.append(f"Attack Vector String: {vector}")
        else:
            lines.append("CVSS v3: Not available in NVD.")

        # Extract CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwes = _extract_cwes(weaknesses)
        if cwes:
            lines.append(f"CWE: {', '.join(cwes)}")

        lines.append(f"Published: {published} | Last Modified: {last_modified}")
        return "\n".join(lines)

    except Exception as e:
        raise RuntimeError(f"NVD API query failed for {cve_id}: {e}") from e
