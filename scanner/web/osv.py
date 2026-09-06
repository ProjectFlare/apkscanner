"""OSV.dev vulnerability lookup client for the APK static scanner.

Queries the OSV.dev REST API for known CVE and GHSA advisories affecting specific
package coordinates and versions.
"""

import requests


def lookup_osv_vulnerabilities(package: str, version: str) -> str:
    """Queries OSV.dev for known CVEs affecting a specific package version.

    Each advisory is returned with its OSV id (usually a GHSA identifier) followed by any
    CVE ids OSV lists as aliases, so the model can look those up via ``lookup_nvd_cve``
    without having to resolve the GHSA-to-CVE mapping itself.

    Args:
        package (str): Full Maven coordinate (e.g. com.squareup.okhttp3:okhttp).
        version (str): The exact version string.

    Returns:
        str: Formatted result string for the model.

    Raises:
        RuntimeError: If the OSV.dev query fails or answers with a non-200 status.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package, "ecosystem": "Maven"}, "version": version}
    try:
        res = requests.post(url, json=payload, timeout=8.0)
        # Any non-200 (rate limit, outage, malformed query) must surface as a failure. Falling
        # through to a "no vulnerabilities" string would report an unqueried package as clean.
        if res.status_code != 200:
            raise RuntimeError(f"OSV.dev API returned HTTP {res.status_code}")

        vulns = res.json().get("vulns", [])
        if not vulns:
            return (
                "No known vulnerabilities found in OSV.dev for this exact package+version. Note: this same "
                "result also occurs if OSV.dev has no advisory data indexed for this package at all (e.g. an "
                "unlisted or misspelled coordinate) — it does not confirm the package name itself is valid. "
                "Do not cite this result as if it contained a source URL; it did not."
            )
        lines = []
        for v in vulns:
            vid = v.get("id", "Unknown")
            summary = v.get("summary", "No summary available.")
            link = f"https://osv.dev/vulnerability/{vid}"
            # OSV reports GHSA ids and carries the corresponding CVE ids in `aliases`.
            # Surfacing them here lets the model call lookup_nvd_cve directly instead of
            # searching the web for the GHSA-to-CVE mapping.
            cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            cve_part = f" [{', '.join(cves)}]" if cves else " [no CVE assigned]"
            lines.append(f"- {vid}{cve_part}: {summary} (Source: {link})")
        return "\n".join(lines)
    except Exception as e:
        raise RuntimeError(f"OSV.dev query failed: {e}") from e
