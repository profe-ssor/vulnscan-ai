"""
CVE/NVD MCP Server — queries the National Vulnerability Database for known
vulnerabilities in software packages.

The Dependency Audit Agent calls this server with a package name and version,
and gets back a list of CVEs with severity scores and descriptions.

How it works:
  1. Agent finds "requests==2.25.0" in requirements.txt
  2. Agent calls search_cves(package_name="requests", version="2.25.0")
  3. This server queries the NVD API
  4. Returns matching CVEs with severity, description, and references

Transport: stdio
"""

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cve-nvd")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Severity label from CVSS score
SEVERITY_THRESHOLDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "None"),
]


def _cvss_to_severity(score: float) -> str:
    """Convert a numeric CVSS score to a severity label."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Unknown"


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    """
    Extract the CVSS score and vector from NVD metrics.
    NVD can have CVSS v3.1, v3.0, or v2.0 — we prefer the newest.
    """
    # Try CVSS v3.1 first, then v3.0, then v2.0
    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
        if version_key in metrics:
            data = metrics[version_key][0]["cvssData"]
            return data.get("baseScore", 0.0), data.get("vectorString", "")

    if "cvssMetricV2" in metrics:
        data = metrics["cvssMetricV2"][0]["cvssData"]
        return data.get("baseScore", 0.0), data.get("vectorString", "")

    return 0.0, ""


@mcp.tool()
def search_cves(package_name: str, version: str = "", max_results: int = 10) -> list[dict]:
    """
    Search the NVD database for known vulnerabilities affecting a package.

    Args:
        package_name: The package/library name, e.g. "requests", "lodash", "spring-core".
        version: Optional specific version to check, e.g. "2.25.0".
        max_results: Maximum number of CVEs to return (default 10).

    Returns:
        List of CVE records, each containing:
        - cve_id: e.g. "CVE-2023-32681"
        - severity: Critical | High | Medium | Low
        - score: CVSS base score (0.0-10.0)
        - description: What the vulnerability is
        - published: When it was disclosed
        - references: Links to advisories
    """
    # Build the keyword query — NVD searches across descriptions and metadata
    keyword = package_name
    if version:
        keyword = f"{package_name} {version}"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    try:
        response = httpx.get(NVD_API_URL, params=params, timeout=30)
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        return [{"error": f"NVD API returned {e.response.status_code}"}]
    except httpx.RequestError as e:
        return [{"error": f"Failed to reach NVD API: {e}"}]

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    results = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "Unknown")

        # Get the English description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available",
        )

        # Extract CVSS score
        metrics = cve.get("metrics", {})
        score, vector = _extract_cvss(metrics)
        severity = _cvss_to_severity(score)

        # Collect reference URLs (advisories, patches, etc.)
        refs = cve.get("references", [])
        reference_urls = [r["url"] for r in refs[:5]]  # cap at 5 links

        # Published date
        published = cve.get("published", "Unknown")[:10]  # just the date part

        results.append({
            "cve_id": cve_id,
            "severity": severity,
            "score": score,
            "vector": vector,
            "description": description,
            "published": published,
            "references": reference_urls,
        })

    return results


@mcp.tool()
def get_cve_details(cve_id: str) -> dict:
    """
    Get full details for a specific CVE by its ID.

    Args:
        cve_id: The CVE identifier, e.g. "CVE-2023-32681".

    Returns:
        Detailed CVE record with description, severity, affected configs,
        and reference links.
    """
    params = {"cveId": cve_id}

    try:
        response = httpx.get(NVD_API_URL, params=params, timeout=30)
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        return {"error": f"NVD API returned {e.response.status_code}"}
    except httpx.RequestError as e:
        return {"error": f"Failed to reach NVD API: {e}"}

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return {"error": f"CVE {cve_id} not found"}

    cve = vulnerabilities[0].get("cve", {})

    # Description
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available",
    )

    # CVSS
    metrics = cve.get("metrics", {})
    score, vector = _extract_cvss(metrics)

    # CWE IDs (weaknesses)
    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                cwe_ids.append(desc["value"])

    # References
    refs = cve.get("references", [])
    reference_urls = [r["url"] for r in refs[:10]]

    return {
        "cve_id": cve.get("id", cve_id),
        "severity": _cvss_to_severity(score),
        "score": score,
        "vector": vector,
        "cwe_ids": cwe_ids,
        "description": description,
        "published": cve.get("published", "Unknown")[:10],
        "last_modified": cve.get("lastModified", "Unknown")[:10],
        "references": reference_urls,
    }


if __name__ == "__main__":
    mcp.run()
