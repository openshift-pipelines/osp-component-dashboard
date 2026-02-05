"""CVE collector using GitHub Advisory Database API."""

import os
import re
from dataclasses import dataclass

import httpx

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


@dataclass
class Advisory:
    """A security advisory."""

    ghsa_id: str
    cve_id: str | None
    summary: str
    severity: str  # low, medium, high, critical
    cvss_score: float | None
    vulnerable_range: str | None
    patched_version: str | None
    published_at: str
    url: str


def parse_version(version: str) -> tuple[int, int, int]:
    """Parse semver string to tuple."""
    v = version.lstrip("v")
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return (0, 0, 0)


def version_in_range(version: str, range_str: str) -> bool:
    """Check if a version falls within a vulnerability range.

    Range examples:
    - ">= 0.35.0, <= 0.52.0"
    - "< 1.0.0"
    - ">= 0.10.0, < 0.20.0"
    """
    if not range_str:
        return False

    v = parse_version(version)

    # Parse range constraints
    constraints = [c.strip() for c in range_str.split(",")]

    for constraint in constraints:
        constraint = constraint.strip()
        if constraint.startswith(">="):
            min_v = parse_version(constraint[2:].strip())
            if v < min_v:
                return False
        elif constraint.startswith(">"):
            min_v = parse_version(constraint[1:].strip())
            if v <= min_v:
                return False
        elif constraint.startswith("<="):
            max_v = parse_version(constraint[2:].strip())
            if v > max_v:
                return False
        elif constraint.startswith("<"):
            max_v = parse_version(constraint[1:].strip())
            if v >= max_v:
                return False
        elif constraint.startswith("="):
            eq_v = parse_version(constraint[1:].strip())
            if v != eq_v:
                return False

    return True


def fetch_advisories(package: str) -> list[Advisory]:
    """Fetch advisories for a Go package from GitHub Advisory Database.

    Args:
        package: Go module path (e.g., "github.com/tektoncd/pipeline")

    Returns:
        List of Advisory objects
    """
    advisories = []

    try:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        with httpx.Client(timeout=30.0) as client:
            response = client.get(
                GITHUB_ADVISORIES_URL,
                params={
                    "ecosystem": "go",
                    "affects": package,
                    "per_page": 100,
                },
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

            for item in data:
                # Extract vulnerability range for this package
                vulnerable_range = None
                patched_version = None
                for vuln in item.get("vulnerabilities", []):
                    pkg = vuln.get("package", {})
                    if pkg.get("name") == package:
                        vulnerable_range = vuln.get("vulnerable_version_range")
                        patched_version = vuln.get("first_patched_version")
                        break

                # Get CVSS score
                cvss_score = None
                cvss = item.get("cvss_severities", {}).get("cvss_v3", {})
                if cvss:
                    cvss_score = cvss.get("score")

                advisories.append(
                    Advisory(
                        ghsa_id=item.get("ghsa_id", ""),
                        cve_id=item.get("cve_id"),
                        summary=item.get("summary", ""),
                        severity=item.get("severity", "unknown"),
                        cvss_score=cvss_score,
                        vulnerable_range=vulnerable_range,
                        patched_version=patched_version,
                        published_at=item.get("published_at", ""),
                        url=item.get("html_url", ""),
                    )
                )
    except httpx.HTTPError:
        # Silently fail on API errors
        pass

    return advisories


def get_advisories_for_version(
    package: str, version: str
) -> list[Advisory]:
    """Get advisories that affect a specific version.

    Args:
        package: Go module path
        version: Version to check (e.g., "v0.62.0")

    Returns:
        List of advisories affecting this version
    """
    all_advisories = fetch_advisories(package)
    affecting = []

    for adv in all_advisories:
        if adv.vulnerable_range and version_in_range(version, adv.vulnerable_range):
            affecting.append(adv)

    return affecting
