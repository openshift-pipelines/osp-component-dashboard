"""npm audit integration for vulnerability scanning.

This module provides vulnerability scanning using npm audit,
which analyzes npm projects to find known vulnerabilities in dependencies.

Requires: npm installed
"""

import json
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

from .govulncheck import clone_repo


@dataclass
class NpmVulnFinding:
    """A vulnerability finding from npm audit."""

    vuln_id: str  # GHSA-xxxx or npm advisory ID
    aliases: list[str]  # CVE IDs
    severity: str  # low, moderate, high, critical
    title: str
    package_name: str
    vulnerable_range: str
    patched_version: str | None
    is_direct: bool  # True if direct dependency


def run_npm_audit(repo_path: Path) -> list[NpmVulnFinding]:
    """Run npm audit on a repository and return findings.

    Args:
        repo_path: Path to the cloned repository

    Returns:
        List of NpmVulnFinding objects
    """
    findings = []

    print("      Running npm audit...", end=" ", flush=True)
    try:
        # First, install dependencies (needed for npm audit to work)
        # Use --ignore-scripts for security
        install_result = subprocess.run(
            ["npm", "install", "--ignore-scripts", "--package-lock-only"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout for install
        )
        if install_result.returncode != 0:
            # Try with legacy-peer-deps flag
            subprocess.run(
                ["npm", "install", "--ignore-scripts", "--package-lock-only", "--legacy-peer-deps"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=300,
            )

        # Run npm audit
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=120,  # 2 minute timeout
        )
        print("done")

        # Parse JSON output
        # npm audit returns exit code 1 if vulnerabilities found, so don't check returncode
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                vulnerabilities = data.get("vulnerabilities", {})

                for pkg_name, vuln_info in vulnerabilities.items():
                    # Each vulnerability entry
                    severity = vuln_info.get("severity", "unknown")
                    is_direct = vuln_info.get("isDirect", False)

                    # Get advisory details from "via" field
                    via_list = vuln_info.get("via", [])
                    for via in via_list:
                        if isinstance(via, dict):
                            # This is an actual vulnerability, not just a dependency chain
                            vuln_id = str(via.get("source", ""))
                            title = via.get("title", "")
                            url = via.get("url", "")
                            vuln_range = via.get("range", "")

                            # Extract CVE from URL if available (format: https://github.com/advisories/GHSA-xxxx)
                            aliases = []
                            if "GHSA-" in url:
                                ghsa = url.split("/")[-1]
                                if ghsa.startswith("GHSA-"):
                                    vuln_id = ghsa

                            # Check for CVE in title or name
                            if "CVE-" in title:
                                import re
                                cve_match = re.search(r"CVE-\d{4}-\d+", title)
                                if cve_match:
                                    aliases.append(cve_match.group())

                            # Get fix info
                            fix_available = vuln_info.get("fixAvailable")
                            patched_version = None
                            if isinstance(fix_available, dict):
                                patched_version = fix_available.get("version")

                            findings.append(
                                NpmVulnFinding(
                                    vuln_id=vuln_id,
                                    aliases=aliases,
                                    severity=severity,
                                    title=title,
                                    package_name=pkg_name,
                                    vulnerable_range=vuln_range,
                                    patched_version=patched_version,
                                    is_direct=is_direct,
                                )
                            )

            except json.JSONDecodeError:
                print("error: Failed to parse npm audit output")

    except subprocess.TimeoutExpired:
        print("timeout")
    except FileNotFoundError:
        print("error: npm not installed")

    # Deduplicate findings by (vuln_id, package_name)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.vuln_id, f.package_name)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


def scan_npm_component(owner: str, repo: str, ref: str) -> list[NpmVulnFinding]:
    """Scan an npm component for vulnerabilities using npm audit.

    Args:
        owner: GitHub owner (e.g., "openshift-pipelines")
        repo: Repository name (e.g., "console-plugin")
        ref: Git ref/tag (e.g., "osp-v1.18.0")

    Returns:
        List of NpmVulnFinding objects
    """
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / repo

        if not clone_repo(owner, repo, ref, repo_path):
            return []

        return run_npm_audit(repo_path)


def save_npm_scan_results(
    results: dict[str, dict[str, list[NpmVulnFinding]]],
    output_path: Path | str,
) -> None:
    """Save npm scan results to JSON file.

    Args:
        results: Dict of {osp_version: {component: [NpmVulnFinding, ...]}}
        output_path: Path to write JSON output
    """
    # Convert dataclasses to dicts
    serializable = {}
    for version, components in results.items():
        serializable[version] = {}
        for component, findings in components.items():
            serializable[version][component] = [asdict(f) for f in findings]

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(serializable, indent=2))


def load_npm_scan_results(
    input_path: Path | str,
) -> dict[str, dict[str, list[NpmVulnFinding]]]:
    """Load npm scan results from JSON file.

    Args:
        input_path: Path to JSON file

    Returns:
        Dict of {osp_version: {component: [NpmVulnFinding, ...]}}
    """
    input_path = Path(input_path)
    data = json.loads(input_path.read_text())

    results = {}
    for version, components in data.items():
        results[version] = {}
        for component, findings in components.items():
            results[version][component] = [
                NpmVulnFinding(**f) for f in findings
            ]

    return results
