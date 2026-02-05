"""Govulncheck integration for vulnerability scanning.

This module provides vulnerability scanning using govulncheck,
which analyzes Go code to find vulnerabilities that are actually
reachable (called) in the code, not just present in dependencies.

Requires: govulncheck installed (`go install golang.org/x/vuln/cmd/govulncheck@latest`)
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VulnFinding:
    """A vulnerability finding from govulncheck."""

    vuln_id: str  # GO-2023-1234
    cve_id: str | None  # CVE-2023-12345
    summary: str
    module_path: str  # github.com/example/pkg
    found_version: str  # v1.2.3
    fixed_version: str | None  # v1.2.4
    is_called: bool  # True if vulnerable code is actually called


def clone_repo(owner: str, repo: str, ref: str, dest: Path) -> bool:
    """Clone a repo at a specific ref."""
    url = f"https://github.com/{owner}/{repo}.git"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def run_govulncheck(repo_path: Path) -> list[VulnFinding]:
    """Run govulncheck on a repository and return findings.

    Args:
        repo_path: Path to the cloned repository

    Returns:
        List of VulnFinding objects
    """
    findings = []

    try:
        result = subprocess.run(
            ["govulncheck", "-json", "./..."],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        # Parse JSON output (streaming format, one JSON object per line)
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)

                # Look for vulnerability findings
                if "finding" in data:
                    finding = data["finding"]
                    osv = finding.get("osv", "")

                    # Get module info
                    trace = finding.get("trace", [])
                    module_info = trace[0] if trace else {}

                    findings.append(
                        VulnFinding(
                            vuln_id=osv,
                            cve_id=None,  # Need to look up separately
                            summary="",  # Need to look up separately
                            module_path=module_info.get("module", ""),
                            found_version=module_info.get("version", ""),
                            fixed_version=None,
                            is_called=len(trace) > 1,  # Has call stack = called
                        )
                    )
            except json.JSONDecodeError:
                continue

    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # govulncheck not installed
        pass

    return findings


def scan_component(owner: str, repo: str, ref: str) -> list[VulnFinding]:
    """Scan a component for vulnerabilities using govulncheck.

    Args:
        owner: GitHub owner (e.g., "tektoncd")
        repo: Repository name (e.g., "pipeline")
        ref: Git ref/tag (e.g., "v0.62.0")

    Returns:
        List of VulnFinding objects
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / repo

        if not clone_repo(owner, repo, ref, repo_path):
            return []

        return run_govulncheck(repo_path)


# Example usage for GitHub Actions workflow:
#
# jobs:
#   scan:
#     runs-on: ubuntu-latest
#     steps:
#       - uses: actions/setup-go@v5
#         with:
#           go-version: '1.22'
#
#       - name: Install govulncheck
#         run: go install golang.org/x/vuln/cmd/govulncheck@latest
#
#       - name: Run vulnerability scan
#         run: uv run osp-dashboard scan  # New command to add
