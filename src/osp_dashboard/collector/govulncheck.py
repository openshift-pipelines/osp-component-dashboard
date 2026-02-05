"""Govulncheck integration for vulnerability scanning.

This module provides vulnerability scanning using govulncheck,
which analyzes Go code to find vulnerabilities that are actually
reachable (called) in the code, not just present in dependencies.

Requires: govulncheck installed (`go install golang.org/x/vuln/cmd/govulncheck@latest`)
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class VulnFinding:
    """A vulnerability finding from govulncheck."""

    vuln_id: str  # GO-2023-1234
    aliases: list[str]  # [CVE-2023-12345, GHSA-xxxx]
    summary: str
    module_path: str  # github.com/example/pkg
    found_version: str  # v1.2.3
    fixed_version: str | None  # v1.2.4
    is_called: bool  # True if vulnerable code is actually called
    symbol: str | None  # The vulnerable function/symbol


def clone_repo(owner: str, repo: str, ref: str, dest: Path) -> bool:
    """Clone a repo at a specific ref."""
    url = f"https://github.com/{owner}/{repo}.git"
    print(f"      Cloning {owner}/{repo}@{ref}...", end=" ", flush=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)],
            check=True,
            capture_output=True,
        )
        print("done")
        return True
    except subprocess.CalledProcessError as e:
        print(f"failed")
        print(f"      Error: {e.stderr.decode() if e.stderr else 'unknown error'}")
        return False


def run_govulncheck(repo_path: Path) -> list[VulnFinding]:
    """Run govulncheck on a repository and return findings.

    Args:
        repo_path: Path to the cloned repository

    Returns:
        List of VulnFinding objects
    """
    findings = []
    osv_cache = {}  # Cache OSV data by ID

    print(f"      Running govulncheck...", end=" ", flush=True)
    try:
        result = subprocess.run(
            ["govulncheck", "-json", "./..."],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
        )
        print("done")

        # Parse JSON output (streaming format, one JSON object per line)
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)

                # Cache OSV entries for later lookup
                if "osv" in data:
                    osv = data["osv"]
                    osv_cache[osv.get("id", "")] = osv

                # Look for vulnerability findings
                if "finding" in data:
                    finding = data["finding"]
                    osv_id = finding.get("osv", "")

                    # Get module info from trace
                    trace = finding.get("trace", [])
                    module_info = trace[0] if trace else {}

                    # Get OSV details
                    osv_data = osv_cache.get(osv_id, {})
                    aliases = osv_data.get("aliases", [])
                    summary = osv_data.get("summary", "")

                    # Get fixed version from affected data
                    fixed_version = None
                    for affected in osv_data.get("affected", []):
                        if affected.get("package", {}).get("name") == module_info.get("module"):
                            ranges = affected.get("ranges", [])
                            for r in ranges:
                                for event in r.get("events", []):
                                    if "fixed" in event:
                                        fixed_version = event["fixed"]
                                        break

                    # Get the vulnerable symbol
                    symbol = None
                    if len(trace) > 0:
                        last_frame = trace[-1]
                        if "function" in last_frame:
                            symbol = last_frame.get("function")

                    findings.append(
                        VulnFinding(
                            vuln_id=osv_id,
                            aliases=aliases,
                            summary=summary,
                            module_path=module_info.get("module", ""),
                            found_version=module_info.get("version", ""),
                            fixed_version=fixed_version,
                            is_called=len(trace) > 1,
                            symbol=symbol,
                        )
                    )
            except json.JSONDecodeError:
                continue

    except subprocess.TimeoutExpired:
        print("timeout (10 min limit)")
    except FileNotFoundError:
        print("error: govulncheck not installed")

    # Deduplicate findings by (vuln_id, module_path)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.vuln_id, f.module_path)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


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


def save_scan_results(
    results: dict[str, dict[str, list[VulnFinding]]],
    output_path: Path | str,
) -> None:
    """Save scan results to JSON file.

    Args:
        results: Dict of {osp_version: {component: [VulnFinding, ...]}}
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


def load_scan_results(
    input_path: Path | str,
) -> dict[str, dict[str, list[VulnFinding]]]:
    """Load scan results from JSON file.

    Args:
        input_path: Path to JSON file

    Returns:
        Dict of {osp_version: {component: [VulnFinding, ...]}}
    """
    input_path = Path(input_path)
    data = json.loads(input_path.read_text())

    results = {}
    for version, components in data.items():
        results[version] = {}
        for component, findings in components.items():
            results[version][component] = [
                VulnFinding(**f) for f in findings
            ]

    return results
