"""HTML generator for the dashboard."""

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..collector.gomod import ComponentData

# Internal Tekton/OSP dependency prefixes
INTERNAL_PREFIXES = (
    "github.com/tektoncd/",
    "github.com/openshift-pipelines/",
)


def is_internal_dep(path: str) -> bool:
    """Check if a dependency is an internal OSP/Tekton component."""
    return any(path.startswith(prefix) for prefix in INTERNAL_PREFIXES)


def normalize_go_version(version: str) -> tuple[int, int]:
    """Extract major.minor from Go version string for comparison.

    Args:
        version: Go version like "1.22", "1.22.5", "1.24.0"

    Returns:
        Tuple of (major, minor) for comparison
    """
    match = re.match(r"(\d+)\.(\d+)", version)
    if match:
        return (int(match.group(1)), int(match.group(2)))
    return (0, 0)


def parse_semver(version: str) -> tuple[int, int, int]:
    """Parse semantic version string to tuple for comparison.

    Args:
        version: Version like "v0.62.0", "v1.3.0", "0.28.0"

    Returns:
        Tuple of (major, minor, patch)
    """
    # Remove leading 'v' if present
    v = version.lstrip("v")
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return (0, 0, 0)


def dep_path_to_component_key(path: str) -> str | None:
    """Convert dependency path to component key (owner/repo).

    Args:
        path: Dependency path like "github.com/tektoncd/pipeline"

    Returns:
        Component key like "tektoncd/pipeline" or None if not a GitHub path
    """
    if path.startswith("github.com/"):
        parts = path.split("/")
        if len(parts) >= 3:
            return f"{parts[1]}/{parts[2]}"
    return None


def version_in_range(version: str, range_str: str) -> bool:
    """Check if a version falls within a vulnerability range."""
    if not range_str:
        return False

    v = parse_semver(version)
    constraints = [c.strip() for c in range_str.split(",")]

    for constraint in constraints:
        constraint = constraint.strip()
        if constraint.startswith(">="):
            min_v = parse_semver(constraint[2:].strip())
            if v < min_v:
                return False
        elif constraint.startswith(">"):
            min_v = parse_semver(constraint[1:].strip())
            if v <= min_v:
                return False
        elif constraint.startswith("<="):
            max_v = parse_semver(constraint[2:].strip())
            if v > max_v:
                return False
        elif constraint.startswith("<"):
            max_v = parse_semver(constraint[1:].strip())
            if v >= max_v:
                return False
        elif constraint.startswith("="):
            eq_v = parse_semver(constraint[1:].strip())
            if v != eq_v:
                return False

    return True


def generate_html(
    data: dict[str, list[ComponentData]],
    highlight_deps: list[str],
    output_path: Path | str,
    template_dir: Path | str | None = None,
    bundled_versions: dict[str, dict[str, str]] | None = None,
    cve_data: dict[str, dict[str, list]] | None = None,
    dep_advisories: dict[str, list] | None = None,
    vuln_data: dict[str, dict[str, list]] | None = None,
) -> None:
    """Generate the dashboard HTML.

    Args:
        data: Dict of OSP version -> list of ComponentData
        highlight_deps: List of dependency paths to highlight
        output_path: Where to write the generated HTML
        template_dir: Directory containing templates (defaults to templates/)
        bundled_versions: Dict of OSP version -> {component: version} for staleness check
        cve_data: Dict of OSP version -> {component: [Advisory, ...]} for CVE display
        dep_advisories: Dict of dep_path -> [Advisory, ...] for dependency CVE checking
        vuln_data: Dict of OSP version -> {component: [VulnFinding, ...]} from govulncheck
    """
    if template_dir is None:
        template_dir = Path(__file__).parent / "templates"

    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("index.html")

    # Convert to template-friendly format
    versions_data = {}
    version_stats = {}  # Per-version statistics

    for osp_version, components in data.items():
        versions_data[osp_version] = []

        # Collect Go versions for mismatch detection
        go_versions = set()
        for comp in components:
            if comp.go_version:
                go_versions.add(normalize_go_version(comp.go_version))

        # Determine if there's a Go version mismatch (different major.minor)
        has_go_mismatch = len(go_versions) > 1

        # Find the most common/newest Go version as "expected"
        expected_go = max(go_versions) if go_versions else (0, 0)

        # Get bundled versions for this OSP release (for staleness check)
        bundled = bundled_versions.get(osp_version, {}) if bundled_versions else {}

        # Get CVE data for this version
        version_cves = cve_data.get(osp_version, {}) if cve_data else {}

        # Get govulncheck data for this version
        version_vulns = vuln_data.get(osp_version, {}) if vuln_data else {}

        # Collect dependency versions across all components for mismatch detection
        dep_versions: dict[str, dict[str, list[str]]] = {}  # {dep_path: {version: [components]}}
        for comp in components:
            for dep in comp.dependencies:
                if dep.path in highlight_deps and not is_internal_dep(dep.path):
                    if dep.path not in dep_versions:
                        dep_versions[dep.path] = {}
                    if dep.version not in dep_versions[dep.path]:
                        dep_versions[dep.path][dep.version] = []
                    dep_versions[dep.path][dep.version].append(comp.repo)

        # Determine expected version for each dep (most common, or newest if tie)
        expected_dep_versions: dict[str, str] = {}
        mismatched_deps: set[str] = set()
        for dep_path, versions in dep_versions.items():
            if len(versions) > 1:
                mismatched_deps.add(dep_path)
            # Pick version used by most components, break ties with newest
            best_version = max(
                versions.keys(),
                key=lambda v: (len(versions[v]), parse_semver(v))
            )
            expected_dep_versions[dep_path] = best_version

        for comp in components:
            # Check if this component's Go version differs from expected
            comp_go_normalized = normalize_go_version(comp.go_version)
            go_version_mismatch = has_go_mismatch and comp_go_normalized != expected_go

            # Filter to highlighted dependencies
            highlighted = [
                d for d in comp.dependencies if d.path in highlight_deps
            ]

            # Separate internal (cross-dependencies) from external
            internal_deps = [d for d in highlighted if is_internal_dep(d.path)]
            external_deps = [d for d in highlighted if not is_internal_dep(d.path)]

            # Sort by path for consistent display
            internal_deps.sort(key=lambda d: d.path)
            external_deps.sort(key=lambda d: d.path)

            # Process internal deps to check for staleness
            internal_deps_data = []
            for dep in internal_deps:
                dep_component = dep_path_to_component_key(dep.path)
                is_stale = False
                bundled_version = None

                if dep_component and dep_component in bundled:
                    bundled_version = bundled[dep_component]
                    # Compare versions - if dependency is older than bundled, it's stale
                    dep_semver = parse_semver(dep.version)
                    bundled_semver = parse_semver(bundled_version)
                    is_stale = dep_semver < bundled_semver

                internal_deps_data.append({
                    "path": dep.path,
                    "version": dep.version,
                    "is_stale": is_stale,
                    "bundled_version": bundled_version,
                })

            # Get CVEs for this component
            component_key = f"{comp.owner}/{comp.repo}"
            comp_cves = version_cves.get(component_key, [])
            cve_list = [
                {
                    "id": adv.cve_id or adv.ghsa_id,
                    "summary": adv.summary,
                    "severity": adv.severity,
                    "cvss_score": adv.cvss_score,
                    "url": adv.url,
                }
                for adv in comp_cves
            ]

            # Get govulncheck findings for this component
            comp_vulns = version_vulns.get(component_key, [])
            vuln_list = [
                {
                    "id": v.vuln_id,
                    "aliases": v.aliases,
                    "summary": v.summary,
                    "module": v.module_path.split("/")[-1] if v.module_path else "",
                    "found_version": v.found_version,
                    "fixed_version": v.fixed_version,
                    "is_called": v.is_called,
                    "symbol": v.symbol,
                }
                for v in comp_vulns
            ]

            # Process external deps to check for version mismatch
            external_deps_data = []
            for dep in external_deps:
                is_mismatched = dep.path in mismatched_deps
                expected_version = expected_dep_versions.get(dep.path)
                version_differs = is_mismatched and dep.version != expected_version

                # Check for CVEs affecting this dependency version
                dep_cves = []
                if dep_advisories and dep.path in dep_advisories:
                    for adv in dep_advisories[dep.path]:
                        if adv.vulnerable_range and version_in_range(dep.version, adv.vulnerable_range):
                            dep_cves.append({
                                "id": adv.cve_id or adv.ghsa_id,
                                "severity": adv.severity,
                                "url": adv.url,
                            })

                external_deps_data.append({
                    "path": dep.path,
                    "version": dep.version,
                    "is_mismatched": is_mismatched,
                    "version_differs": version_differs,
                    "expected_version": expected_version,
                    "cves": dep_cves,
                })

            versions_data[osp_version].append({
                "owner": comp.owner,
                "repo": comp.repo,
                "ref": comp.ref,
                "go_version": comp.go_version,
                "go_version_mismatch": go_version_mismatch,
                "internal_deps": internal_deps_data,
                "external_deps": external_deps_data,
                "total_deps": len(comp.dependencies),
                "cves": cve_list,
                "vulns": vuln_list,
                "release_status": {
                    "branch_exists": comp.release_status.branch_exists,
                    "branch_name": comp.release_status.branch_name,
                    "current_version": comp.release_status.current_version,
                    "latest_version": comp.release_status.latest_version,
                    "has_unreleased": comp.release_status.has_unreleased,
                    "update_available": comp.release_status.update_available,
                },
            })

        # Count total CVEs for this version and track affected components
        total_cves = sum(len(cves) for cves in version_cves.values())
        cve_details = []
        for component_key, cves in version_cves.items():
            repo = component_key.split("/")[-1]
            for adv in cves:
                cve_details.append({
                    "id": adv.cve_id or adv.ghsa_id,
                    "severity": adv.severity,
                    "component": repo,
                    "url": adv.url,
                })

        # Collect dependency CVEs from the components we just processed
        dep_cve_details = []
        seen_dep_cves = set()
        for comp_data in versions_data[osp_version]:
            for dep in comp_data["external_deps"]:
                for cve in dep.get("cves", []):
                    cve_key = (cve["id"], dep["path"])
                    if cve_key not in seen_dep_cves:
                        seen_dep_cves.add(cve_key)
                        dep_cve_details.append({
                            "id": cve["id"],
                            "severity": cve["severity"],
                            "dep": dep["path"].split("/")[-1],
                            "url": cve["url"],
                        })

        # Collect govulncheck findings for version stats
        vuln_details = []
        total_vulns = 0
        called_vulns = 0
        for component_key, vulns in version_vulns.items():
            repo = component_key.split("/")[-1]
            for v in vulns:
                total_vulns += 1
                if v.is_called:
                    called_vulns += 1
                # Get primary CVE ID from aliases
                cve_id = next((a for a in v.aliases if a.startswith("CVE-")), v.vuln_id)
                vuln_details.append({
                    "id": cve_id,
                    "go_id": v.vuln_id,
                    "component": repo,
                    "module": v.module_path.split("/")[-1] if v.module_path else "",
                    "is_called": v.is_called,
                    "symbol": v.symbol,
                })

        # Store version-level stats
        version_stats[osp_version] = {
            "has_go_mismatch": has_go_mismatch,
            "go_versions": sorted([f"{v[0]}.{v[1]}" for v in go_versions], reverse=True),
            "total_cves": total_cves,
            "cve_details": cve_details,
            "has_dep_mismatch": len(mismatched_deps) > 0,
            "mismatched_deps": sorted([p.split("/")[-1] for p in mismatched_deps]),
            "dep_cve_details": dep_cve_details,
            "total_dep_cves": len(dep_cve_details),
            "total_vulns": total_vulns,
            "called_vulns": called_vulns,
            "vuln_details": vuln_details,
            "has_vuln_data": vuln_data is not None,
        }

    # Sort OSP versions descending (newest first)
    sorted_versions = sorted(versions_data.keys(), reverse=True)

    html = template.render(
        versions=sorted_versions,
        versions_data=versions_data,
        version_stats=version_stats,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
