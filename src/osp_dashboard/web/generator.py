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


def generate_html(
    data: dict[str, list[ComponentData]],
    highlight_deps: list[str],
    output_path: Path | str,
    template_dir: Path | str | None = None,
    bundled_versions: dict[str, dict[str, str]] | None = None,
    cve_data: dict[str, dict[str, list]] | None = None,
) -> None:
    """Generate the dashboard HTML.

    Args:
        data: Dict of OSP version -> list of ComponentData
        highlight_deps: List of dependency paths to highlight
        output_path: Where to write the generated HTML
        template_dir: Directory containing templates (defaults to templates/)
        bundled_versions: Dict of OSP version -> {component: version} for staleness check
        cve_data: Dict of OSP version -> {component: [Advisory, ...]} for CVE display
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

            versions_data[osp_version].append({
                "owner": comp.owner,
                "repo": comp.repo,
                "ref": comp.ref,
                "go_version": comp.go_version,
                "go_version_mismatch": go_version_mismatch,
                "internal_deps": internal_deps_data,
                "external_deps": [
                    {"path": d.path, "version": d.version} for d in external_deps
                ],
                "total_deps": len(comp.dependencies),
                "cves": cve_list,
            })

        # Count total CVEs for this version
        total_cves = sum(len(cves) for cves in version_cves.values())

        # Store version-level stats
        version_stats[osp_version] = {
            "has_go_mismatch": has_go_mismatch,
            "go_versions": sorted([f"{v[0]}.{v[1]}" for v in go_versions], reverse=True),
            "total_cves": total_cves,
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
