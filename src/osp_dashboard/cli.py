"""CLI entry point for OSP Dashboard."""

import argparse
import sys
from pathlib import Path

from .collector import collect_component_data, get_advisories_for_version, fetch_advisories
from .collector.govulncheck import scan_component, save_scan_results, load_scan_results
from .config import load_config, parse_component
from .web import generate_html


def collect_command(args: argparse.Namespace) -> int:
    """Collect component data and generate HTML."""
    config_path = Path(args.config)
    output_path = Path(args.output)

    print(f"Loading config from {config_path}")
    config = load_config(config_path)

    # Load govulncheck scan results if provided
    vuln_data = None
    if args.vulns:
        vulns_path = Path(args.vulns)
        if vulns_path.exists():
            print(f"\nLoading govulncheck results from {vulns_path}")
            vuln_data = load_scan_results(vulns_path)
            total = sum(
                len(findings)
                for version in vuln_data.values()
                for findings in version.values()
            )
            print(f"  Loaded {total} vulnerability findings")
        else:
            print(f"Warning: {vulns_path} not found, skipping vuln data", file=sys.stderr)

    # Pre-fetch CVE advisories for all tracked dependencies (to avoid repeated API calls)
    print("\nFetching CVE advisories for tracked dependencies...")
    dep_advisories = {}
    for dep_path in config.highlight_dependencies:
        advs = fetch_advisories(dep_path)
        if advs:
            dep_advisories[dep_path] = advs
            print(f"  {dep_path}: {len(advs)} advisory(ies)")

    all_data = {}
    all_cves = {}  # {osp_version: {component_key: [Advisory, ...]}}

    for osp_version, components in config.versions.items():
        print(f"\nCollecting data for OSP {osp_version}...")
        version_data = []
        version_cves = {}

        for component, ref in components.items():
            owner, repo = parse_component(component)
            print(f"  Fetching {owner}/{repo} @ {ref}...")
            try:
                data = collect_component_data(owner, repo, ref)
                version_data.append(data)
                print(f"    Go {data.go_version}, {len(data.dependencies)} deps")

                # Fetch CVEs for this component
                package = f"github.com/{owner}/{repo}"
                advisories = get_advisories_for_version(package, ref)
                if advisories:
                    version_cves[component] = advisories
                    print(f"    {len(advisories)} CVE(s) affecting this version")
            except Exception as e:
                print(f"    Error: {e}", file=sys.stderr)

        all_data[osp_version] = version_data
        all_cves[osp_version] = version_cves

    print(f"\nGenerating HTML to {output_path}...")
    generate_html(
        all_data,
        config.highlight_dependencies,
        output_path,
        bundled_versions=config.versions,
        cve_data=all_cves,
        dep_advisories=dep_advisories,
        vuln_data=vuln_data,
    )
    print("Done!")

    return 0


def scan_command(args: argparse.Namespace) -> int:
    """Scan components for vulnerabilities using govulncheck."""
    config_path = Path(args.config)
    output_path = Path(args.output)

    print(f"Loading config from {config_path}")
    config = load_config(config_path)

    # Check if govulncheck is available
    import subprocess
    try:
        subprocess.run(["govulncheck", "-version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: govulncheck not found. Install with:", file=sys.stderr)
        print("  go install golang.org/x/vuln/cmd/govulncheck@latest", file=sys.stderr)
        return 1

    all_vulns = {}
    total_findings = 0

    for osp_version, components in config.versions.items():
        print(f"\nScanning OSP {osp_version}...")
        version_vulns = {}

        for component, ref in components.items():
            owner, repo = parse_component(component)
            print(f"  Scanning {owner}/{repo} @ {ref}...")

            findings = scan_component(owner, repo, ref)
            if findings:
                version_vulns[component] = findings
                called = sum(1 for f in findings if f.is_called)
                print(f"    {len(findings)} vuln(s) found ({called} called)")
                total_findings += len(findings)
            else:
                print(f"    No vulnerabilities found")

        all_vulns[osp_version] = version_vulns

    print(f"\nSaving results to {output_path}...")
    save_scan_results(all_vulns, output_path)
    print(f"Done! Total: {total_findings} vulnerabilities across all versions")

    return 0


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="osp-dashboard",
        description="OSP Component Version Dashboard",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Collect command
    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect component data and generate HTML",
    )
    collect_parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    collect_parser.add_argument(
        "-o", "--output",
        default="data/index.html",
        help="Output HTML path (default: data/index.html)",
    )
    collect_parser.add_argument(
        "--vulns",
        help="Path to govulncheck scan results (from 'scan' command)",
    )
    collect_parser.set_defaults(func=collect_command)

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan components for vulnerabilities using govulncheck (slow)",
    )
    scan_parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    scan_parser.add_argument(
        "-o", "--output",
        default="data/vulns.json",
        help="Output JSON path (default: data/vulns.json)",
    )
    scan_parser.set_defaults(func=scan_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
