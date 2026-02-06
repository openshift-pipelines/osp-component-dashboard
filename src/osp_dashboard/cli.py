"""CLI entry point for OSP Dashboard."""

import argparse
import sys
from pathlib import Path

from .collector import collect_component_data, get_advisories_for_version, fetch_advisories
from .collector import collect_npm_component_data, fetch_npm_latest_versions
from .collector.govulncheck import scan_component, save_scan_results, load_scan_results
from .collector.npmaudit import scan_npm_component, save_npm_scan_results, load_npm_scan_results
from .config import load_config, parse_component, resolve_versions, resolve_npm_versions
from .web import generate_html


def collect_command(args: argparse.Namespace) -> int:
    """Collect component data and generate HTML."""
    config_path = Path(args.config)
    output_path = Path(args.output)

    print(f"Loading config from {config_path}")
    config = load_config(config_path)

    print("\nResolving component versions from operator...")
    resolve_versions(config, verbose=True)
    resolve_npm_versions(config, verbose=True)

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

    # Load npm audit scan results if provided
    npm_vuln_data = None
    if args.npm_vulns:
        npm_vulns_path = Path(args.npm_vulns)
        if npm_vulns_path.exists():
            print(f"\nLoading npm audit results from {npm_vulns_path}")
            npm_vuln_data = load_npm_scan_results(npm_vulns_path)
            total = sum(
                len(findings)
                for version in npm_vuln_data.values()
                for findings in version.values()
            )
            print(f"  Loaded {total} npm vulnerability findings")
        else:
            print(f"Warning: {npm_vulns_path} not found, skipping npm vuln data", file=sys.stderr)

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

        # Check release branches for all versions except "main"
        check_releases = osp_version != "main"

        for component, ref in components.items():
            owner, repo = parse_component(component)
            print(f"  Fetching {owner}/{repo} @ {ref}...")
            try:
                data = collect_component_data(owner, repo, ref, check_release=check_releases)
                version_data.append(data)
                status_info = ""
                if data.release_status.branch_exists:
                    if data.release_status.update_available:
                        status_info = f", update: {data.release_status.latest_version}"
                    elif data.release_status.has_unreleased:
                        status_info = f", +{data.release_status.commits_ahead} ahead"
                print(f"    Go {data.go_version}, {len(data.dependencies)} deps{status_info}")

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

    # Collect npm component data
    all_npm_data = {}
    if config.npm_versions:
        for osp_version, components in config.npm_versions.items():
            print(f"\nCollecting npm data for OSP {osp_version}...")
            version_npm_data = []

            # Check release branches for all versions except "main"
            check_releases = osp_version != "main"

            for component, ref in components.items():
                owner, repo = parse_component(component)
                print(f"  Fetching {owner}/{repo} @ {ref}...")
                try:
                    data = collect_npm_component_data(owner, repo, ref, check_release=check_releases)
                    version_npm_data.append(data)
                    node_info = f"Node {data.node_version}" if data.node_version else "Node ?"
                    pm_info = f", {data.package_manager}" if data.package_manager else ""
                    print(f"    {node_info}{pm_info}, {len(data.dependencies)} deps")
                except Exception as e:
                    print(f"    Error: {e}", file=sys.stderr)

            all_npm_data[osp_version] = version_npm_data

    # Fetch latest versions from npm registry for highlighted packages
    npm_latest_versions = {}
    if config.highlight_npm_dependencies:
        print("\nFetching latest versions from npm registry...")
        npm_latest_versions = fetch_npm_latest_versions(config.highlight_npm_dependencies)
        for pkg, version in npm_latest_versions.items():
            print(f"  {pkg}: {version}")

    print(f"\nGenerating HTML to {output_path}...")
    generate_html(
        all_data,
        config.highlight_dependencies,
        output_path,
        bundled_versions=config.versions,
        cve_data=all_cves,
        dep_advisories=dep_advisories,
        vuln_data=vuln_data,
        support_status=config.support_status,
        npm_data=all_npm_data,
        highlight_npm_deps=config.highlight_npm_dependencies,
        npm_vuln_data=npm_vuln_data,
        npm_latest_versions=npm_latest_versions,
    )
    print("Done!")

    return 0


def scan_command(args: argparse.Namespace) -> int:
    """Scan components for vulnerabilities using govulncheck."""
    import time
    config_path = Path(args.config)
    output_path = Path(args.output)

    print(f"Loading config from {config_path}")
    config = load_config(config_path)

    print("\nResolving component versions from operator...")
    resolve_versions(config, verbose=True)

    # Check if govulncheck is available
    import subprocess
    try:
        result = subprocess.run(["govulncheck", "-version"], capture_output=True, check=True, text=True)
        print(f"Using {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: govulncheck not found. Install with:", file=sys.stderr)
        print("  go install golang.org/x/vuln/cmd/govulncheck@latest", file=sys.stderr)
        return 1

    # Filter to single version if specified
    versions_to_scan = config.versions
    if args.version:
        if args.version not in config.versions:
            print(f"Error: Version '{args.version}' not found in config", file=sys.stderr)
            print(f"Available versions: {', '.join(config.versions.keys())}", file=sys.stderr)
            return 1
        versions_to_scan = {args.version: config.versions[args.version]}
        print(f"Scanning only version: {args.version}")

    # Count total scans
    total_scans = sum(len(components) for components in versions_to_scan.values())
    current_scan = 0
    start_time = time.time()

    all_vulns = {}
    total_findings = 0

    for osp_version, components in versions_to_scan.items():
        print(f"\n{'='*60}")
        print(f"Scanning OSP {osp_version} ({len(components)} components)")
        print(f"{'='*60}")
        version_vulns = {}

        for component, ref in components.items():
            current_scan += 1
            owner, repo = parse_component(component)
            elapsed = time.time() - start_time
            print(f"\n  [{current_scan}/{total_scans}] {owner}/{repo} @ {ref}")
            print(f"    Elapsed: {elapsed/60:.1f} min")

            findings = scan_component(owner, repo, ref)
            if findings:
                version_vulns[component] = findings
                called = sum(1 for f in findings if f.is_called)
                print(f"    Result: {len(findings)} vuln(s) ({called} called)")
                total_findings += len(findings)
            else:
                print(f"    Result: No vulnerabilities found")

        all_vulns[osp_version] = version_vulns

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"Scan complete!")
    print(f"{'='*60}")
    print(f"  Duration: {elapsed/60:.1f} minutes")
    print(f"  Components scanned: {total_scans}")
    print(f"  Vulnerabilities found: {total_findings}")
    print(f"\nSaving results to {output_path}...")
    save_scan_results(all_vulns, output_path)
    print("Done!")

    return 0


def scan_npm_command(args: argparse.Namespace) -> int:
    """Scan npm components for vulnerabilities using npm audit."""
    import time
    config_path = Path(args.config)
    output_path = Path(args.output)

    print(f"Loading config from {config_path}")
    config = load_config(config_path)

    print("\nResolving npm component versions...")
    resolve_npm_versions(config, verbose=True)

    if not config.npm_versions:
        print("No npm components configured, nothing to scan")
        return 0

    # Check if npm is available
    import subprocess
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, check=True, text=True)
        print(f"Using npm {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: npm not found. Please install Node.js/npm.", file=sys.stderr)
        return 1

    # Filter to single version if specified
    versions_to_scan = config.npm_versions
    if args.version:
        if args.version not in config.npm_versions:
            print(f"Error: Version '{args.version}' not found in npm config", file=sys.stderr)
            print(f"Available versions: {', '.join(config.npm_versions.keys())}", file=sys.stderr)
            return 1
        versions_to_scan = {args.version: config.npm_versions[args.version]}
        print(f"Scanning only version: {args.version}")

    # Count total scans
    total_scans = sum(len(components) for components in versions_to_scan.values())
    current_scan = 0
    start_time = time.time()

    all_vulns = {}
    total_findings = 0

    for osp_version, components in versions_to_scan.items():
        print(f"\n{'='*60}")
        print(f"Scanning npm OSP {osp_version} ({len(components)} components)")
        print(f"{'='*60}")
        version_vulns = {}

        for component, ref in components.items():
            current_scan += 1
            owner, repo = parse_component(component)
            elapsed = time.time() - start_time
            print(f"\n  [{current_scan}/{total_scans}] {owner}/{repo} @ {ref}")
            print(f"    Elapsed: {elapsed/60:.1f} min")

            findings = scan_npm_component(owner, repo, ref)
            if findings:
                version_vulns[component] = findings
                direct = sum(1 for f in findings if f.is_direct)
                print(f"    Result: {len(findings)} vuln(s) ({direct} direct)")
                total_findings += len(findings)
            else:
                print(f"    Result: No vulnerabilities found")

        all_vulns[osp_version] = version_vulns

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"npm scan complete!")
    print(f"{'='*60}")
    print(f"  Duration: {elapsed/60:.1f} minutes")
    print(f"  Components scanned: {total_scans}")
    print(f"  Vulnerabilities found: {total_findings}")
    print(f"\nSaving results to {output_path}...")
    save_npm_scan_results(all_vulns, output_path)
    print("Done!")

    return 0


def merge_command(args: argparse.Namespace) -> int:
    """Merge multiple vuln scan results into one file."""
    import json
    output_path = Path(args.output)

    merged = {}
    for input_file in args.inputs:
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"Warning: {input_path} not found, skipping", file=sys.stderr)
            continue

        print(f"Loading {input_path}...")
        data = json.loads(input_path.read_text())
        merged.update(data)

    print(f"Merged {len(merged)} versions into {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(merged, indent=2))

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
    collect_parser.add_argument(
        "--npm-vulns",
        help="Path to npm audit scan results (from 'scan-npm' command)",
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
    scan_parser.add_argument(
        "-v", "--version",
        help="Scan only a specific OSP version (e.g., '1.21', 'main')",
    )
    scan_parser.set_defaults(func=scan_command)

    # Scan npm command
    scan_npm_parser = subparsers.add_parser(
        "scan-npm",
        help="Scan npm components for vulnerabilities using npm audit",
    )
    scan_npm_parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    scan_npm_parser.add_argument(
        "-o", "--output",
        default="data/npm-vulns.json",
        help="Output JSON path (default: data/npm-vulns.json)",
    )
    scan_npm_parser.add_argument(
        "-v", "--version",
        help="Scan only a specific OSP version (e.g., '1.21', 'main')",
    )
    scan_npm_parser.set_defaults(func=scan_npm_command)

    # Merge command
    merge_parser = subparsers.add_parser(
        "merge",
        help="Merge multiple vuln scan results into one file",
    )
    merge_parser.add_argument(
        "inputs",
        nargs="+",
        help="Input JSON files to merge",
    )
    merge_parser.add_argument(
        "-o", "--output",
        default="data/vulns.json",
        help="Output JSON path (default: data/vulns.json)",
    )
    merge_parser.set_defaults(func=merge_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
