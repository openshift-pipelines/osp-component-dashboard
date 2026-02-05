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
