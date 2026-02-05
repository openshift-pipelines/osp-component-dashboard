"""CLI entry point for OSP Dashboard."""

import argparse
import sys
from pathlib import Path

from .collector import collect_component_data
from .config import load_config, parse_component
from .web import generate_html


def collect_command(args: argparse.Namespace) -> int:
    """Collect component data and generate HTML."""
    config_path = Path(args.config)
    output_path = Path(args.output)

    print(f"Loading config from {config_path}")
    config = load_config(config_path)

    all_data = {}

    for osp_version, components in config.versions.items():
        print(f"\nCollecting data for OSP {osp_version}...")
        version_data = []

        for component, ref in components.items():
            owner, repo = parse_component(component)
            print(f"  Fetching {owner}/{repo} @ {ref}...")
            try:
                data = collect_component_data(owner, repo, ref)
                version_data.append(data)
                print(f"    Go {data.go_version}, {len(data.dependencies)} deps")
            except Exception as e:
                print(f"    Error: {e}", file=sys.stderr)

        all_data[osp_version] = version_data

    print(f"\nGenerating HTML to {output_path}...")
    generate_html(all_data, config.highlight_dependencies, output_path)
    print("Done!")

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
    collect_parser.set_defaults(func=collect_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
