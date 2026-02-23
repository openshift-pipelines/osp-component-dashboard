"""Configuration loader for OSP dashboard."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    """Dashboard configuration."""

    # OSP version -> operator branch/tag
    operator_branches: dict[str, str] = field(default_factory=dict)
    # Extra components not in operator's components.yaml
    # {component: {osp_version: ref}}
    extra_components: dict[str, dict[str, str]] = field(default_factory=dict)
    # Components to skip from components.yaml
    skip_components: list[str] = field(default_factory=list)
    # Dependencies to highlight in the UI
    highlight_dependencies: list[str] = field(default_factory=list)
    # Support status for each version (full, maintenance, security, unsupported, upcoming, development)
    support_status: dict[str, str] = field(default_factory=dict)

    # npm-based components (manually tracked, not in operator's components.yaml)
    # {component: {osp_version: ref}}
    npm_components: dict[str, dict[str, str]] = field(default_factory=dict)
    # npm dependencies to highlight in the UI
    highlight_npm_dependencies: list[str] = field(default_factory=list)

    # Computed: OSP version -> {component_name: version}
    # Populated by resolve_versions()
    versions: dict[str, dict[str, str]] = field(default_factory=dict)
    # Computed: OSP version -> {npm_component: ref}
    # Populated by resolve_npm_versions()
    npm_versions: dict[str, dict[str, str]] = field(default_factory=dict)


def load_config(path: Path | str) -> Config:
    """Load configuration from YAML file.

    Args:
        path: Path to config.yaml

    Returns:
        Parsed Config object

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If YAML is invalid
    """
    path = Path(path)
    with open(path) as f:
        data = yaml.safe_load(f)

    return Config(
        operator_branches=data.get("operator_branches", {}),
        extra_components=data.get("extra_components", {}),
        skip_components=data.get("skip_components", []),
        highlight_dependencies=data.get("highlight_dependencies", []),
        support_status=data.get("support_status", {}),
        npm_components=data.get("npm_components", {}),
        highlight_npm_dependencies=data.get("highlight_npm_dependencies", []),
    )


def resolve_versions(config: Config, verbose: bool = False) -> None:
    """Resolve component versions from hack repo and operator's components.yaml.

    For versions that have a release file in openshift-pipelines/hack, uses that
    as the source of truth. Falls back to operator's components.yaml + extra_components
    for versions without a hack release file.

    For "main" OSP version, uses "main" branch for all components.

    Args:
        config: Config object to populate
        verbose: Print progress messages
    """
    from .collector import fetch_operator_components
    from .collector.hack import fetch_hack_release, list_hack_releases, parse_hack_release

    # Discover available hack release files
    hack_versions: dict[str, dict] = {}
    try:
        available = list_hack_releases()
        if verbose:
            print(f"  Found hack release configs: {', '.join(available)}")
        for v in available:
            try:
                hack_versions[v] = fetch_hack_release(v)
            except Exception as e:
                if verbose:
                    print(f"    Warning: Failed to fetch hack release {v}: {e}")
    except Exception as e:
        if verbose:
            print(f"  Warning: Failed to list hack releases: {e}")

    # Build the full set of versions to process:
    # - All versions from operator_branches (includes "main" and fallback versions)
    # - All versions discovered from hack (auto-picks up new releases)
    all_versions = set(config.operator_branches.keys()) | set(hack_versions.keys())

    for osp_version in sorted(all_versions, key=_version_sort_key):
        components: dict[str, str] = {}
        operator_ref = config.operator_branches.get(osp_version)

        # For "main" version, use main branch for all components
        use_main = osp_version == "main"

        # Try hack release file first
        hack_data = hack_versions.get(osp_version)
        if hack_data and not use_main:
            if verbose:
                print(f"  Using hack release config for {osp_version}...")
            components = parse_hack_release(hack_data, config.skip_components)

            # Auto-add support_status for new hack versions not in config
            if osp_version not in config.support_status:
                config.support_status[osp_version] = "upcoming"
                if verbose:
                    print(f"    New version from hack, defaulting support_status to 'upcoming'")

            if verbose:
                print(f"    Resolved {len(components)} components from hack")
        elif operator_ref is not None:
            # Fall back to operator's components.yaml
            if use_main:
                if verbose:
                    print(f"  Fetching components.yaml from operator @ {operator_ref} (main version)...")
            else:
                print(f"  WARNING: No hack release file for {osp_version}, "
                      f"falling back to operator components.yaml + config.yaml extra_components. "
                      f"Consider adding {osp_version}.yaml to openshift-pipelines/hack.")

            try:
                operator_components = fetch_operator_components(operator_ref)

                for name, info in operator_components.items():
                    # Skip if in skip list
                    if name in config.skip_components:
                        continue

                    github_path = info.get("github", "")
                    version = info.get("version", "")

                    if github_path:
                        # Use "main" for main version, otherwise use specified version
                        components[github_path] = "main" if use_main else version

            except Exception as e:
                if verbose:
                    print(f"    Warning: Failed to fetch components.yaml: {e}")

            # Add extra components for this version (only when not using hack)
            for component, version_map in config.extra_components.items():
                if osp_version in version_map:
                    components[component] = version_map[osp_version]

        # Always add operator itself (use hack's ref if available, else fallback)
        if "tektoncd/operator" not in components and operator_ref:
            components["tektoncd/operator"] = operator_ref

        config.versions[osp_version] = components

        if verbose:
            print(f"    Resolved {len(components)} components for {osp_version}")


def resolve_npm_versions(config: Config, verbose: bool = False) -> None:
    """Resolve npm component versions from config.

    Populates config.npm_versions from config.npm_components.

    Args:
        config: Config object to populate
        verbose: Print progress messages
    """
    if verbose and config.npm_components:
        print("  Resolving npm component versions...")

    # Build npm_versions from npm_components
    # npm_components is {component: {osp_version: ref}}
    # npm_versions should be {osp_version: {component: ref}}
    for component, version_map in config.npm_components.items():
        for osp_version, ref in version_map.items():
            if osp_version not in config.npm_versions:
                config.npm_versions[osp_version] = {}
            config.npm_versions[osp_version][component] = ref

    if verbose:
        total_npm = sum(len(v) for v in config.npm_versions.values())
        if total_npm:
            print(f"    Resolved {len(config.npm_components)} npm components across {len(config.npm_versions)} versions")


def _version_sort_key(version: str) -> tuple[int, float]:
    """Sort key for OSP version strings.

    Sorts "main" first, then "next", then numeric versions descending.

    Args:
        version: Version string like "main", "next", "1.22"

    Returns:
        Tuple for sorting
    """
    if version == "main":
        return (0, 0)
    if version == "next":
        return (1, 0)
    try:
        return (2, -float(version))
    except ValueError:
        return (3, 0)


def parse_component(component: str) -> tuple[str, str]:
    """Parse component string into owner and repo.

    Args:
        component: String like 'tektoncd/pipeline'

    Returns:
        Tuple of (owner, repo)
    """
    parts = component.split("/")
    if len(parts) != 2:
        raise ValueError(f"Invalid component format: {component}")
    return parts[0], parts[1]
