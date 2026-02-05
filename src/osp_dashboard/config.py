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

    # Computed: OSP version -> {component_name: version}
    # Populated by resolve_versions()
    versions: dict[str, dict[str, str]] = field(default_factory=dict)


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
    )


def resolve_versions(config: Config, verbose: bool = False) -> None:
    """Resolve component versions from operator's components.yaml.

    Fetches components.yaml from the operator at each OSP version's branch,
    merges with extra_components, and populates config.versions.

    For "main" OSP version, uses "main" branch for all components instead of
    the versions in components.yaml.

    Args:
        config: Config object to populate
        verbose: Print progress messages
    """
    from .collector import fetch_operator_components

    for osp_version, operator_ref in config.operator_branches.items():
        if verbose:
            print(f"  Fetching components.yaml from operator @ {operator_ref}...")

        components = {}

        # For "main" version, use main branch for all components
        use_main = osp_version == "main"

        # Fetch from operator's components.yaml
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

        # Add extra components for this version
        for component, version_map in config.extra_components.items():
            if osp_version in version_map:
                components[component] = version_map[osp_version]

        # Always add operator itself
        components["tektoncd/operator"] = operator_ref

        config.versions[osp_version] = components

        if verbose:
            print(f"    Resolved {len(components)} components for {osp_version}")


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
