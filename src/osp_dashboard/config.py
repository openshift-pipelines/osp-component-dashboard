"""Configuration loader for OSP dashboard."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    """Dashboard configuration."""

    # OSP version -> {component_name: version}
    versions: dict[str, dict[str, str]] = field(default_factory=dict)
    # Dependencies to highlight in the UI
    highlight_dependencies: list[str] = field(default_factory=list)
    # Support status for each version (full, maintenance, security, unsupported, upcoming, development)
    support_status: dict[str, str] = field(default_factory=dict)


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
        versions=data.get("versions", {}),
        highlight_dependencies=data.get("highlight_dependencies", []),
        support_status=data.get("support_status", {}),
    )


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
