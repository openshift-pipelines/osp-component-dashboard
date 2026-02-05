"""Data collection modules."""

from .gomod import fetch_gomod, parse_gomod, collect_component_data
from .cve import Advisory, fetch_advisories, get_advisories_for_version

__all__ = [
    "fetch_gomod",
    "parse_gomod",
    "collect_component_data",
    "Advisory",
    "fetch_advisories",
    "get_advisories_for_version",
]
