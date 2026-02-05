"""Data collection modules."""

from .gomod import fetch_gomod, parse_gomod, collect_component_data

__all__ = ["fetch_gomod", "parse_gomod", "collect_component_data"]
