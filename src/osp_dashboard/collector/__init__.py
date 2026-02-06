"""Data collection modules."""

from .gomod import fetch_gomod, parse_gomod, collect_component_data, fetch_operator_components
from .cve import Advisory, fetch_advisories, get_advisories_for_version
from .govulncheck import VulnFinding, scan_component, save_scan_results, load_scan_results
from .npm import NpmDependency, NpmComponentData, collect_npm_component_data, fetch_npm_latest_versions
from .npmaudit import NpmVulnFinding, scan_npm_component, save_npm_scan_results, load_npm_scan_results

__all__ = [
    # Go modules
    "fetch_gomod",
    "parse_gomod",
    "collect_component_data",
    "fetch_operator_components",
    # CVE/Advisory
    "Advisory",
    "fetch_advisories",
    "get_advisories_for_version",
    # Go vulnerabilities
    "VulnFinding",
    "scan_component",
    "save_scan_results",
    "load_scan_results",
    # npm modules
    "NpmDependency",
    "NpmComponentData",
    "collect_npm_component_data",
    "fetch_npm_latest_versions",
    # npm vulnerabilities
    "NpmVulnFinding",
    "scan_npm_component",
    "save_npm_scan_results",
    "load_npm_scan_results",
]
