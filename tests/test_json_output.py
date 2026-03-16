"""Tests for JSON data output generation."""

from osp_dashboard.web.generator import _build_json_data


def test_build_json_data_basic():
    """Test basic JSON structure generation."""
    versions_data = {
        "1.21": [
            {
                "owner": "tektoncd",
                "repo": "pipeline",
                "ref": "release-v0.62.x",
                "tag_version": "v0.62.3",
                "language": "go",
                "go_version": "1.22",
                "go_version_mismatch": False,
                "internal_deps": [],
                "external_deps": [],
                "total_deps": 42,
                "cves": [],
                "vulns": [],
                "is_primary": False,
                "release_status": {
                    "branch_exists": True,
                    "branch_name": "release-v0.62.x",
                    "current_version": "v0.62.3",
                    "latest_version": "v0.62.3",
                    "has_unreleased": False,
                    "commits_ahead": 0,
                    "update_available": False,
                },
            },
        ],
    }
    version_stats = {
        "1.21": {
            "has_go_mismatch": False,
            "go_versions": ["1.22"],
            "total_cves": 0,
            "cve_details": [],
            "has_dep_mismatch": False,
            "mismatched_deps": [],
            "dep_cve_details": [],
            "total_dep_cves": 0,
            "total_vulns": 0,
            "called_vulns": 0,
            "vuln_details": [],
            "has_vuln_data": True,
            "has_npm_components": False,
            "npm_vulns_total": 0,
            "npm_vulns_direct": 0,
        },
    }
    support_status = {"1.21": "full"}
    bundled_versions = {"1.21": {"tektoncd/pipeline": "release-v0.62.x"}}

    result = _build_json_data(
        ["1.21"], versions_data, version_stats, support_status, bundled_versions
    )

    assert "generated_at" in result
    assert "versions" in result
    assert "1.21" in result["versions"]

    v121 = result["versions"]["1.21"]
    assert v121["support_status"] == "full"
    assert "tektoncd/pipeline" in v121["components"]

    comp = v121["components"]["tektoncd/pipeline"]
    assert comp["ref"] == "release-v0.62.x"
    assert comp["tag_version"] == "v0.62.3"
    assert comp["language"] == "go"
    assert comp["go_version"] == "1.22"
    assert comp["release_status"]["current_version"] == "v0.62.3"

    # has_vuln_data should be stripped from stats
    assert "has_vuln_data" not in v121["stats"]
    assert v121["stats"]["total_cves"] == 0


def test_build_json_data_npm_component():
    """Test JSON output includes npm-specific fields."""
    versions_data = {
        "1.21": [
            {
                "owner": "openshift-pipelines",
                "repo": "console-plugin",
                "ref": "release-v1.21.x",
                "language": "npm",
                "node_version": "20",
                "package_manager": "yarn@4.1.0",
                "go_version": None,
                "go_version_mismatch": False,
                "internal_deps": [],
                "external_deps": [],
                "total_deps": 15,
                "cves": [],
                "vulns": [],
                "npm_vulns": [{"id": "GHSA-123", "severity": "high", "package": "foo"}],
                "is_primary": False,
                "release_status": {
                    "branch_exists": True,
                    "branch_name": "release-v1.21.x",
                    "current_version": "",
                    "latest_version": "",
                    "has_unreleased": False,
                    "commits_ahead": 0,
                    "update_available": False,
                },
            },
        ],
    }
    version_stats = {
        "1.21": {
            "has_go_mismatch": False,
            "go_versions": [],
            "total_cves": 0,
            "cve_details": [],
            "has_dep_mismatch": False,
            "mismatched_deps": [],
            "dep_cve_details": [],
            "total_dep_cves": 0,
            "total_vulns": 0,
            "called_vulns": 0,
            "vuln_details": [],
            "has_vuln_data": False,
            "has_npm_components": True,
            "npm_vulns_total": 1,
            "npm_vulns_direct": 0,
        },
    }

    result = _build_json_data(["1.21"], versions_data, version_stats, {}, {})

    comp = result["versions"]["1.21"]["components"]["openshift-pipelines/console-plugin"]
    assert comp["language"] == "npm"
    assert comp["node_version"] == "20"
    assert comp["package_manager"] == "yarn@4.1.0"
    assert len(comp["npm_vulns"]) == 1


def test_build_json_data_empty():
    """Test JSON output with no versions."""
    result = _build_json_data([], {}, {}, {}, {})
    assert result["versions"] == {}
    assert "generated_at" in result
