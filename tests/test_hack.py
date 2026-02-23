"""Tests for hack release config parsing."""

from osp_dashboard.collector.hack import parse_hack_release, resolve_hack_name


SAMPLE_RELEASE = {
    "version": 1.22,
    "patch-version": "1.22.0",
    "image-suffix": "-rhel9",
    "branches": {
        "git-init": {"upstream": "release-v1.2.x"},
        "manual-approval-gate": {"upstream": "release-v0.7.0"},
        "opc": {"upstream": "release-v1.19.x"},
        "pipelines-as-code": {"upstream": "release-v0.41.x"},
        "tekton-assist": {"upstream": "release-v0.1.x"},
        "tekton-caches": {"upstream": "release-v0.3.x"},
        "tekton-kueue": {"upstream": "release-v0.3.x"},
        "tektoncd-chains": {"upstream": "release-v0.26.x"},
        "tektoncd-cli": {"upstream": "release-v0.43.x"},
        "tektoncd-hub": {"upstream": "release-v1.23.6"},
        "tektoncd-operator": {"upstream": "main"},
        "tektoncd-pipeline": {"upstream": "release-v1.9.x"},
        "tektoncd-pruner": {"upstream": "release-v0.3.x"},
        "tektoncd-results": {"upstream": "release-v0.17.x"},
        "tektoncd-triggers": {"upstream": "release-v0.34.x"},
        "syncer-service": {"upstream": "release-v0.1.x"},
        "multicluster-proxy-aae": {"upstream": "release-v0.1.x"},
    },
}


def test_resolve_hack_name_known():
    """Test resolving known hack component names."""
    assert resolve_hack_name("tektoncd-pipeline") == "tektoncd/pipeline"
    assert resolve_hack_name("pipelines-as-code") == "openshift-pipelines/pipelines-as-code"
    assert resolve_hack_name("opc") == "openshift-pipelines/opc"
    assert resolve_hack_name("tekton-kueue") == "konflux-ci/tekton-kueue"


def test_resolve_hack_name_unknown():
    """Test resolving unknown hack component names."""
    assert resolve_hack_name("unknown-component") is None


def test_parse_hack_release_basic():
    """Test parsing a hack release YAML."""
    components = parse_hack_release(SAMPLE_RELEASE)

    assert "tektoncd/pipeline" in components
    assert components["tektoncd/pipeline"] == "release-v1.9.x"

    assert "tektoncd/chains" in components
    assert components["tektoncd/chains"] == "release-v0.26.x"

    assert "openshift-pipelines/pipelines-as-code" in components
    assert components["openshift-pipelines/pipelines-as-code"] == "release-v0.41.x"

    assert "tektoncd/operator" in components
    assert components["tektoncd/operator"] == "main"


def test_parse_hack_release_skips_git_init():
    """Test that git-init is skipped (shares repo with pipeline)."""
    components = parse_hack_release(SAMPLE_RELEASE)
    # git-init maps to tektoncd/pipeline, but should be skipped
    # pipeline should still be there from the tektoncd-pipeline entry
    assert components["tektoncd/pipeline"] == "release-v1.9.x"


def test_parse_hack_release_skip_components():
    """Test skipping components by repo name."""
    components = parse_hack_release(SAMPLE_RELEASE, skip_components=["hub", "chains"])

    assert "tektoncd/hub" not in components
    assert "tektoncd/chains" not in components
    # Others should still be present
    assert "tektoncd/pipeline" in components


def test_parse_hack_release_all_components():
    """Test that all expected components are resolved."""
    components = parse_hack_release(SAMPLE_RELEASE)

    expected = {
        "tektoncd/pipeline",
        "tektoncd/triggers",
        "tektoncd/chains",
        "tektoncd/results",
        "tektoncd/cli",
        "tektoncd/operator",
        "tektoncd/hub",
        "tektoncd/pruner",
        "openshift-pipelines/pipelines-as-code",
        "openshift-pipelines/manual-approval-gate",
        "openshift-pipelines/opc",
        "openshift-pipelines/tekton-caches",
        "openshift-pipelines/tekton-assist",
        "konflux-ci/tekton-kueue",
        "openshift-pipelines/syncer-service",
        "openshift-pipelines/multicluster-proxy-aae",
    }

    assert set(components.keys()) == expected


def test_parse_hack_release_empty():
    """Test parsing a release with no branches."""
    components = parse_hack_release({"version": 1.0})
    assert components == {}


def test_parse_hack_release_missing_upstream():
    """Test that entries without upstream are skipped."""
    data = {
        "branches": {
            "tektoncd-pipeline": {"upstream": "release-v1.9.x"},
            "tektoncd-triggers": {},  # no upstream
        }
    }
    components = parse_hack_release(data)
    assert "tektoncd/pipeline" in components
    assert "tektoncd/triggers" not in components
