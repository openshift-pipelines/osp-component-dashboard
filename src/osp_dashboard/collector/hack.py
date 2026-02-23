"""Fetch release configurations from the openshift-pipelines/hack repository.

The hack repo at https://github.com/openshift-pipelines/hack contains
the source-of-truth release definitions under config/downstream/releases/.
Each YAML file defines which upstream branches/tags each component uses
for a given OSP version.
"""

import re

import httpx
import yaml

from .gomod import get_github_token

# Base URL for raw file access
HACK_RAW_BASE = "https://raw.githubusercontent.com/openshift-pipelines/hack/main"
HACK_API_BASE = "https://api.github.com/repos/openshift-pipelines/hack"

# Mapping from hack component names to GitHub owner/repo paths.
# Most components follow a pattern (e.g. "tektoncd-pipeline" → "tektoncd/pipeline"),
# but some need explicit mapping because the hack name doesn't match.
# Components found in operator's components.yaml are resolved dynamically;
# this table covers components that aren't in components.yaml or whose hack
# name differs from the components.yaml key.
HACK_NAME_TO_GITHUB: dict[str, str] = {
    "tektoncd-pipeline": "tektoncd/pipeline",
    "tektoncd-triggers": "tektoncd/triggers",
    "tektoncd-chains": "tektoncd/chains",
    "tektoncd-results": "tektoncd/results",
    "tektoncd-cli": "tektoncd/cli",
    "tektoncd-operator": "tektoncd/operator",
    "tektoncd-hub": "tektoncd/hub",
    "tektoncd-pruner": "tektoncd/pruner",
    "pipelines-as-code": "openshift-pipelines/pipelines-as-code",
    "manual-approval-gate": "openshift-pipelines/manual-approval-gate",
    "opc": "openshift-pipelines/opc",
    "tekton-caches": "openshift-pipelines/tekton-caches",
    "tekton-assist": "openshift-pipelines/tekton-assist",
    "tekton-kueue": "konflux-ci/tekton-kueue",
    "git-init": "tektoncd/pipeline",  # git-init lives inside tektoncd/pipeline
    "syncer-service": "openshift-pipelines/syncer-service",
    "multicluster-proxy-aae": "openshift-pipelines/multicluster-proxy-aae",
}


def list_hack_releases(timeout: float = 15.0) -> list[str]:
    """List available release YAML files from the hack repo.

    Returns:
        List of version identifiers (e.g., ["1.22", "next"])

    Raises:
        httpx.HTTPError: If the API request fails
    """
    token = get_github_token()
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"token {token}"

    url = f"{HACK_API_BASE}/contents/config/downstream/releases"
    with httpx.Client(timeout=timeout, headers=headers) as client:
        response = client.get(url)
        response.raise_for_status()
        files = response.json()

    versions: list[str] = []
    for f in files:
        name = f.get("name", "")
        if name.endswith(".yaml") or name.endswith(".yml"):
            version = re.sub(r"\.ya?ml$", "", name)
            versions.append(version)

    return versions


def fetch_hack_release(version: str, timeout: float = 15.0) -> dict:
    """Fetch a release YAML from the hack repo.

    Args:
        version: Version identifier (e.g., "1.22", "next")
        timeout: Request timeout in seconds

    Returns:
        Parsed YAML content as dict

    Raises:
        httpx.HTTPStatusError: If the file doesn't exist
    """
    url = f"{HACK_RAW_BASE}/config/downstream/releases/{version}.yaml"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return yaml.safe_load(response.text)


def resolve_hack_name(name: str) -> str | None:
    """Resolve a hack component name to a GitHub owner/repo path.

    Args:
        name: Component name from hack release YAML (e.g., "tektoncd-pipeline")

    Returns:
        GitHub path like "tektoncd/pipeline", or None if unknown
    """
    return HACK_NAME_TO_GITHUB.get(name)


def parse_hack_release(
    release_data: dict,
    skip_components: list[str] | None = None,
) -> dict[str, str]:
    """Parse a hack release YAML into a component→ref mapping.

    Args:
        release_data: Parsed YAML from fetch_hack_release
        skip_components: Component names to skip (matches against the
            repo part of the GitHub path, e.g., "dashboard", "hub")

    Returns:
        Dict mapping GitHub paths (e.g., "tektoncd/pipeline") to git refs
        (e.g., "release-v1.9.x")
    """
    skip = set(skip_components or [])
    branches = release_data.get("branches", {})
    components: dict[str, str] = {}

    for hack_name, info in branches.items():
        upstream_ref = info.get("upstream", "")
        if not upstream_ref:
            continue

        github_path = resolve_hack_name(hack_name)
        if github_path is None:
            continue

        # Check if the repo part is in the skip list
        repo = github_path.split("/")[-1]
        if repo in skip:
            continue

        # Skip git-init since it shares a repo with pipeline
        if hack_name == "git-init":
            continue

        components[github_path] = upstream_ref

    return components
