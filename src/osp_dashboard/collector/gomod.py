"""Fetch and parse go.mod files from GitHub."""

import os
import re
import subprocess
from dataclasses import dataclass, field

import httpx
import yaml


def get_github_token() -> str:
    """Get GitHub token from environment or gh CLI."""
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        # Try to get token from gh CLI
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                token = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return token


@dataclass
class Dependency:
    """A Go module dependency."""

    path: str
    version: str


@dataclass
class ReleaseStatus:
    """Status of a component's release branch."""

    branch_exists: bool = False
    branch_name: str = ""
    current_version: str = ""
    latest_version: str = ""
    has_unreleased: bool = False
    commits_ahead: int = 0
    update_available: bool = False


@dataclass
class ComponentData:
    """Parsed data from a component's go.mod."""

    owner: str
    repo: str
    ref: str
    go_version: str
    dependencies: list[Dependency]
    commit: str = ""
    release_status: ReleaseStatus = field(default_factory=ReleaseStatus)


def fetch_downstream_head(
    downstream_name: str, ref: str, timeout: float = 10.0
) -> str:
    """Fetch the upstream commit SHA from a downstream fork's ``head`` file.

    The openshift-pipelines downstream forks (e.g.
    ``openshift-pipelines/tektoncd-pipeline``) store the upstream commit
    they were built from in a plain-text ``head`` file at the repo root.

    Args:
        downstream_name: Downstream repo name under openshift-pipelines
            (e.g., 'tektoncd-pipeline')
        ref: Git ref (branch) on the downstream fork
        timeout: Request timeout in seconds

    Returns:
        Full commit SHA string, or empty string if not available
    """
    url = (
        f"https://raw.githubusercontent.com/openshift-pipelines/"
        f"{downstream_name}/{ref}/head"
    )
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url)
            if response.status_code == 200:
                sha = response.text.strip()
                # Sanity-check: must look like a hex SHA
                if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
                    return sha
    except httpx.HTTPError:
        pass
    return ""


def _downstream_branch(osp_version: str) -> str:
    """Map an OSP version to the downstream fork branch name.

    The openshift-pipelines downstream forks use OSP-version-aligned
    branch names, not the upstream ref names:
        - ``main``  → ``main``
        - ``next``  → ``next``
        - ``1.22``  → ``release-v1.22.x``

    Args:
        osp_version: OSP version string (e.g., "main", "next", "1.22")

    Returns:
        Branch name on the downstream fork
    """
    if osp_version in ("main", "next"):
        return osp_version
    return f"release-v{osp_version}.x"


def resolve_commit_sha(
    owner: str, repo: str, ref: str,
    osp_version: str = "",
    timeout: float = 10.0,
) -> str:
    """Resolve a git ref to a commit SHA.

    First tries fetching the ``head`` file from the downstream
    openshift-pipelines fork (which records the upstream commit used).
    The downstream fork uses OSP-version-aligned branch names
    (e.g. ``release-v1.22.x``), so the *osp_version* is needed to
    locate the correct branch.

    Falls back to the GitHub API on the upstream repo.

    Args:
        owner: Repository owner (e.g., 'tektoncd')
        repo: Repository name (e.g., 'pipeline')
        ref: Git ref (tag, branch, or commit) on the *upstream* repo
        osp_version: OSP version (e.g., "1.22", "next", "main") used
            to derive the downstream branch name
        timeout: Request timeout in seconds

    Returns:
        Full commit SHA string, or empty string if resolution fails
    """
    # Build the downstream fork name.
    # tektoncd/pipeline  → openshift-pipelines/tektoncd-pipeline
    # konflux-ci/tekton-kueue → openshift-pipelines/tekton-kueue
    # openshift-pipelines/* repos don't have a head file (they *are* upstream)
    if owner != "openshift-pipelines" and osp_version:
        if owner == "tektoncd":
            downstream_name = f"tektoncd-{repo}"
        else:
            downstream_name = repo

        downstream_ref = _downstream_branch(osp_version)
        sha = fetch_downstream_head(downstream_name, downstream_ref, timeout)
        if sha:
            return sha

    # Fallback: resolve via GitHub API on the upstream repo
    token = get_github_token()
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"token {token}"

    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
        for ref_type in ("heads", "tags"):
            url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/{ref_type}/{ref}"
            try:
                response = client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    obj = data.get("object", {})
                    # For annotated tags, the object type is "tag" and we need
                    # to dereference to get the commit
                    if obj.get("type") == "tag":
                        tag_url = obj.get("url", "")
                        if tag_url:
                            tag_resp = client.get(tag_url)
                            if tag_resp.status_code == 200:
                                return tag_resp.json().get("object", {}).get("sha", "")
                    return obj.get("sha", "")
            except httpx.HTTPError:
                continue

    return ""


def fetch_gomod(owner: str, repo: str, ref: str, timeout: float = 30.0) -> str:
    """Fetch go.mod content from GitHub.

    Args:
        owner: Repository owner (e.g., 'tektoncd')
        repo: Repository name (e.g., 'pipeline')
        ref: Git ref (tag, branch, or commit)
        timeout: Request timeout in seconds

    Returns:
        Raw go.mod content as string

    Raises:
        httpx.HTTPStatusError: If the request fails
    """
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/go.mod"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.text


def get_release_branch_name(version: str) -> str:
    """Convert a version tag to release branch name.

    Args:
        version: Version tag like "v1.9.0", "v0.34.0"

    Returns:
        Release branch name like "release-v1.9.x", "release-v0.34.x"
    """
    # Strip leading 'v' and parse
    v = version.lstrip("v")
    match = re.match(r"(\d+)\.(\d+)\.", v)
    if match:
        major, minor = match.groups()
        return f"release-v{major}.{minor}.x"
    return ""


def check_release_status(
    owner: str, repo: str, current_ref: str, timeout: float = 10.0
) -> ReleaseStatus:
    """Check if there are updates available on the release branch.

    Args:
        owner: Repository owner
        repo: Repository name
        current_ref: Current version tag (e.g., "v1.9.0") or release branch (e.g., "release-v0.78.x")
        timeout: Request timeout in seconds

    Returns:
        ReleaseStatus with branch info and update availability
    """
    status = ReleaseStatus(current_version=current_ref)

    # Skip main branch
    if current_ref == "main":
        return status

    # Get GitHub token
    token = get_github_token()
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"

    # Determine if this is a release branch ref or a version tag
    is_branch_ref = current_ref.startswith("release-")

    if is_branch_ref:
        # Extract version pattern from branch name (e.g., "v0.78" from "release-v0.78.x")
        branch_name = current_ref
        match = re.match(r"release-(v\d+\.\d+)\.x", current_ref)
        version_prefix = match.group(1) if match else None
    else:
        # Version tag - derive branch name
        if not current_ref.startswith("v"):
            return status
        branch_name = get_release_branch_name(current_ref)
        if not branch_name:
            return status
        version_prefix = current_ref.rsplit(".", 1)[0]  # "v1.9" from "v1.9.0"

    status.branch_name = branch_name

    try:
        with httpx.Client(timeout=timeout, headers=headers) as client:
            # Check if branch exists
            branch_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch_name}"
            branch_resp = client.get(branch_url)
            if branch_resp.status_code == 404:
                return status  # Branch doesn't exist

            status.branch_exists = True
            branch_data = branch_resp.json()
            branch_sha = branch_data.get("commit", {}).get("sha", "")

            # Get tags matching this release branch pattern
            tags_url = f"https://api.github.com/repos/{owner}/{repo}/tags?per_page=100"
            tags_resp = client.get(tags_url)
            tags_resp.raise_for_status()
            tags = tags_resp.json()

            # Filter to matching minor version and sort
            if version_prefix:
                matching_tags = [
                    t for t in tags
                    if t["name"].startswith(version_prefix + ".")
                ]
            else:
                matching_tags = []

            if matching_tags:
                # Tags are usually sorted newest first, but let's be sure
                def parse_patch(tag_name: str) -> int:
                    match = re.search(r"\.(\d+)$", tag_name)
                    return int(match.group(1)) if match else 0

                matching_tags.sort(key=lambda t: parse_patch(t["name"]), reverse=True)
                latest_tag = matching_tags[0]
                status.latest_version = latest_tag["name"]

                if is_branch_ref:
                    # For branch refs, current_version should be the latest tag
                    status.current_version = latest_tag["name"]
                else:
                    # Check if there's a newer version than what we're tracking
                    current_patch = parse_patch(current_ref)
                    latest_patch = parse_patch(status.latest_version)
                    status.update_available = latest_patch > current_patch

                # Check if there are unreleased commits
                latest_tag_sha = latest_tag["commit"]["sha"]
                if branch_sha and latest_tag_sha and branch_sha != latest_tag_sha:
                    # Compare commits
                    compare_url = f"https://api.github.com/repos/{owner}/{repo}/compare/{latest_tag['name']}...{branch_name}"
                    compare_resp = client.get(compare_url)
                    if compare_resp.status_code == 200:
                        compare_data = compare_resp.json()
                        ahead_by = compare_data.get("ahead_by", 0)
                        status.has_unreleased = ahead_by > 0
                        status.commits_ahead = ahead_by

    except httpx.HTTPError:
        # If API fails, just return what we have
        pass

    return status


def parse_gomod(content: str) -> tuple[str, list[Dependency]]:
    """Parse go.mod content to extract Go version and dependencies.

    Args:
        content: Raw go.mod file content

    Returns:
        Tuple of (go_version, list of dependencies)
    """
    # Extract Go version
    go_version = ""
    go_match = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", content, re.MULTILINE)
    if go_match:
        go_version = go_match.group(1)

    dependencies: list[Dependency] = []

    # Find require blocks and single require statements
    # Handle both single-line: require github.com/foo/bar v1.0.0
    # And block form:
    # require (
    #     github.com/foo/bar v1.0.0
    # )

    # Single-line requires
    single_requires = re.findall(
        r"^require\s+(\S+)\s+(\S+)\s*$", content, re.MULTILINE
    )
    for path, version in single_requires:
        dependencies.append(Dependency(path=path, version=version))

    # Block requires
    block_pattern = re.compile(r"require\s*\(\s*(.*?)\s*\)", re.DOTALL)
    for block_match in block_pattern.finditer(content):
        block_content = block_match.group(1)
        # Parse each line in the block
        for line in block_content.strip().split("\n"):
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("//"):
                continue
            # Extract module path and version
            parts = line.split()
            if len(parts) >= 2:
                path = parts[0]
                version = parts[1]
                # Skip indirect dependencies
                if "// indirect" not in line:
                    dependencies.append(Dependency(path=path, version=version))

    return go_version, dependencies


def fetch_operator_components(
    ref: str, timeout: float = 30.0
) -> dict[str, dict[str, str]]:
    """Fetch components.yaml from the operator repository.

    Args:
        ref: Git ref (tag, branch, or commit) for tektoncd/operator
        timeout: Request timeout in seconds

    Returns:
        Dict mapping component name to {github: "owner/repo", version: "vX.Y.Z"}

    Raises:
        httpx.HTTPStatusError: If the request fails
    """
    url = f"https://raw.githubusercontent.com/tektoncd/operator/{ref}/components.yaml"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return yaml.safe_load(response.text)


def collect_component_data(
    owner: str, repo: str, ref: str, timeout: float = 30.0,
    check_release: bool = False,
    osp_version: str = "",
) -> ComponentData:
    """Collect all data for a component.

    Args:
        owner: Repository owner
        repo: Repository name
        ref: Git ref (tag, branch, or commit)
        timeout: Request timeout in seconds
        check_release: Whether to check release branch for updates
        osp_version: OSP version (e.g., "1.22") for downstream commit lookup

    Returns:
        ComponentData with parsed go.mod information
    """
    content = fetch_gomod(owner, repo, ref, timeout)
    go_version, dependencies = parse_gomod(content)

    commit = resolve_commit_sha(owner, repo, ref, osp_version=osp_version)

    release_status = ReleaseStatus()
    if check_release:
        release_status = check_release_status(owner, repo, ref)

    return ComponentData(
        owner=owner,
        repo=repo,
        ref=ref,
        go_version=go_version,
        dependencies=dependencies,
        commit=commit,
        release_status=release_status,
    )
