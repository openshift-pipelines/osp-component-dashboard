"""Fetch and parse package.json files from GitHub for npm-based components."""

import json
import re
from dataclasses import dataclass, field

import httpx

from .gomod import ReleaseStatus, get_github_token, check_release_status


def fetch_npm_latest_versions(package_names: list[str], timeout: float = 30.0) -> dict[str, str]:
    """Fetch latest versions from npm registry for given packages.

    Args:
        package_names: List of npm package names
        timeout: Request timeout in seconds

    Returns:
        Dict of {package_name: latest_version}
    """
    latest_versions = {}

    with httpx.Client(timeout=timeout) as client:
        for name in package_names:
            try:
                # npm registry API - encode @ in scoped packages
                encoded_name = name.replace("/", "%2F")
                url = f"https://registry.npmjs.org/{encoded_name}/latest"
                response = client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    latest_versions[name] = data.get("version", "")
            except (httpx.HTTPError, json.JSONDecodeError):
                pass

    return latest_versions


@dataclass
class NpmDependency:
    """An npm package dependency."""

    name: str
    version: str
    is_dev: bool = False


@dataclass
class NpmComponentData:
    """Parsed data from a component's package.json."""

    owner: str
    repo: str
    ref: str
    node_version: str | None  # from package.json engines or .nvmrc
    package_manager: str | None  # yarn, npm, pnpm (from packageManager field)
    dependencies: list[NpmDependency]
    release_status: ReleaseStatus = field(default_factory=ReleaseStatus)


def fetch_package_json(owner: str, repo: str, ref: str, timeout: float = 30.0) -> str:
    """Fetch package.json content from GitHub.

    Args:
        owner: Repository owner (e.g., 'openshift-pipelines')
        repo: Repository name (e.g., 'console-plugin')
        ref: Git ref (tag, branch, or commit)
        timeout: Request timeout in seconds

    Returns:
        Raw package.json content as string

    Raises:
        httpx.HTTPStatusError: If the request fails
    """
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/package.json"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.text


def fetch_node_version(owner: str, repo: str, ref: str, timeout: float = 30.0) -> str | None:
    """Fetch Node.js version from various sources.

    Checks in order:
    1. .nvmrc
    2. .node-version
    3. package.json engines.node
    4. Dockerfile (ARG BUILDER or FROM nodejs-XX)

    Args:
        owner: Repository owner
        repo: Repository name
        ref: Git ref
        timeout: Request timeout in seconds

    Returns:
        Node version string or None if not found
    """
    token = get_github_token()
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"

    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
        # Try .nvmrc
        try:
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/.nvmrc"
            response = client.get(url)
            if response.status_code == 200:
                version = response.text.strip()
                # Clean up version string (remove 'v' prefix if present)
                return version.lstrip("v")
        except httpx.HTTPError:
            pass

        # Try .node-version
        try:
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/.node-version"
            response = client.get(url)
            if response.status_code == 200:
                version = response.text.strip()
                return version.lstrip("v")
        except httpx.HTTPError:
            pass

        # Try package.json engines.node
        try:
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/package.json"
            response = client.get(url)
            if response.status_code == 200:
                pkg = json.loads(response.text)
                engines = pkg.get("engines", {})
                node_constraint = engines.get("node")
                if node_constraint:
                    # Extract version from constraint like ">=18.0.0", "^20", "20.x"
                    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", node_constraint)
                    if match:
                        major = match.group(1)
                        minor = match.group(2) or "x"
                        return f"{major}.{minor}"
        except (httpx.HTTPError, json.JSONDecodeError):
            pass

        # Try Dockerfile - look for nodejs-XX image or NODE_VERSION ARG
        try:
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/Dockerfile"
            response = client.get(url)
            if response.status_code == 200:
                dockerfile = response.text
                # Match patterns like:
                # - registry.access.redhat.com/ubi9/nodejs-20
                # - node:20-alpine
                # - ARG NODE_VERSION=20
                patterns = [
                    r"nodejs-(\d+)",  # ubi9/nodejs-20
                    r"node:(\d+)",     # node:20-alpine
                    r"NODE_VERSION[=:](\d+)",  # ARG NODE_VERSION=20
                ]
                for pattern in patterns:
                    match = re.search(pattern, dockerfile)
                    if match:
                        return match.group(1)
        except httpx.HTTPError:
            pass

    return None


def parse_package_json(content: str) -> tuple[str | None, str | None, list[NpmDependency]]:
    """Parse package.json content to extract metadata and dependencies.

    Args:
        content: Raw package.json file content

    Returns:
        Tuple of (node_version, package_manager, list of dependencies)
    """
    pkg = json.loads(content)

    # Extract Node version from engines
    node_version = None
    engines = pkg.get("engines", {})
    node_constraint = engines.get("node")
    if node_constraint:
        match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", node_constraint)
        if match:
            major = match.group(1)
            minor = match.group(2) or "x"
            node_version = f"{major}.{minor}"

    # Extract package manager from packageManager field (e.g., "yarn@4.6.0")
    package_manager = None
    pm_field = pkg.get("packageManager")
    if pm_field:
        # Format: "yarn@4.6.0" or "npm@10.0.0"
        match = re.match(r"(\w+)@", pm_field)
        if match:
            package_manager = match.group(1)

    # Extract dependencies
    dependencies: list[NpmDependency] = []

    # Production dependencies
    for name, version in pkg.get("dependencies", {}).items():
        dependencies.append(NpmDependency(
            name=name,
            version=version,
            is_dev=False,
        ))

    # Dev dependencies
    for name, version in pkg.get("devDependencies", {}).items():
        dependencies.append(NpmDependency(
            name=name,
            version=version,
            is_dev=True,
        ))

    return node_version, package_manager, dependencies


def collect_npm_component_data(
    owner: str, repo: str, ref: str, timeout: float = 30.0,
    check_release: bool = False
) -> NpmComponentData:
    """Collect all data for an npm component.

    Args:
        owner: Repository owner
        repo: Repository name
        ref: Git ref (tag, branch, or commit)
        timeout: Request timeout in seconds
        check_release: Whether to check release branch for updates

    Returns:
        NpmComponentData with parsed package.json information
    """
    content = fetch_package_json(owner, repo, ref, timeout)
    engines_node, package_manager, dependencies = parse_package_json(content)

    # Try to get more specific Node version from .nvmrc or .node-version
    node_version = fetch_node_version(owner, repo, ref, timeout)
    if not node_version:
        node_version = engines_node

    release_status = ReleaseStatus()
    if check_release:
        release_status = check_release_status(owner, repo, ref)

    return NpmComponentData(
        owner=owner,
        repo=repo,
        ref=ref,
        node_version=node_version,
        package_manager=package_manager,
        dependencies=dependencies,
        release_status=release_status,
    )
