"""Fetch and parse go.mod files from GitHub."""

import re
from dataclasses import dataclass

import httpx


@dataclass
class Dependency:
    """A Go module dependency."""

    path: str
    version: str


@dataclass
class ComponentData:
    """Parsed data from a component's go.mod."""

    owner: str
    repo: str
    ref: str
    go_version: str
    dependencies: list[Dependency]


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


def collect_component_data(
    owner: str, repo: str, ref: str, timeout: float = 30.0
) -> ComponentData:
    """Collect all data for a component.

    Args:
        owner: Repository owner
        repo: Repository name
        ref: Git ref (tag, branch, or commit)
        timeout: Request timeout in seconds

    Returns:
        ComponentData with parsed go.mod information
    """
    content = fetch_gomod(owner, repo, ref, timeout)
    go_version, dependencies = parse_gomod(content)

    return ComponentData(
        owner=owner,
        repo=repo,
        ref=ref,
        go_version=go_version,
        dependencies=dependencies,
    )
