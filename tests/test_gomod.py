"""Tests for go.mod parsing."""

from osp_dashboard.collector.gomod import parse_gomod


def test_parse_go_version():
    """Test extracting Go version from go.mod."""
    content = """
module github.com/tektoncd/pipeline

go 1.22.0

require (
    github.com/foo/bar v1.0.0
)
"""
    go_version, deps = parse_gomod(content)
    assert go_version == "1.22.0"


def test_parse_go_version_short():
    """Test extracting short Go version."""
    content = """
module github.com/example/test

go 1.21
"""
    go_version, _ = parse_gomod(content)
    assert go_version == "1.21"


def test_parse_block_requires():
    """Test parsing require block."""
    content = """
module github.com/example/test

go 1.22

require (
    github.com/foo/bar v1.0.0
    github.com/baz/qux v2.0.0
    github.com/indirect/dep v0.1.0 // indirect
)
"""
    _, deps = parse_gomod(content)
    # Should skip indirect dependencies
    assert len(deps) == 2
    assert deps[0].path == "github.com/foo/bar"
    assert deps[0].version == "v1.0.0"
    assert deps[1].path == "github.com/baz/qux"
    assert deps[1].version == "v2.0.0"


def test_parse_single_require():
    """Test parsing single-line require."""
    content = """
module github.com/example/test

go 1.22

require github.com/single/dep v1.2.3
"""
    _, deps = parse_gomod(content)
    assert len(deps) == 1
    assert deps[0].path == "github.com/single/dep"
    assert deps[0].version == "v1.2.3"


def test_parse_mixed_requires():
    """Test parsing both single-line and block requires."""
    content = """
module github.com/example/test

go 1.22

require github.com/first/dep v1.0.0

require (
    github.com/second/dep v2.0.0
    github.com/third/dep v3.0.0
)
"""
    _, deps = parse_gomod(content)
    assert len(deps) == 3
    paths = [d.path for d in deps]
    assert "github.com/first/dep" in paths
    assert "github.com/second/dep" in paths
    assert "github.com/third/dep" in paths
