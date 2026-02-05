"""HTML generator for the dashboard."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..collector.gomod import ComponentData

# Internal Tekton/OSP dependency prefixes
INTERNAL_PREFIXES = (
    "github.com/tektoncd/",
    "github.com/openshift-pipelines/",
)


def is_internal_dep(path: str) -> bool:
    """Check if a dependency is an internal OSP/Tekton component."""
    return any(path.startswith(prefix) for prefix in INTERNAL_PREFIXES)


def generate_html(
    data: dict[str, list[ComponentData]],
    highlight_deps: list[str],
    output_path: Path | str,
    template_dir: Path | str | None = None,
) -> None:
    """Generate the dashboard HTML.

    Args:
        data: Dict of OSP version -> list of ComponentData
        highlight_deps: List of dependency paths to highlight
        output_path: Where to write the generated HTML
        template_dir: Directory containing templates (defaults to templates/)
    """
    if template_dir is None:
        template_dir = Path(__file__).parent / "templates"

    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("index.html")

    # Convert to template-friendly format
    versions_data = {}
    for osp_version, components in data.items():
        versions_data[osp_version] = []
        for comp in components:
            # Filter to highlighted dependencies
            highlighted = [
                d for d in comp.dependencies if d.path in highlight_deps
            ]

            # Separate internal (cross-dependencies) from external
            internal_deps = [d for d in highlighted if is_internal_dep(d.path)]
            external_deps = [d for d in highlighted if not is_internal_dep(d.path)]

            # Sort by path for consistent display
            internal_deps.sort(key=lambda d: d.path)
            external_deps.sort(key=lambda d: d.path)

            versions_data[osp_version].append({
                "owner": comp.owner,
                "repo": comp.repo,
                "ref": comp.ref,
                "go_version": comp.go_version,
                "internal_deps": [
                    {"path": d.path, "version": d.version} for d in internal_deps
                ],
                "external_deps": [
                    {"path": d.path, "version": d.version} for d in external_deps
                ],
                "total_deps": len(comp.dependencies),
            })

    # Sort OSP versions descending (newest first)
    sorted_versions = sorted(versions_data.keys(), reverse=True)

    html = template.render(
        versions=sorted_versions,
        versions_data=versions_data,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
