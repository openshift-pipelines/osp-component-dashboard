# OSP Component Dashboard

Static dashboard displaying Go versions and dependencies for [OpenShift Pipelines](https://github.com/openshift-pipelines) components.

**Live:** https://openshift-pipelines.github.io/osp-component-dashboard/

![Dashboard Screenshot](docs/screenshot.png)

## Features

- Go version tracking across OSP releases
- "Next" version tracking latest upstream releases
- Cross-dependency detection between Tekton components
- Warnings for Go version mismatches within a release
- Stale dependency flagging
- Card and table view toggle

## Usage

```bash
uv run osp-dashboard collect
```

Generates `data/index.html` from component go.mod files.

## Configuration

Edit `config.yaml` to add/update OSP versions and components.
