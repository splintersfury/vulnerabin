"""Test vb walk CLI subcommands."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WALK_PY = REPO_ROOT / "scripts" / "catalog_walk.py"


def _make_binary_yaml(tmp_path: Path, name: str, contents: dict) -> Path:
    """Drop a binary YAML into a fresh catalog/binaries dir under tmp_path."""
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True, exist_ok=True)
    f = bdir / f"{name}.yml"
    f.write_text(yaml.safe_dump(contents))
    return f


def _run_walk(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(WALK_PY)] + args,
        cwd=cwd, capture_output=True, text=True,
    )


def test_status_empty_binary_reports_not_started(tmp_path):
    _make_binary_yaml(tmp_path, "test_dll", {
        "binary": "test.dll",
        "platform": "windows",
        "binary_kind": "dll",
    })
    r = _run_walk(["status", "test_dll", "--json"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["current_stage"] == "not_started"
    assert out["pending_counts"]["features_unconfirmed"] == 0


def test_status_open_2a_reports_pending_inputs(tmp_path):
    _make_binary_yaml(tmp_path, "test_dll", {
        "binary": "test.dll",
        "platform": "windows",
        "binary_kind": "dll",
        "reverse_engineering": {
            "inputs": [
                {"id": "INP-001", "kind": "ioctl", "confirmed": False},
                {"id": "INP-002", "kind": "ipc_pipe", "confirmed": True},
            ],
        },
        "walk_state": {
            "stages": {
                "2a-inputs": {"status": "open", "opened_at": "2026-05-10T00:00:00Z"},
                "2b-sinks": {"status": "not_started"},
                "2c-features": {"status": "not_started"},
            },
        },
    })
    r = _run_walk(["status", "test_dll", "--json"], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["current_stage"] == "2a-inputs"
    assert out["pending_counts"]["inputs_unconfirmed"] == 1
