"""Tests for the `vb-add reconstruction` subcommand."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CATALOG_ADD = REPO_ROOT / "scripts" / "catalog_add.py"


def _make_binary_yaml(tmp_path: Path, stem: str) -> Path:
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True, exist_ok=True)
    f = bdir / f"{stem}.yml"
    f.write_text(yaml.safe_dump({
        "binary": stem,
        "product": "test-product",
        "sources": [],
        "sinks": [],
        "chains": [],
    }))
    return f


def test_vb_add_reconstruction_creates_catalog_dir(tmp_path, monkeypatch):
    stem = "sample_stem"
    _make_binary_yaml(tmp_path, stem)
    env = {**dict(__import__("os").environ), "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", "v1_0_0"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    recon_dir = tmp_path / "catalog" / "reconstructed" / f"{stem}_v1_0_0"
    assert recon_dir.is_dir(), f"{recon_dir} not created"
    assert (recon_dir / "manifest.json").is_file()
    assert (recon_dir / ".lock").is_file()


def test_vb_add_reconstruction_writes_block_to_binary_yaml(tmp_path):
    stem = "sample_stem"
    yml_path = _make_binary_yaml(tmp_path, stem)
    env = {**dict(__import__("os").environ), "VULNERABIN_ROOT": str(tmp_path)}
    subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", "v1_0_0"],
        capture_output=True, text=True, env=env, check=True,
    )
    data = yaml.safe_load(yml_path.read_text())
    assert "reconstruction" in data
    r = data["reconstruction"]
    assert r["ref"] == f"catalog/reconstructed/{stem}_v1_0_0"
    assert r["version_tag"] == "v1_0_0"
    assert r["status"] == "not_started"


def test_vb_add_reconstruction_is_idempotent_when_dir_exists(tmp_path):
    stem = "sample_stem"
    _make_binary_yaml(tmp_path, stem)
    env = {**dict(__import__("os").environ), "VULNERABIN_ROOT": str(tmp_path)}
    # First invocation: creates.
    subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", "v1_0_0"],
        env=env, check=True, capture_output=True, text=True,
    )
    # Second invocation: no-op.
    second = subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", "v1_0_0"],
        env=env, capture_output=True, text=True,
    )
    assert second.returncode == 0
    assert "already" in second.stdout.lower() or "exists" in second.stdout.lower() or "no-op" in second.stdout.lower()


def test_vb_add_reconstruction_refuses_unknown_binary(tmp_path):
    env = {**dict(__import__("os").environ), "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", "does_not_exist", "--version", "v1_0_0"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "binary" in result.stderr.lower() or "not found" in result.stderr.lower()
