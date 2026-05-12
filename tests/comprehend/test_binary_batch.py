"""Tests for comprehend_binary_batch."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BATCH_PY = REPO_ROOT / "scripts" / "comprehend_binary_batch.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import comprehend_binary_batch as batch  # type: ignore


def _seed_basic_yaml(tmp_path: Path, stem: str = "samplebin") -> Path:
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True, exist_ok=True)
    yml = bdir / f"{stem}.yml"
    yml.write_text(yaml.safe_dump({
        "binary": stem, "binary_kind": "exe", "platform": "windows",
        "product": "test-product",
        "description": "Sample test binary used in fixtures.",
        "process_model": {"principal": "SYSTEM"},
        "sources": [{"id": "SRC-001", "name": "pipe_handler"}],
        "sinks": [{"id": "SNK-001", "name": "CreateProcessAsUserW"}],
    }))
    return yml


def _seed_reconstruction(tmp_path: Path, stem: str, version: str = "v1"):
    rdir = tmp_path / "catalog" / "reconstructed" / f"{stem}_{version}"
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "manifest.json").write_text(json.dumps({
        "binary": {"stem": stem, "version_tag": version, "status": "partial"},
        "passes": [],
    }))
    (rdir / "coverage.json").write_text(json.dumps({
        "named": {"total_named": 700},
        "totals": {"user_defined_functions": 1000},
    }))
    (rdir / "vuln_surface.json").write_text(json.dumps({
        "summary": {"trust_boundary": 6, "ipc_source": 20, "privilege_sink": 11, "process_sink": 4},
        "classified": {
            "trust_boundary": [
                {"name": "verify_authenticode_signature"},
                {"name": "verify_file_trust"},
            ],
            "ipc_source": [{"name": "service__on_control_handler"}],
            "privilege_sink": [{"name": "install_bdelam_certificate"}],
        },
    }))
    return rdir


def test_build_bundle_minimal_yaml_only(tmp_path, monkeypatch):
    yml = _seed_basic_yaml(tmp_path, "samplebin")
    # Update binary YAML to NOT have reconstruction block.
    monkeypatch.setattr(batch, "ROOT", tmp_path)
    bundle = batch.build_bundle("samplebin")
    assert bundle["binary"]["stem"] == "samplebin"
    assert bundle["binary"]["principal"] == "SYSTEM"
    assert "catalog_yaml_excerpt" in bundle
    assert bundle["catalog_yaml_excerpt"]["sources"][0]["id"] == "SRC-001"
    # No reconstruction data
    assert "reconstruction" not in bundle


def test_build_bundle_with_full_reconstruction(tmp_path, monkeypatch):
    yml = _seed_basic_yaml(tmp_path, "samplebin")
    # Update YAML to point at reconstruction
    data = yaml.safe_load(yml.read_text())
    data["reconstruction"] = {"ref": "catalog/reconstructed/samplebin_v1", "version_tag": "v1", "status": "partial"}
    yml.write_text(yaml.safe_dump(data, sort_keys=False))
    _seed_reconstruction(tmp_path, "samplebin")

    monkeypatch.setattr(batch, "ROOT", tmp_path)
    bundle = batch.build_bundle("samplebin")
    assert "reconstruction" in bundle
    assert bundle["reconstruction"]["named_total"] == 700
    assert bundle["reconstruction"]["named_pct"] == 70.0
    assert "vuln_surface_summary" in bundle
    assert bundle["vuln_surface_summary"]["trust_boundary"] == 6
    assert "vuln_surface_examples" in bundle
    assert "trust_boundary" in bundle["vuln_surface_examples"]


def test_build_bundle_with_notes(tmp_path, monkeypatch):
    yml = _seed_basic_yaml(tmp_path, "samplebin")
    data = yaml.safe_load(yml.read_text())
    data["reconstruction"] = {"ref": "catalog/reconstructed/samplebin_v1", "version_tag": "v1", "status": "partial"}
    yml.write_text(yaml.safe_dump(data, sort_keys=False))
    rdir = _seed_reconstruction(tmp_path, "samplebin")
    notes_dir = rdir / "notes"
    notes_dir.mkdir()
    (notes_dir / "ipc.md").write_text("# IPC notes\n\n- Pipe foo\n")

    monkeypatch.setattr(batch, "ROOT", tmp_path)
    bundle = batch.build_bundle("samplebin")
    assert "notes_subsystems" in bundle
    assert "ipc" in bundle["notes_subsystems"]
    assert "Pipe foo" in bundle["notes_subsystems"]["ipc"]


def test_cli_writes_bundle_to_default_path(tmp_path):
    yml = _seed_basic_yaml(tmp_path, "samplebin")
    data = yaml.safe_load(yml.read_text())
    data["reconstruction"] = {"ref": "catalog/reconstructed/samplebin_v1", "version_tag": "v1", "status": "partial"}
    yml.write_text(yaml.safe_dump(data, sort_keys=False))
    _seed_reconstruction(tmp_path, "samplebin")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(BATCH_PY), "--binary", "samplebin"],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    out = tmp_path / "catalog" / "reconstructed" / "samplebin_v1" / "comprehend_input.json"
    assert out.is_file()
    data = json.loads(out.read_text())
    assert data["binary"]["stem"] == "samplebin"


def test_cli_refuses_unknown_binary(tmp_path):
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(BATCH_PY), "--binary", "does_not_exist"],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "not found" in (r.stdout + r.stderr).lower()
