"""Tests for comprehend_product_batch + comprehend_product_apply."""
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
BATCH_PY = REPO_ROOT / "scripts" / "comprehend_product_batch.py"
APPLY_PY = REPO_ROOT / "scripts" / "comprehend_product_apply.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import comprehend_product_batch as pbatch  # type: ignore
import comprehend_product_apply as papply  # type: ignore


def _seed_product_with_two_binaries(tmp_path: Path):
    """One binary fully comprehended, one pending."""
    pdir = tmp_path / "catalog" / "products"
    bdir = tmp_path / "catalog" / "binaries"
    pdir.mkdir(parents=True)
    bdir.mkdir(parents=True)

    (pdir / "test-product.yml").write_text(yaml.safe_dump({
        "product": "test-product",
        "display_name": "Test Product",
        "vendor": "Acme",
        "description": "A made-up product for tests.",
        "binaries": ["bin_done", "bin_pending"],
    }))

    (bdir / "bin_done.yml").write_text(yaml.safe_dump({
        "binary": "bin_done",
        "summary": "SYSTEM-context worker.",
        "full_picture": {
            "loaded_by": ["service manager"], "start_trigger": ["boot"],
            "ipc_peers": [], "accepted_inputs": [], "dangerous_operations_reachable": [],
            "defense_gaps_observed": [],
        },
    }))

    (bdir / "bin_pending.yml").write_text(yaml.safe_dump({
        "binary": "bin_pending",
        "product": "test-product",
    }))


def test_build_bundle_splits_comprehended_vs_pending(tmp_path, monkeypatch):
    _seed_product_with_two_binaries(tmp_path)
    monkeypatch.setattr(pbatch, "ROOT", tmp_path)
    bundle = pbatch.build_bundle("test-product")
    assert len(bundle["binaries_comprehended"]) == 1
    assert bundle["binaries_comprehended"][0]["stem"] == "bin_done"
    assert "bin_pending" in bundle["binaries_pending"]


def test_build_bundle_handles_missing_binary_yaml(tmp_path, monkeypatch):
    pdir = tmp_path / "catalog" / "products"
    pdir.mkdir(parents=True)
    (pdir / "test-product.yml").write_text(yaml.safe_dump({
        "product": "test-product",
        "binaries": ["nonexistent_binary"],
    }))
    monkeypatch.setattr(pbatch, "ROOT", tmp_path)
    bundle = pbatch.build_bundle("test-product")
    assert bundle["binaries_comprehended"] == []
    assert "nonexistent_binary" in bundle["binaries_pending"]


def test_validate_accepts_valid_result():
    r = {
        "product": "test-product",
        "summary": "A product.",
        "data_flow_prose": "Data flows.",
        "binary_roles": [{"stem": "x", "role": "y"}],
        "trust_boundaries": ["A → B via C"],
        "attack_surface_primary": "X is the surface.",
    }
    assert papply.validate_worker_result(r) == []


def test_validate_rejects_missing_data_flow_prose():
    r = {
        "product": "test", "summary": "x",
        "binary_roles": [], "trust_boundaries": [],
        "attack_surface_primary": "x",
    }
    errors = papply.validate_worker_result(r)
    assert any("data_flow_prose" in e for e in errors)


def test_validate_rejects_role_without_stem():
    r = {
        "product": "test", "summary": "x", "data_flow_prose": "x",
        "binary_roles": [{"role": "no stem"}],
        "trust_boundaries": [], "attack_surface_primary": "x",
    }
    errors = papply.validate_worker_result(r)
    assert any("stem" in e for e in errors)


def test_merge_writes_architecture_narrative():
    product_yaml = {"product": "test-product", "binaries": ["bin_done"]}
    bundle = {
        "binaries_comprehended": [{"stem": "bin_done", "summary": "x", "full_picture": {}}],
        "binaries_pending": [],
    }
    result = {
        "product": "test-product",
        "summary": "Product summary.",
        "data_flow_prose": "Data flow text.",
        "binary_roles": [{"stem": "bin_done", "role": "the worker"}],
        "trust_boundaries": ["AU → SYSTEM via pipe (DACL)"],
        "attack_surface_primary": "Pipe is primary surface.",
    }
    out = papply.merge_into_product_yaml(product_yaml, result, bundle)
    nar = out["architecture_narrative"]
    assert nar["summary"] == "Product summary."
    assert nar["binary_roles"][0]["stem"] == "bin_done"
    assert "fingerprint" in nar
    assert "last_synthesized" in nar
    assert nar["binaries_comprehended"] == ["bin_done"]


def test_cli_batch_writes_bundle(tmp_path):
    _seed_product_with_two_binaries(tmp_path)
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(BATCH_PY), "--product", "test-product"],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    out = tmp_path / "catalog" / "products" / "test-product.comprehend_input.json"
    assert out.is_file()
    bundle = json.loads(out.read_text())
    assert len(bundle["binaries_comprehended"]) == 1


def test_cli_apply_end_to_end(tmp_path):
    _seed_product_with_two_binaries(tmp_path)
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    # Write the bundle
    subprocess.run(
        [sys.executable, str(BATCH_PY), "--product", "test-product"],
        env=env, capture_output=True, text=True, check=True,
    )
    # Write a worker result
    result = {
        "product": "test-product",
        "summary": "Test product overview.",
        "data_flow_prose": "Data flows from external attacker through bin_done.",
        "binary_roles": [
            {"stem": "bin_done", "role": "SYSTEM-context worker"},
            {"stem": "bin_pending", "role": "unknown — not yet reconstructed"},
        ],
        "trust_boundaries": ["AU → SYSTEM via test_pipe (no auth observed)"],
        "attack_surface_primary": "test_pipe is the entry point; bin_done dispatches.",
    }
    res_path = tmp_path / "result.json"
    res_path.write_text(json.dumps(result))

    bundle_path = tmp_path / "catalog" / "products" / "test-product.comprehend_input.json"
    r = subprocess.run(
        [sys.executable, str(APPLY_PY), "--product", "test-product",
         "--bundle", str(bundle_path), "--result", str(res_path)],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr

    # Verify product YAML now has the narrative
    p = yaml.safe_load((tmp_path / "catalog" / "products" / "test-product.yml").read_text())
    nar = p["architecture_narrative"]
    assert nar["summary"] == "Test product overview."
    assert "bin_done" in nar["binaries_comprehended"]
    assert "bin_pending" in nar["binaries_pending_reconstruction"]
