"""Tests for catalog_reconstruct_render — Layer 8 page generation."""
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
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import catalog_reconstruct_render as r  # type: ignore


def _seed_recon_dir(tmp_path: Path, stem: str = "samplebin", tag: str = "v1_2_3") -> Path:
    """Materialize a catalog/reconstructed/<stem>_<tag>/ dir with the fixtures."""
    d = tmp_path / "catalog" / "reconstructed" / f"{stem}_{tag}"
    d.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_complete.json", d / "manifest.json")
    shutil.copy(FIXTURES / "sample_coverage_complete.json", d / "coverage.json")
    return d


def test_build_context_returns_required_top_level_keys(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    assert set(ctx.keys()) >= {
        "stem",
        "version_tag",
        "status",
        "coverage",
        "pass_log",
        "project_discovery",
        "proposed_renames",
        "renames_by_source_totals",
        "carryforward",
    }
    assert ctx["stem"] == "samplebin"
    assert ctx["version_tag"] == "v1_2_3"
    assert ctx["status"] == "partial"


def test_build_context_coverage_summary(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    cov = ctx["coverage"]
    assert cov["hard_gate_pass"] is False
    assert cov["soft_gate_pass"] is False
    assert cov["totals"]["user_defined_functions"] == 8
    assert cov["named_total"] == 6
    assert cov["named_pct"] == pytest.approx(75.0)  # 6/8 = 75%


def test_build_context_pass_log_lists_pass0(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    log = ctx["pass_log"]
    assert len(log) == 1
    entry = log[0]
    assert entry["pass"] == "pass0"
    assert entry["tools_used"] == [
        "project_discovery", "iat_wrapper_detection", "pcode_hash_carryforward"
    ]
    assert entry["renames_proposed"] == 3
    # Duration field should be derived from started_at + ended_at.
    assert "duration_seconds" in entry
    assert entry["duration_seconds"] == 42


def test_build_context_proposed_renames_sorted_and_complete(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    renames = ctx["proposed_renames"]
    assert len(renames) == 3
    # Sorted by addr (matches reconstruct_pass0 sort).
    addrs = [p["addr"] for p in renames]
    assert addrs == sorted(addrs)
    for p in renames:
        assert {"addr", "from", "to", "confidence", "source", "rationale"} <= set(p.keys())


def test_build_context_renames_by_source_totals(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    totals = ctx["renames_by_source_totals"]
    assert totals["iat_wrapper_detection"] == 2
    assert totals["pcode_hash_carryforward"] == 1


def test_build_context_carryforward_summary(tmp_path):
    recon_dir = _seed_recon_dir(tmp_path)
    ctx = r.build_context(recon_dir)
    cf = ctx["carryforward"]
    assert cf["prior_version_consulted"] == "samplebin_v1_2_2"
    assert cf["renames_ported"] == 1  # one pcode_hash_carryforward rename


def test_build_context_handles_missing_coverage_json(tmp_path):
    """If coverage.json is absent, still produce a context (just empty coverage)."""
    d = tmp_path / "catalog" / "reconstructed" / "samplebin_vfresh"
    d.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_complete.json", d / "manifest.json")
    ctx = r.build_context(d)
    assert ctx["coverage"] is None or ctx["coverage"] == {} or "hard_gate_pass" not in (ctx["coverage"] or {})


def test_build_context_handles_no_carryforward(tmp_path):
    """If pass0 has no prior_version_consulted, carryforward block reflects that."""
    d = tmp_path / "catalog" / "reconstructed" / "fresh_v1"
    d.mkdir(parents=True)
    manifest = json.loads((FIXTURES / "sample_manifest_complete.json").read_text())
    manifest["passes"][0]["prior_version_consulted"] = None
    manifest["passes"][0]["renames_by_source"] = {"iat_wrapper_detection": 2}
    manifest["passes"][0]["proposed_renames"] = [
        p for p in manifest["passes"][0]["proposed_renames"]
        if p["source"] != "pcode_hash_carryforward"
    ]
    (d / "manifest.json").write_text(json.dumps(manifest))
    (d / "coverage.json").write_text(json.dumps({
        "hard_gate_pass": False, "soft_gate_pass": False,
        "totals": {"user_defined_functions": 8, "external_imports_skipped": 3, "thunks_skipped": 1},
        "named": {"total_named": 5, "from_pass0": 2},
        "low_confidence_named_addresses": [],
    }))
    ctx = r.build_context(d)
    cf = ctx["carryforward"]
    assert cf["prior_version_consulted"] is None
    assert cf["renames_ported"] == 0


def test_cli_writes_markdown_for_specific_target(tmp_path):
    """CLI with target arg renders single binary to catalog/pages/reconstructed/."""
    _seed_recon_dir(tmp_path, stem="samplebin", tag="v1_2_3")
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_reconstruct_render.py"),
         "samplebin_v1_2_3"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    out = tmp_path / "catalog" / "pages" / "reconstructed" / "samplebin_v1_2_3.md"
    assert out.is_file()
    text = out.read_text()
    assert "Reconstruction detail — samplebin @ v1_2_3" in text
    assert "RtlAllocateHeap_wrapper" in text
    assert "Carryforward" in text


def test_cli_writes_markdown_for_all_targets_when_no_arg(tmp_path):
    """CLI with no args discovers and renders all binaries."""
    _seed_recon_dir(tmp_path, stem="bin_a", tag="v1")
    _seed_recon_dir(tmp_path, stem="bin_b", tag="v2")
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_reconstruct_render.py")],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    pages = tmp_path / "catalog" / "pages" / "reconstructed"
    assert (pages / "bin_a_v1.md").is_file()
    assert (pages / "bin_b_v2.md").is_file()


def test_cli_refuses_unknown_target(tmp_path):
    """CLI with unknown target returns exit code 2 and error message."""
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_reconstruct_render.py"),
         "does_not_exist_vfoo"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "not found" in (result.stderr + result.stdout).lower()


def test_site_render_emits_reconstruction_html(tmp_path):
    """Drive catalog_site_render.py via subprocess and verify it writes the
    Layer 8 HTML for a seeded reconstruction.
    """
    # Mirror the bare-minimum repo layout that catalog_site_render expects.
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)
    (tmp_path / "catalog" / "products").mkdir(parents=True)
    (tmp_path / "taxonomy" / "binary").mkdir(parents=True)
    # Copy the real defense_library.json + templates so the existing render
    # functions don't crash for lack of inputs.
    shutil.copy(
        REPO_ROOT / "taxonomy" / "binary" / "defense_library.json",
        tmp_path / "taxonomy" / "binary" / "defense_library.json",
    )
    shutil.copytree(REPO_ROOT / "catalog" / "site" / "_templates",
                    tmp_path / "catalog" / "site" / "_templates")

    # Seed a binary YAML that references our reconstruction.
    (tmp_path / "catalog" / "binaries" / "samplebin.yml").write_text(yaml.safe_dump({
        "binary": "samplebin",
        "product": "test",
        "reconstruction": {
            "ref": "catalog/reconstructed/samplebin_v1_2_3",
            "version_tag": "v1_2_3",
            "status": "partial",
        },
    }))
    _seed_recon_dir(tmp_path, stem="samplebin", tag="v1_2_3")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    # Some downstream rendering reads other source data; let it fail
    # gracefully but require that reconstructed/ specifically is emitted.
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_site_render.py")],
        env=env, capture_output=True, text=True,
    )
    # Non-zero exit is acceptable here as long as the reconstructed HTML
    # was produced — the renderer may bail on missing product YAMLs etc.
    html = tmp_path / "catalog" / "site" / "reconstructed" / "samplebin_v1_2_3.html"
    assert html.is_file(), (
        f"reconstructed HTML not emitted. stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    text = html.read_text()
    assert "samplebin" in text
    assert "v1_2_3" in text
    assert "Reconstruction" in text
