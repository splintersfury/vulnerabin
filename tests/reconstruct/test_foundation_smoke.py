"""End-to-end smoke test for the reconstruct phase foundation.

Drives: vb-add reconstruction -> binary YAML + catalog dir scaffold ->
fsm.py state reports gate evidence for libghidra_alive, no_concurrent_writer,
reachable_named_100pct (fails since coverage.json absent), tail_named_80pct
(fails since coverage.json absent).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_foundation_end_to_end(tmp_path, monkeypatch):
    # 1. Set up a fake repo layout under tmp_path.
    (tmp_path / "scripts").mkdir()
    (tmp_path / "engagements").mkdir()
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)

    # Copy the real pipeline.yml so fsm.py reads the right phase definitions.
    (tmp_path / "pipeline.yml").write_text((REPO_ROOT / "pipeline.yml").read_text())

    # Seed a binary YAML.
    stem = "smoke_target"
    (tmp_path / "catalog" / "binaries" / f"{stem}.yml").write_text(yaml.safe_dump({
        "binary": stem,
        "product": "smoke",
    }))

    # Seed an engagement with the bare minimum to satisfy preparation outputs.
    eng = tmp_path / "engagements" / "smoke-2026-05-11"
    eng.mkdir()
    (eng / "scope.json").write_text(json.dumps({
        "binary": stem,
        "target_type": "binary",
    }))
    (eng / "decomp").mkdir()
    (eng / "decomp" / "function_index.json").write_text('{"functions": []}')

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}

    # 2. Run vb-add reconstruction.
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "catalog_add.py"),
         "reconstruction", "--binary", stem, "--version", "vsmoke"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    # Catalog dir + YAML block populated.
    recon_dir = tmp_path / "catalog" / "reconstructed" / f"{stem}_vsmoke"
    assert recon_dir.is_dir()
    assert (recon_dir / "manifest.json").is_file()
    assert (recon_dir / ".lock").is_file()

    yml = yaml.safe_load((tmp_path / "catalog" / "binaries" / f"{stem}.yml").read_text())
    assert yml["reconstruction"]["status"] == "not_started"

    # 3. Run fsm.gate_status (in-process) to confirm gate evidence for all 4 gates.
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore

    # Monkeypatch all module-level path constants so gate checks use our
    # fixture layout, not the real repo tree.  Also patch PIPELINE so that
    # fsm.load_pipeline() reads our tmp_path copy (module-level PIPELINE is
    # set once at import time, so we must override it explicitly here).
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", tmp_path / "catalog" / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)
    monkeypatch.setattr(fsm, "PIPELINE", tmp_path / "pipeline.yml")

    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "smoke-2026-05-11", eng, "reconstruct", cfg["phases"]["reconstruct"]
    )
    gate_ids = {s["id"] for s in statuses}
    assert gate_ids == {
        "libghidra_alive",
        "no_concurrent_writer",
        "reachable_named_100pct",
        "tail_named_80pct",
    }

    # libghidra_alive must be False (no endpoint configured) but with evidence.
    libg = next(s for s in statuses if s["id"] == "libghidra_alive")
    assert libg["ok"] is False
    assert "libghidra" in libg["evidence"].lower() or "endpoint" in libg["evidence"].lower()

    # no_concurrent_writer: lock file exists but is unheld; should pass.
    ncw = next(s for s in statuses if s["id"] == "no_concurrent_writer")
    assert ncw["ok"] is True

    # post-gates fail because coverage.json is not yet produced.
    hard = next(s for s in statuses if s["id"] == "reachable_named_100pct")
    assert hard["ok"] is False
    assert "coverage.json missing" in hard["evidence"]

    tail = next(s for s in statuses if s["id"] == "tail_named_80pct")
    assert tail["ok"] is False
    assert "coverage.json missing" in tail["evidence"]
