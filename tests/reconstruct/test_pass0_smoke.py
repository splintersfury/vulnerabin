"""Smoke test: after Pass 0 runs end-to-end, fsm gate reads reflect new state."""
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
RECONSTRUCT = REPO_ROOT / "scripts" / "reconstruct.py"
CATALOG_ADD = REPO_ROOT / "scripts" / "catalog_add.py"
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"


def test_pass0_smoke_flips_post_gates(tmp_path, monkeypatch):
    """After Pass 0 runs, coverage.json exists with hard_gate_pass=False and
    soft_gate_pass=False. The fsm post-gates must read those values and
    report ok=False with non-coverage-missing evidence.
    """
    # Set up the layout the orchestrator + fsm both expect.
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)
    (tmp_path / "engagements" / "smoke").mkdir(parents=True)
    (tmp_path / "engagements" / "smoke" / "scope.json").write_text(json.dumps({
        "binary": "smoke", "target_type": "binary",
    }))
    (tmp_path / "engagements" / "smoke" / "decomp").mkdir()
    shutil.copy(
        FIXTURES / "sample_function_index.json",
        tmp_path / "engagements" / "smoke" / "decomp" / "function_index.json",
    )
    (tmp_path / "catalog" / "binaries" / "smoke.yml").write_text(yaml.safe_dump({
        "binary": "smoke",
    }))
    (tmp_path / "pipeline.yml").write_text((REPO_ROOT / "pipeline.yml").read_text())

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}

    # Scaffold + run pass 0.
    subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", "smoke", "--version", "vsmoke"],
        env=env, check=True, capture_output=True, text=True,
    )
    r = subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", "smoke", "--binary", "smoke", "--version", "vsmoke"],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr

    # coverage.json must exist now.
    cov_path = tmp_path / "catalog" / "reconstructed" / "smoke_vsmoke" / "coverage.json"
    assert cov_path.is_file()
    cov = json.loads(cov_path.read_text())
    assert cov["hard_gate_pass"] is False
    assert cov["soft_gate_pass"] is False

    # Now run fsm gate_status and verify the gates read coverage.json
    # (not "coverage.json missing").
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", tmp_path / "catalog" / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)
    monkeypatch.setattr(fsm, "PIPELINE", tmp_path / "pipeline.yml")

    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "smoke",
        tmp_path / "engagements" / "smoke",
        "reconstruct",
        cfg["phases"]["reconstruct"],
    )
    hard = next(s for s in statuses if s["id"] == "reachable_named_100pct")
    soft = next(s for s in statuses if s["id"] == "tail_named_80pct")
    assert hard["ok"] is False
    assert "coverage.json missing" not in hard["evidence"]  # coverage now present
    assert soft["ok"] is False
    assert "coverage.json missing" not in soft["evidence"]


def test_full_reconstruct_suite_still_passes():
    """Sanity: every prior test in tests/reconstruct/ continues to pass."""
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/reconstruct/", "-q",
         "--ignore=tests/reconstruct/test_pass0_smoke.py"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    # If this fails, the failures are in stdout/stderr.
    assert r.returncode == 0, r.stdout + r.stderr
