"""End-to-end tests for the reconstruct.py orchestrator (Pass 0 only)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RECONSTRUCT = REPO_ROOT / "scripts" / "reconstruct.py"
CATALOG_ADD = REPO_ROOT / "scripts" / "catalog_add.py"
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"


def _seed_repo(tmp_path: Path, stem: str = "sample", version_tag: str = "vmvp") -> dict:
    """Set up engagement + catalog + scope.json + function_index.json."""
    (tmp_path / "catalog" / "binaries").mkdir(parents=True)
    (tmp_path / "engagements").mkdir()

    eng = tmp_path / "engagements" / "test-eng"
    eng.mkdir()
    (eng / "scope.json").write_text(json.dumps({
        "binary": stem, "target_type": "binary",
    }))
    (eng / "decomp").mkdir()
    shutil.copy(
        FIXTURES / "sample_function_index.json",
        eng / "decomp" / "function_index.json",
    )

    (tmp_path / "catalog" / "binaries" / f"{stem}.yml").write_text(yaml.safe_dump({
        "binary": stem,
        "product": "test-product",
    }))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    # Scaffold via vb-add reconstruction (already shipped in foundation).
    r = subprocess.run(
        [sys.executable, str(CATALOG_ADD), "reconstruction",
         "--binary", stem, "--version", version_tag],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr

    return {
        "tmp_path": tmp_path,
        "stem": stem,
        "version_tag": version_tag,
        "engagement": "test-eng",
        "env": env,
        "recon_dir": tmp_path / "catalog" / "reconstructed" / f"{stem}_{version_tag}",
    }


def test_orchestrator_runs_end_to_end(tmp_path):
    seed = _seed_repo(tmp_path)
    result = subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_orchestrator_writes_manifest_with_pass0_entry(tmp_path):
    seed = _seed_repo(tmp_path)
    subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], check=True, capture_output=True, text=True,
    )
    manifest = json.loads((seed["recon_dir"] / "manifest.json").read_text())
    assert manifest["passes"], "manifest should have at least one pass entry"
    p0 = next(p for p in manifest["passes"] if p["pass"] == "pass0")
    assert "started_at" in p0
    assert "ended_at" in p0
    assert "iat_wrapper_detection" in p0["tools_used"]
    # IAT detector finds 0x140002000 and 0x140004000 (both 1-2 instructions
    # with single external callee).
    addrs = {r["addr"] for r in p0["proposed_renames"]}
    assert addrs == {"0x140002000", "0x140004000"}


def test_orchestrator_writes_coverage_json(tmp_path):
    seed = _seed_repo(tmp_path)
    subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], check=True, capture_output=True, text=True,
    )
    cov = json.loads((seed["recon_dir"] / "coverage.json").read_text())
    # In the fixture: 8 user-defined functions, 2 proposed renames from IAT.
    # Hard gate (reachable_named_100pct) is False since no LLM passes yet.
    # Soft gate also False — but the orchestrator must still populate the keys.
    assert cov["totals"]["user_defined_functions"] == 8
    assert cov["hard_gate_pass"] is False
    assert cov["soft_gate_pass"] is False


def test_orchestrator_updates_binary_yaml_status(tmp_path):
    seed = _seed_repo(tmp_path)
    subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], check=True, capture_output=True, text=True,
    )
    yml = yaml.safe_load(
        (tmp_path / "catalog" / "binaries" / f"{seed['stem']}.yml").read_text()
    )
    # After Pass 0 only, status is `partial` (hard gate not satisfied).
    assert yml["reconstruction"]["status"] == "partial"


def test_orchestrator_refuses_when_lock_held(tmp_path):
    import fcntl
    seed = _seed_repo(tmp_path)
    lock_path = seed["recon_dir"] / ".lock"
    lf = open(lock_path, "w")
    fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        result = subprocess.run(
            [sys.executable, str(RECONSTRUCT),
             "--engagement", seed["engagement"],
             "--binary", seed["stem"],
             "--version", seed["version_tag"]],
            env=seed["env"], capture_output=True, text=True,
        )
        assert result.returncode != 0
        out = result.stdout + result.stderr
        assert "lock" in out.lower()
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()


def test_orchestrator_carries_forward_from_prior_version(tmp_path, monkeypatch):
    """If a prior reconstruction dir exists, the orchestrator loads its
    manifest as the carryforward source. We seed one manually.
    """
    seed = _seed_repo(tmp_path, version_tag="vcurrent")
    # Seed a prior version directory under the same stem.
    prior_dir = tmp_path / "catalog" / "reconstructed" / f"{seed['stem']}_vprior"
    prior_dir.mkdir(parents=True)
    shutil.copy(
        FIXTURES / "prior_manifest_carryforward.json",
        prior_dir / "manifest.json",
    )

    result = subprocess.run(
        [sys.executable, str(RECONSTRUCT),
         "--engagement", seed["engagement"],
         "--binary", seed["stem"],
         "--version", seed["version_tag"]],
        env=seed["env"], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    manifest = json.loads((seed["recon_dir"] / "manifest.json").read_text())
    p0 = next(p for p in manifest["passes"] if p["pass"] == "pass0")
    # Without monkeypatching pcode_hash, no carryforward matches will fire,
    # but the orchestrator should still record that the prior version was
    # consulted in pass0 metadata.
    assert p0.get("prior_version_consulted") == f"{seed['stem']}_vprior"
