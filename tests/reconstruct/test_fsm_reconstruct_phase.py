"""Tests for the reconstruct phase node in pipeline.yml."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from route_model import _load_yaml  # type: ignore


def test_pipeline_yml_declares_reconstruct_phase():
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    phases = cfg.get("phases", {})
    assert "reconstruct" in phases, "pipeline.yml must declare a 'reconstruct' phase"


def test_reconstruct_phase_sits_between_preparation_and_walk():
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    phases = cfg.get("phases", {})
    prep_next = phases["preparation"].get("next", [])
    assert "reconstruct" in prep_next, "preparation.next must include reconstruct"
    recon_next = phases["reconstruct"].get("next", [])
    assert "walk" in recon_next, "reconstruct.next must include walk"


def test_reconstruct_phase_has_all_four_gates():
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    gates = cfg["phases"]["reconstruct"].get("gates", [])
    gate_ids = {g["id"] for g in gates}
    assert gate_ids == {
        "libghidra_alive",
        "no_concurrent_writer",
        "reachable_named_100pct",
        "tail_named_80pct",
    }


def test_reconstruct_reachability_roots_declared_at_top_level():
    """Reachability roots are a top-level sibling of `phases:`, consumed by Pass 0."""
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    roots = cfg.get("reconstruct_reachability_roots")
    assert roots is not None, "pipeline.yml must declare top-level reconstruct_reachability_roots"
    assert isinstance(roots, dict)
    expected_kinds = {
        "windows_sys", "windows_exe", "windows_dll",
        "linux_elf_exec", "linux_elf_so",
    }
    assert set(roots.keys()) >= expected_kinds, (
        f"missing binary kinds: {expected_kinds - set(roots.keys())}"
    )
    # Each kind must declare a non-empty list of root identifiers.
    for kind, root_list in roots.items():
        assert isinstance(root_list, list) and root_list, f"{kind} must be a non-empty list"


def test_journal_allows_reconstruct_phase():
    import journal  # type: ignore
    assert "reconstruct" in journal.PHASES


import subprocess


def test_fsm_libghidra_alive_gate_returns_evidence(tmp_path):
    """The libghidra_alive gate must run when reconstruct is the current phase.

    For foundation: returns ok=False with evidence string mentioning libghidra.
    A real healthz probe is wired in sub-plan 3.
    """
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text('{"binary": "test", "target_type": "binary"}')
    (eng_dir / "target").mkdir()
    (eng_dir / "decomp").mkdir()
    (eng_dir / "decomp" / "function_index.json").write_text('{"functions": []}')

    # Drive fsm.py state with a custom engagement root via env.
    # The script computes ENG_ROOT from its own location, so we test the
    # gate_status function in-process instead.
    import sys
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    cfg = fsm.load_pipeline()
    phase_def = cfg["phases"]["reconstruct"]
    # Monkeypatch the ENG_ROOT so gate checks point at our fixture.
    orig = fsm.ENG_ROOT
    try:
        fsm.ENG_ROOT = tmp_path / "engagements"
        statuses = fsm.gate_status("fixture", eng_dir, "reconstruct", phase_def)
    finally:
        fsm.ENG_ROOT = orig

    gate_ids = {s["id"] for s in statuses}
    assert "libghidra_alive" in gate_ids
    libg = next(s for s in statuses if s["id"] == "libghidra_alive")
    assert libg["ok"] is False
    assert "libghidra" in libg["evidence"].lower() or "endpoint" in libg["evidence"].lower()


def test_no_concurrent_writer_gate_no_lock_passes(tmp_path, monkeypatch):
    """When no lock file exists, gate passes (nothing to conflict with)."""
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        '{"binary": "test_stem", "target_type": "binary"}'
    )
    (eng_dir / "decomp").mkdir()
    (eng_dir / "decomp" / "function_index.json").write_text('{"functions": []}')

    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(
        "reconstruction:\n  ref: catalog/reconstructed/test_stem_vfoundation\n"
        "  status: not_started\n"
    )
    (catalog / "reconstructed" / "test_stem_vfoundation").mkdir(parents=True)

    import sys
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)

    cfg = fsm.load_pipeline()
    phase_def = cfg["phases"]["reconstruct"]
    statuses = fsm.gate_status("fixture", eng_dir, "reconstruct", phase_def)

    g = next(s for s in statuses if s["id"] == "no_concurrent_writer")
    assert g["ok"] is True
    assert "no lock" in g["evidence"].lower() or "not held" in g["evidence"].lower()


def test_no_concurrent_writer_gate_held_lock_fails(tmp_path, monkeypatch):
    """When .lock exists AND is flock-held by another process, gate fails."""
    import fcntl

    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        '{"binary": "test_stem", "target_type": "binary"}'
    )
    (eng_dir / "decomp").mkdir()
    (eng_dir / "decomp" / "function_index.json").write_text('{"functions": []}')

    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(
        "reconstruction:\n  ref: catalog/reconstructed/test_stem_vfoundation\n"
        "  status: not_started\n"
    )
    recon_dir = catalog / "reconstructed" / "test_stem_vfoundation"
    recon_dir.mkdir(parents=True)
    lock_path = recon_dir / ".lock"
    lock_path.touch()

    # Acquire the lock in the test process; the gate should see it held.
    lf = open(lock_path, "w")
    fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        import sys
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import fsm  # type: ignore
        monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
        monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
        monkeypatch.setattr(fsm, "ROOT", tmp_path)

        cfg = fsm.load_pipeline()
        phase_def = cfg["phases"]["reconstruct"]
        statuses = fsm.gate_status("fixture", eng_dir, "reconstruct", phase_def)
        g = next(s for s in statuses if s["id"] == "no_concurrent_writer")
        assert g["ok"] is False
        assert "held" in g["evidence"].lower() or "locked" in g["evidence"].lower()
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()


def _make_coverage_fixture(tmp_path, monkeypatch, hard: bool, soft: bool):
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        '{"binary": "test_stem", "target_type": "binary"}'
    )
    (eng_dir / "decomp").mkdir()
    (eng_dir / "decomp" / "function_index.json").write_text('{"functions": []}')

    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(
        "reconstruction:\n  ref: catalog/reconstructed/test_stem_vfix\n"
        "  status: complete\n"
    )
    recon_dir = catalog / "reconstructed" / "test_stem_vfix"
    recon_dir.mkdir(parents=True)
    import json as _json
    (recon_dir / "coverage.json").write_text(_json.dumps({
        "hard_gate_pass": hard,
        "soft_gate_pass": soft,
        "reachable": {"function_count": 100, "named": 100 if hard else 90},
        "tail": {"function_count": 1000, "named": 850 if soft else 700},
    }))

    import sys
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)
    return fsm, eng_dir


def test_reachable_named_gate_passes_when_coverage_says_so(tmp_path, monkeypatch):
    fsm, eng_dir = _make_coverage_fixture(tmp_path, monkeypatch, hard=True, soft=True)
    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "fixture", eng_dir, "reconstruct", cfg["phases"]["reconstruct"]
    )
    g = next(s for s in statuses if s["id"] == "reachable_named_100pct")
    assert g["ok"] is True


def test_reachable_named_gate_fails_when_coverage_says_so(tmp_path, monkeypatch):
    fsm, eng_dir = _make_coverage_fixture(tmp_path, monkeypatch, hard=False, soft=True)
    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "fixture", eng_dir, "reconstruct", cfg["phases"]["reconstruct"]
    )
    g = next(s for s in statuses if s["id"] == "reachable_named_100pct")
    assert g["ok"] is False
    assert "90" in g["evidence"] or "100" in g["evidence"]


def test_tail_named_gate_reads_soft_gate_flag(tmp_path, monkeypatch):
    fsm, eng_dir = _make_coverage_fixture(tmp_path, monkeypatch, hard=True, soft=False)
    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status(
        "fixture", eng_dir, "reconstruct", cfg["phases"]["reconstruct"]
    )
    g = next(s for s in statuses if s["id"] == "tail_named_80pct")
    assert g["ok"] is False
