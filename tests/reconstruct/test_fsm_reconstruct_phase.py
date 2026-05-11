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
