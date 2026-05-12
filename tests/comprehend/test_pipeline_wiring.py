"""Tests for comprehend phase wiring in pipeline.yml + fsm.py + journal.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def test_pipeline_declares_comprehend_phase():
    from route_model import _load_yaml  # type: ignore
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    phases = cfg.get("phases", {})
    assert "comprehend" in phases
    # Sits between reconstruct and walk
    assert "comprehend" in phases["reconstruct"].get("next", [])
    assert "walk" in phases["comprehend"].get("next", [])


def test_pipeline_comprehend_has_three_gates():
    from route_model import _load_yaml  # type: ignore
    cfg = _load_yaml(REPO_ROOT / "pipeline.yml")
    gate_ids = {g["id"] for g in cfg["phases"]["comprehend"].get("gates", [])}
    assert gate_ids >= {
        "primary_binary_reconstructed",
        "narrative_present",
        "binary_summaries_present",
    }


def test_journal_allows_comprehend_phase():
    import journal  # type: ignore
    assert "comprehend" in journal.PHASES


def test_fsm_primary_binary_reconstructed_gate_passes_when_status_partial(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(json.dumps({"binary": "test_stem"}))
    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(yaml.safe_dump({
        "binary": "test_stem",
        "reconstruction": {"status": "partial"},
    }))

    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)

    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status("fixture", eng_dir, "comprehend", cfg["phases"]["comprehend"])
    g = next(s for s in statuses if s["id"] == "primary_binary_reconstructed")
    assert g["ok"] is True


def test_fsm_primary_binary_reconstructed_gate_fails_when_status_not_started(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(json.dumps({"binary": "test_stem"}))
    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(yaml.safe_dump({
        "binary": "test_stem",
        "reconstruction": {"status": "not_started"},
    }))

    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)

    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status("fixture", eng_dir, "comprehend", cfg["phases"]["comprehend"])
    g = next(s for s in statuses if s["id"] == "primary_binary_reconstructed")
    assert g["ok"] is False


def test_fsm_narrative_present_gate_passes_when_product_has_narrative(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(json.dumps({"binary": "test_stem"}))
    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "products").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(yaml.safe_dump({
        "binary": "test_stem", "product": "test-product",
        "reconstruction": {"status": "partial"},
    }))
    (catalog / "products" / "test-product.yml").write_text(yaml.safe_dump({
        "product": "test-product",
        "architecture_narrative": {
            "summary": "It's a product.",
            "fingerprint": "x",
        },
    }))

    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)

    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status("fixture", eng_dir, "comprehend", cfg["phases"]["comprehend"])
    g = next(s for s in statuses if s["id"] == "narrative_present")
    assert g["ok"] is True


def test_fsm_binary_summaries_present_gate_passes_when_summary_present(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "fixture"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(json.dumps({"binary": "test_stem"}))
    catalog = tmp_path / "catalog"
    (catalog / "binaries").mkdir(parents=True)
    (catalog / "binaries" / "test_stem.yml").write_text(yaml.safe_dump({
        "binary": "test_stem",
        "summary": "ELI5 sentence.",
        "full_picture": {"loaded_by": []},
        "reconstruction": {"status": "partial"},
    }))

    import fsm  # type: ignore
    monkeypatch.setattr(fsm, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(fsm, "CATALOG_BINARIES", catalog / "binaries")
    monkeypatch.setattr(fsm, "ROOT", tmp_path)

    cfg = fsm.load_pipeline()
    statuses = fsm.gate_status("fixture", eng_dir, "comprehend", cfg["phases"]["comprehend"])
    g = next(s for s in statuses if s["id"] == "binary_summaries_present")
    assert g["ok"] is True
