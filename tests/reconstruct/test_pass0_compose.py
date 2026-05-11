"""Tests for reconstruct_pass0 — the composed Pass 0 entry."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass0 as pass0  # type: ignore


@pytest.fixture()
def sample_index() -> dict:
    return json.loads((FIXTURES / "sample_function_index.json").read_text())


def test_pass0_result_shape(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    assert set(res.keys()) >= {
        "pass",
        "tools_used",
        "project_discovery",
        "proposed_renames",
        "renames_by_source",
    }
    assert res["pass"] == "pass0"


def test_pass0_includes_iat_wrappers(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    sources = {p["source"] for p in res["proposed_renames"]}
    assert "iat_wrapper_detection" in sources


def test_pass0_skips_carryforward_when_prior_absent(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    sources = {p["source"] for p in res["proposed_renames"]}
    assert "pcode_hash_carryforward" not in sources


def test_pass0_uses_carryforward_when_prior_present(sample_index, monkeypatch):
    import pcode_hash  # type: ignore
    # Force a hash match on 0x140002000 against the prior manifest fixture.
    expected = {r["address"]: "PRIOR_HASH_FOR_2000" if r["address"] == "0x140002000" else "miss"
                for r in sample_index["functions"] if not r.get("is_external") and not r.get("is_thunk")}
    monkeypatch.setattr(
        pcode_hash, "hash_function_record",
        lambda rec: expected.get(rec["address"], "miss"),
    )
    prior = json.loads((FIXTURES / "prior_manifest_carryforward.json").read_text())
    res = pass0.run(sample_index, prior_manifest=prior)
    cf_renames = [p for p in res["proposed_renames"] if p["source"] == "pcode_hash_carryforward"]
    assert any(p["to"] == "AllocBufferHelper" for p in cf_renames)


def test_pass0_no_duplicate_renames_for_same_addr(sample_index, monkeypatch):
    """If both IAT detector and carryforward propose for the same addr,
    carryforward wins (higher confidence: high vs medium).
    """
    import pcode_hash  # type: ignore
    monkeypatch.setattr(
        pcode_hash, "hash_function_record",
        lambda rec: "PRIOR_HASH_FOR_2000" if rec["address"] == "0x140002000" else "miss",
    )
    prior = json.loads((FIXTURES / "prior_manifest_carryforward.json").read_text())
    res = pass0.run(sample_index, prior_manifest=prior)
    addrs = [p["addr"] for p in res["proposed_renames"]]
    assert len(addrs) == len(set(addrs)), "duplicate addr in proposed_renames"
    # And the surviving rename for 0x140002000 must be the carryforward one (high).
    p = next(r for r in res["proposed_renames"] if r["addr"] == "0x140002000")
    assert p["source"] == "pcode_hash_carryforward"
    assert p["confidence"] == "high"


def test_renames_by_source_counts_align(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    rbs = res["renames_by_source"]
    assert rbs["iat_wrapper_detection"] == sum(
        1 for p in res["proposed_renames"] if p["source"] == "iat_wrapper_detection"
    )


def test_tools_used_reflects_active_detectors(sample_index):
    res = pass0.run(sample_index, prior_manifest=None)
    assert "iat_wrapper_detection" in res["tools_used"]
    assert "pcode_hash_carryforward" not in res["tools_used"]
