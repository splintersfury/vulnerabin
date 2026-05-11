"""Tests for reconstruct_gates — hard/soft gate computation."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_gates as gates  # type: ignore


def _function_index(named_addrs: list[str], unnamed_addrs: list[str]) -> dict:
    fns = []
    for a in named_addrs:
        fns.append({"address": a, "name": f"SemanticName_{a[2:]}",
                    "is_external": False, "is_thunk": False,
                    "is_exported": False,
                    "callers": [], "callees": [], "code_hash": "h",
                    "instruction_count": 10, "size": 32, "strings": []})
    for a in unnamed_addrs:
        fns.append({"address": a, "name": f"FUN_{a[2:]}",
                    "is_external": False, "is_thunk": False,
                    "is_exported": False,
                    "callers": [], "callees": [], "code_hash": "h",
                    "instruction_count": 10, "size": 32, "strings": []})
    return {"binary": "test", "functions": fns}


def _manifest(reachable: list[str], renames: list[dict] | None = None) -> dict:
    return {
        "binary": {"stem": "t", "version_tag": "v1", "status": "partial"},
        "project_discovery": {"reachable_user_defined": list(reachable)},
        "passes": [{
            "pass": "pass0",
            "proposed_renames": renames or [],
        }],
    }


def test_hard_gate_passes_when_all_reachable_named():
    reachable = ["0x100", "0x101", "0x102"]
    tail_named = [f"0x{i:03x}" for i in range(0x200, 0x207)]
    tail_unnamed = [f"0x{i:03x}" for i in range(0x300, 0x303)]
    fi = _function_index(reachable + tail_named, tail_unnamed)
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True
    assert state["soft_gate_pass"] is False
    assert state["named"]["reachable"] == 3
    assert state["reachable_total"] == 3
    assert state["tail_total"] == 10
    assert state["named"]["tail"] == 7


def test_hard_gate_fails_when_reachable_function_unnamed():
    reachable = ["0x100", "0x101", "0x102"]
    fi = _function_index(["0x100", "0x101"], ["0x102"])
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is False
    assert state["named"]["reachable"] == 2


def test_hard_gate_uses_rename_when_function_name_is_FUN_():
    reachable = ["0x100", "0x101"]
    fi = _function_index(["0x101"], ["0x100"])
    manifest = _manifest(reachable, renames=[
        {"addr": "0x100", "to": "Renamed", "confidence": "high",
         "source": "llm_rename"}
    ])
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True


def test_low_confidence_pass0_rename_does_not_count():
    reachable = ["0x100"]
    fi = _function_index([], ["0x100"])
    manifest = _manifest(reachable, renames=[
        {"addr": "0x100", "to": "try_open_file", "confidence": "low",
         "source": "string_xref"}
    ])
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is False


def test_low_confidence_llm_rename_does_count():
    reachable = ["0x100"]
    fi = _function_index([], ["0x100"])
    manifest = _manifest(reachable, renames=[
        {"addr": "0x100", "to": "Unsure", "confidence": "low",
         "source": "llm_rename"}
    ])
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True


def test_soft_gate_passes_when_tail_above_80pct():
    reachable = ["0x100"]
    tail_named = [f"0x{i:03x}" for i in range(0x200, 0x208)]
    tail_unnamed = [f"0x{i:03x}" for i in range(0x300, 0x302)]
    fi = _function_index(reachable + tail_named, tail_unnamed)
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["soft_gate_pass"] is True


def test_soft_gate_passes_when_tail_is_empty():
    reachable = ["0x100", "0x101"]
    fi = _function_index(reachable, [])
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["soft_gate_pass"] is True
    assert state["tail_total"] == 0


def test_hard_gate_passes_when_reachable_set_empty():
    fi = _function_index([], ["0x100", "0x101"])
    manifest = _manifest([])
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True


def test_named_breakdown_includes_pass0_pass1_pass2_origins():
    reachable = ["0x100", "0x101", "0x102", "0x103"]
    fi = _function_index([], ["0x100", "0x101", "0x102", "0x103"])
    manifest = {
        "binary": {"stem": "t", "version_tag": "v1", "status": "partial"},
        "project_discovery": {"reachable_user_defined": reachable},
        "passes": [
            {"pass": "pass0", "proposed_renames": [
                {"addr": "0x100", "to": "P0name", "confidence": "high",
                 "source": "iat_wrapper_detection"},
            ]},
            {"pass": "pass1", "proposed_renames": [
                {"addr": "0x101", "to": "P1name", "confidence": "high",
                 "source": "llm_rename"},
                {"addr": "0x102", "to": "P1name2", "confidence": "medium",
                 "source": "llm_rename"},
            ]},
            {"pass": "pass2", "retypes": [
                {"addr": "0x103",
                 "params": [{"index": 0, "to": "DWORD",
                             "confidence": "high", "rationale": "..."}],
                 "locals": []},
            ]},
        ],
    }
    state = gates.compute_gate_state(fi, manifest)
    breakdown = state["named"]
    assert breakdown["from_pass0"] == 1
    assert breakdown["from_pass1"] == 2
    # Pass 2 contributes types not names, so it does NOT increment named-count.
    # 0x103 has no rename anywhere, so hard gate must fail.
    assert state["hard_gate_pass"] is False
    assert breakdown["reachable"] == 3


def test_compute_gate_state_handles_missing_project_discovery():
    fi = _function_index([], [])
    manifest = {"binary": {"stem": "t"}, "passes": []}
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True
    assert state["reachable_total"] == 0


def test_status_recommendation_complete_when_both_gates_pass():
    reachable = ["0x100"]
    fi = _function_index(reachable, [])
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["recommended_status"] == "complete"


def test_status_recommendation_partial_when_only_hard_passes():
    reachable = ["0x100"]
    tail_named = [f"0x{i:03x}" for i in range(0x200, 0x205)]
    tail_unnamed = [f"0x{i:03x}" for i in range(0x300, 0x305)]
    fi = _function_index(reachable + tail_named, tail_unnamed)
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is True
    assert state["soft_gate_pass"] is False
    assert state["recommended_status"] == "partial"


def test_status_recommendation_partial_when_hard_fails():
    reachable = ["0x100"]
    fi = _function_index([], ["0x100"])
    manifest = _manifest(reachable)
    state = gates.compute_gate_state(fi, manifest)
    assert state["hard_gate_pass"] is False
    assert state["recommended_status"] == "partial"
