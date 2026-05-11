"""Tests for reconstruct_pass0_carryforward — match by pcode_hash, port renames."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass0_carryforward as cf  # type: ignore
import pcode_hash  # type: ignore


def _current_records():
    """Two functions matching the prior manifest's pcode_hashes and one that doesn't."""
    return [
        {"address": "0x140002000", "name": "FUN_140002000", "code_hash": "match_2000",
         "instruction_count": 2, "size": 12, "callers": [], "callees": [],
         "is_external": False, "is_thunk": False, "is_exported": False, "strings": []},
        {"address": "0x140003000", "name": "FUN_140003000", "code_hash": "match_3000",
         "instruction_count": 128, "size": 512, "callers": [], "callees": [],
         "is_external": False, "is_thunk": False, "is_exported": False, "strings": []},
        {"address": "0x140005000", "name": "FUN_140005000", "code_hash": "fresh_5000",
         "instruction_count": 64, "size": 256, "callers": [], "callees": [],
         "is_external": False, "is_thunk": False, "is_exported": False, "strings": []},
    ]


def _prior_manifest():
    return json.loads((FIXTURES / "prior_manifest_carryforward.json").read_text())


def test_no_prior_manifest_returns_empty(tmp_path):
    function_index = {"binary": "sample", "functions": _current_records()}
    proposed = cf.carryforward(function_index, prior_manifest=None)
    assert proposed == []


def test_matches_by_pcode_hash_when_hashes_align(monkeypatch):
    """Force pcode_hash.hash_function_record to return the values the prior
    manifest declares, then verify the carryforward picks them up.
    """
    expected = {
        "0x140002000": "PRIOR_HASH_FOR_2000",
        "0x140003000": "PRIOR_HASH_FOR_3000",
        "0x140005000": "DIFFERENT_HASH_NO_MATCH",
    }
    def fake_hash(rec):
        return expected[rec["address"]]
    monkeypatch.setattr(pcode_hash, "hash_function_record", fake_hash)

    function_index = {"binary": "sample", "functions": _current_records()}
    proposed = cf.carryforward(function_index, prior_manifest=_prior_manifest())

    by_addr = {p["addr"]: p for p in proposed}
    # 0x140002000 and 0x140003000 match; 0x140005000 has no matching prior hash.
    assert set(by_addr) == {"0x140002000", "0x140003000"}
    assert by_addr["0x140002000"]["to"] == "AllocBufferHelper"
    assert by_addr["0x140003000"]["to"] == "DispatchCommand"
    for p in proposed:
        assert p["source"] == "pcode_hash_carryforward"
        assert p["confidence"] == "high"
        assert "vprior" in p["rationale"]


def test_skips_when_prior_function_only_has_FUN_name(monkeypatch):
    """If the prior reconstruction never renamed a function (i.e. its name
    in the prior manifest's proposed_renames is missing), don't propose
    anything for it.
    """
    prior = {
        "binary": {"stem": "sample", "version_tag": "vprior"},
        "passes": [
            {
                "pass": "pass0",
                "proposed_renames": [],
                "tools_used": [],
            }
        ],
        "pcode_hashes_by_addr": {"0x140002000": "PRIOR_HASH_FOR_2000"},
    }
    monkeypatch.setattr(
        pcode_hash, "hash_function_record",
        lambda rec: "PRIOR_HASH_FOR_2000" if rec["address"] == "0x140002000" else "MISS",
    )
    function_index = {"binary": "sample", "functions": _current_records()}
    proposed = cf.carryforward(function_index, prior_manifest=prior)
    assert proposed == []


def test_only_user_defined_functions_considered(monkeypatch):
    """External or thunk functions in the current index must be ignored."""
    monkeypatch.setattr(
        pcode_hash, "hash_function_record",
        lambda rec: "PRIOR_HASH_FOR_2000",
    )
    function_index = {
        "binary": "sample",
        "functions": [
            {"address": "0x140020000", "name": "RtlAllocateHeap", "code_hash": "ext",
             "instruction_count": 0, "size": 0, "callers": [], "callees": [],
             "is_external": True, "is_thunk": False, "is_exported": False, "strings": []},
        ],
    }
    proposed = cf.carryforward(function_index, prior_manifest=_prior_manifest())
    assert proposed == []
