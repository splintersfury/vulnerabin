"""Tests for reconstruct_pass0_discovery — extract project_discovery from function_index."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass0_discovery as discovery  # type: ignore


@pytest.fixture()
def sample_index() -> dict:
    return json.loads((FIXTURES / "sample_function_index.json").read_text())


def test_extracts_binary_metadata(sample_index):
    d = discovery.extract(sample_index)
    assert d["binary"] == "sample.exe"
    assert d["arch"] == "x86_64"
    assert d["format"] == "PE"
    assert d["address_size"] == 64


def test_extracts_exports_excluding_externals_and_thunks(sample_index):
    d = discovery.extract(sample_index)
    exports = d["exports"]
    # entry, DllMain, Ordinal_42 are exported user-defined.
    # RtlAllocateHeap is external — must not appear.
    # j_CreateFileW is a thunk — must not appear.
    assert {"entry", "DllMain", "Ordinal_42"} == {e["name"] for e in exports}
    for e in exports:
        assert "address" in e
        assert e["address"].startswith("0x")


def test_identifies_entrypoint_when_name_is_entry(sample_index):
    d = discovery.extract(sample_index)
    assert d["entrypoints"] == ["0x140001000"]


def test_function_counts_distinguish_user_defined_vs_external_vs_thunk(sample_index):
    d = discovery.extract(sample_index)
    c = d["function_counts"]
    # 12 total in fixture: 8 user-defined non-thunk, 3 external, 1 thunk.
    # entry, DllMain, Ordinal_42, FUN_140002000, FUN_140003000, FUN_140004000, FUN_140005000, FUN_140040000 = 8 user-defined
    assert c["total"] == 12
    assert c["user_defined"] == 8
    assert c["external"] == 3
    assert c["thunk"] == 1


def test_reachability_walk_includes_transitive_callees(sample_index):
    d = discovery.extract(sample_index)
    reachable = set(d["reachable_user_defined"])
    # From entry (0x140001000): direct callees 0x140002000, 0x140003000.
    # 0x140003000 calls 0x140004000, 0x140005000.
    # External callees (RtlAllocateHeap, CreateFileW, memcpy) excluded.
    # FUN_140040000 is an orphan — must NOT be reachable.
    assert "0x140001000" in reachable        # entry itself
    assert "0x140002000" in reachable
    assert "0x140003000" in reachable
    assert "0x140004000" in reachable
    assert "0x140005000" in reachable
    assert "0x140006000" in reachable        # DllMain is its own root
    assert "0x140007000" in reachable        # Ordinal_42 is its own root
    assert "0x140040000" not in reachable    # orphan
    assert "0x140020000" not in reachable    # external (RtlAllocateHeap)


def test_strings_aggregated_by_function(sample_index):
    d = discovery.extract(sample_index)
    s = d["strings_by_function"]
    assert s.get("0x140040000") == [
        "Initializing config",
        "C:\\ProgramData\\sample\\config.json",
    ]
    # Functions with no strings should not appear as empty entries.
    assert "0x140001000" not in s


def test_handles_missing_optional_fields_gracefully():
    minimal = {
        "binary": "tiny.exe",
        "functions": [
            {
                "address": "0x100",
                "name": "main",
                "callers": [],
                "callees": [],
                "is_external": False,
                "is_thunk": False,
                "is_exported": True,
                "code_hash": "0",
                "instruction_count": 1,
                "size": 4,
                "strings": [],
            }
        ],
    }
    d = discovery.extract(minimal)
    assert d["binary"] == "tiny.exe"
    assert d["arch"] is None
    assert d["function_counts"]["user_defined"] == 1
