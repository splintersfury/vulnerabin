"""Tests for reconstruct_pass0_iat — detect single-call IAT wrappers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass0_iat as iat  # type: ignore


@pytest.fixture()
def sample_index() -> dict:
    return json.loads((FIXTURES / "sample_function_index.json").read_text())


def test_detects_two_instruction_wrapper(sample_index):
    """FUN_140002000 in the fixture has 2 instructions and one external callee
    (RtlAllocateHeap). It must be proposed as `RtlAllocateHeap_wrapper`.
    """
    proposed = iat.detect_wrappers(sample_index)
    by_addr = {p["addr"]: p for p in proposed}
    assert "0x140002000" in by_addr
    p = by_addr["0x140002000"]
    assert p["to"] == "RtlAllocateHeap_wrapper"
    assert p["from"] == "FUN_140002000"
    assert p["confidence"] == "medium"
    assert p["source"] == "iat_wrapper_detection"
    assert "RtlAllocateHeap" in p["rationale"]


def test_detects_one_instruction_wrapper(sample_index):
    """FUN_140004000 has 1 instruction and one external callee (CreateFileW)."""
    proposed = iat.detect_wrappers(sample_index)
    by_addr = {p["addr"]: p for p in proposed}
    assert "0x140004000" in by_addr
    assert by_addr["0x140004000"]["to"] == "CreateFileW_wrapper"


def test_skips_large_functions_even_with_external_callee(sample_index):
    """FUN_140005000 has 64 instructions and 3 callees including externals.
    Threshold for wrapper = <=2 instructions. Must NOT be proposed.
    """
    proposed = iat.detect_wrappers(sample_index)
    by_addr = {p["addr"]: p for p in proposed}
    assert "0x140005000" not in by_addr


def test_skips_functions_with_no_callees(sample_index):
    """FUN_140040000 has 0 callees — not a wrapper."""
    proposed = iat.detect_wrappers(sample_index)
    by_addr = {p["addr"]: p for p in proposed}
    assert "0x140040000" not in by_addr


def test_skips_already_named_functions(sample_index):
    """`entry`, `DllMain`, `Ordinal_42` are not `FUN_*` — must be skipped."""
    proposed = iat.detect_wrappers(sample_index)
    for p in proposed:
        assert p["from"].startswith("FUN_"), f"shouldn't rename non-FUN_ name: {p}"


def test_skips_thunks_and_externals(sample_index):
    """j_CreateFileW is is_thunk=True; RtlAllocateHeap is is_external=True.
    Both must be skipped.
    """
    proposed = iat.detect_wrappers(sample_index)
    addrs = {p["addr"] for p in proposed}
    assert "0x140030000" not in addrs  # j_CreateFileW (thunk)
    assert "0x140020000" not in addrs  # RtlAllocateHeap (external)


def test_skips_functions_with_multiple_external_callees():
    """If a small function calls 2+ externals, we can't name it after one of them."""
    fi = {
        "binary": "tiny.exe",
        "functions": [
            {
                "address": "0x100",
                "name": "FUN_100",
                "callers": [],
                "callees": ["0x200", "0x300"],
                "is_external": False,
                "is_thunk": False,
                "is_exported": False,
                "code_hash": "x",
                "instruction_count": 2,
                "size": 8,
                "strings": [],
            },
            {
                "address": "0x200",
                "name": "ExternA",
                "callers": ["0x100"],
                "callees": [],
                "is_external": True,
                "is_thunk": False,
                "is_exported": False,
                "code_hash": "0",
                "instruction_count": 0,
                "size": 0,
                "strings": [],
            },
            {
                "address": "0x300",
                "name": "ExternB",
                "callers": ["0x100"],
                "callees": [],
                "is_external": True,
                "is_thunk": False,
                "is_exported": False,
                "code_hash": "0",
                "instruction_count": 0,
                "size": 0,
                "strings": [],
            },
        ],
    }
    proposed = iat.detect_wrappers(fi)
    assert proposed == []
