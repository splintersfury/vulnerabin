"""Tests for the pcode_hash stub library."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import pcode_hash  # type: ignore


def test_hash_function_record_is_deterministic():
    rec = {
        "address": "0x140012a0",
        "code_hash": "abcdef0123",
        "instruction_count": 42,
        "size": 256,
    }
    h1 = pcode_hash.hash_function_record(rec)
    h2 = pcode_hash.hash_function_record(rec)
    assert h1 == h2
    assert isinstance(h1, str)
    assert len(h1) == 64  # SHA-256 hex


def test_hash_function_record_changes_with_inputs():
    a = {"address": "0x140012a0", "code_hash": "abcd", "instruction_count": 42, "size": 256}
    b = dict(a, code_hash="ef01")
    assert pcode_hash.hash_function_record(a) != pcode_hash.hash_function_record(b)


def test_hash_function_record_ignores_irrelevant_fields():
    """Fields like callers/callees (which depend on neighbor naming) MUST NOT
    affect the structural hash — otherwise carryforward breaks across versions.
    """
    a = {"address": "0x140012a0", "code_hash": "abcd", "instruction_count": 42, "size": 256, "callers": ["FUN_a"]}
    b = dict(a, callers=["FUN_b"])
    assert pcode_hash.hash_function_record(a) == pcode_hash.hash_function_record(b)


def test_aggregate_hash_is_order_independent():
    records = [
        {"address": "0x100", "code_hash": "aaaa", "instruction_count": 5, "size": 20},
        {"address": "0x200", "code_hash": "bbbb", "instruction_count": 10, "size": 40},
    ]
    h1 = pcode_hash.aggregate_hash(records)
    h2 = pcode_hash.aggregate_hash(list(reversed(records)))
    assert h1 == h2
