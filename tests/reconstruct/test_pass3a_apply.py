"""Tests for reconstruct_pass3a_apply — worker result validation + merge."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass3a_apply as apply_mod  # type: ignore


def test_validate_accepts_well_formed_result():
    result = json.loads((FIXTURES / "sample_pass3a_result_valid.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    assert errors == []


def test_validate_rejects_missing_pass_field():
    result = {"batch_id": "x", "structs": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass" in e.lower() for e in errors)


def test_validate_rejects_wrong_pass_value():
    result = {"pass": "pass2", "batch_id": "x", "structs": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass3a" in e.lower() for e in errors)


def test_validate_rejects_structs_not_a_list():
    result = {"pass": "pass3a", "batch_id": "x", "structs": "x"}
    errors = apply_mod.validate_worker_result(result)
    assert any("structs" in e.lower() for e in errors)


def test_validate_rejects_empty_struct_name():
    result = {
        "pass": "pass3a", "batch_id": "x",
        "structs": [{
            "name": "",
            "supporting_functions": ["0x1"],
            "fields": [{"offset": 0, "type": "uint32_t", "name": "x", "rationale": "r"}],
            "confidence": "high",
            "rationale": "r",
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("name" in e.lower() for e in errors)


def test_validate_rejects_unknown_confidence():
    result = {
        "pass": "pass3a", "batch_id": "x",
        "structs": [{
            "name": "OK", "supporting_functions": ["0x1"],
            "fields": [{"offset": 0, "type": "uint32_t", "name": "x", "rationale": "r"}],
            "confidence": "ultra",
            "rationale": "r",
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("confidence" in e.lower() for e in errors)


def test_validate_rejects_field_with_non_int_offset():
    result = {
        "pass": "pass3a", "batch_id": "x",
        "structs": [{
            "name": "OK", "supporting_functions": ["0x1"],
            "fields": [{"offset": "x", "type": "uint32_t", "name": "x", "rationale": "r"}],
            "confidence": "high",
            "rationale": "r",
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("offset" in e.lower() for e in errors)


def test_validate_rejects_field_missing_offset():
    result = {
        "pass": "pass3a", "batch_id": "x",
        "structs": [{
            "name": "OK", "supporting_functions": ["0x1"],
            "fields": [{"type": "uint32_t", "name": "x", "rationale": "r"}],
            "confidence": "high",
            "rationale": "r",
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("offset" in e.lower() for e in errors)


def test_validate_rejects_malformed_fixture():
    result = json.loads((FIXTURES / "sample_pass3a_result_malformed.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    joined = " ".join(errors).lower()
    assert "name" in joined
    assert "offset" in joined
    assert "confidence" in joined
