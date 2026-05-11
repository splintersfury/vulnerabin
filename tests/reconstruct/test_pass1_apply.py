"""Tests for reconstruct_pass1_apply — worker result validation + manifest merge."""
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

import reconstruct_pass1_apply as apply_mod  # type: ignore


def test_validate_accepts_well_formed_result():
    result = json.loads((FIXTURES / "sample_worker_result_valid.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    assert errors == []


def test_validate_rejects_missing_pass_field():
    result = {"batch_id": "x", "renames": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass" in e.lower() for e in errors)


def test_validate_rejects_wrong_pass_value():
    result = {"pass": "pass2", "batch_id": "x", "renames": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass1" in e.lower() for e in errors)


def test_validate_rejects_empty_rename_target():
    result = {
        "pass": "pass1", "batch_id": "x",
        "renames": [{"addr": "0x1", "to": "", "confidence": "high", "rationale": "r"}],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("name" in e.lower() and "empty" in e.lower() for e in errors)


def test_validate_rejects_unknown_confidence():
    result = {
        "pass": "pass1", "batch_id": "x",
        "renames": [{"addr": "0x1", "to": "Foo", "confidence": "bogus", "rationale": "r"}],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("confidence" in e.lower() for e in errors)


def test_validate_rejects_record_missing_addr():
    result = json.loads((FIXTURES / "sample_worker_result_malformed.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    # The fixture has both an empty name AND a missing addr; both should error.
    joined = " ".join(errors).lower()
    assert "addr" in joined
    assert "name" in joined or "confidence" in joined


def test_validate_rejects_renames_not_a_list():
    result = {"pass": "pass1", "batch_id": "x", "renames": "not-a-list"}
    errors = apply_mod.validate_worker_result(result)
    assert any("renames" in e.lower() for e in errors)
