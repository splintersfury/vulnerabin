"""Tests for reconstruct_pass2_apply — worker result validator + manifest merge."""
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

import reconstruct_pass2_apply as apply_mod  # type: ignore


def test_validate_accepts_well_formed_result():
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    assert errors == []


def test_validate_rejects_missing_pass_field():
    result = {"batch_id": "x", "retypes": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass" in e.lower() for e in errors)


def test_validate_rejects_wrong_pass_value():
    result = {"pass": "pass3", "batch_id": "x", "retypes": []}
    errors = apply_mod.validate_worker_result(result)
    assert any("pass2" in e.lower() for e in errors)


def test_validate_rejects_retypes_not_a_list():
    result = {"pass": "pass2", "batch_id": "x", "retypes": "not-a-list"}
    errors = apply_mod.validate_worker_result(result)
    assert any("retypes" in e.lower() for e in errors)


def test_validate_rejects_missing_addr_on_retype():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{"params": [], "locals": []}],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("addr" in e.lower() for e in errors)


def test_validate_rejects_empty_param_to():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{
            "addr": "0x1",
            "params": [{"index": 0, "to": "", "confidence": "high", "rationale": "r"}],
            "locals": [],
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("`to`" in e or "empty" in e.lower() for e in errors)


def test_validate_rejects_unknown_confidence():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{
            "addr": "0x1",
            "params": [{"index": 0, "to": "Foo", "confidence": "ultra", "rationale": "r"}],
            "locals": [],
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("confidence" in e.lower() for e in errors)


def test_validate_rejects_local_without_name():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{
            "addr": "0x1",
            "params": [],
            "locals": [{"to": "DWORD", "confidence": "high", "rationale": "r"}],
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("local" in e.lower() and "name" in e.lower() for e in errors)


def test_validate_rejects_param_without_index():
    result = {
        "pass": "pass2", "batch_id": "x",
        "retypes": [{
            "addr": "0x1",
            "params": [{"to": "DWORD", "confidence": "high", "rationale": "r"}],
            "locals": [],
        }],
    }
    errors = apply_mod.validate_worker_result(result)
    assert any("index" in e.lower() for e in errors)


def test_validate_rejects_malformed_fixture():
    result = json.loads((FIXTURES / "sample_pass2_result_malformed.json").read_text())
    errors = apply_mod.validate_worker_result(result)
    joined = " ".join(errors).lower()
    assert "addr" in joined
    assert "to" in joined or "empty" in joined
    assert "confidence" in joined
