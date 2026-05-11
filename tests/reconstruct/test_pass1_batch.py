"""Tests for reconstruct_pass1_batch — survivor detection + batching."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "reconstruct" / "fixtures"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import reconstruct_pass1_batch as batch  # type: ignore


def _function_index_with_survivors() -> dict:
    """Mirror the sample fixture's user-defined set so survivor detection
    has a real function_index to work against."""
    return {
        "binary": "samplebin.exe",
        "functions": [
            {"address": "0x140001000", "name": "entry", "callees": ["0x140003000"],
             "callers": [], "is_external": False, "is_thunk": False,
             "is_exported": True, "code_hash": "h1", "instruction_count": 42, "size": 256, "strings": []},
            {"address": "0x140002000", "name": "FUN_140002000",
             "callees": ["0x140020000"], "callers": ["0x140001000"],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h2", "instruction_count": 2, "size": 12, "strings": []},
            {"address": "0x140003000", "name": "FUN_140003000",
             "callees": ["0x140004000"], "callers": ["0x140001000"],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h3", "instruction_count": 128, "size": 512, "strings": []},
            {"address": "0x140004000", "name": "FUN_140004000",
             "callees": ["0x140021000"], "callers": ["0x140003000"],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h4", "instruction_count": 1, "size": 8, "strings": []},
            {"address": "0x140005000", "name": "FUN_140005000",
             "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h5", "instruction_count": 64, "size": 256, "strings": []},
            {"address": "0x140006000", "name": "DllMain",
             "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": True,
             "code_hash": "h6", "instruction_count": 32, "size": 128, "strings": []},
            {"address": "0x140007000", "name": "FUN_140007000",
             "callees": ["0x140003000"], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h7", "instruction_count": 8, "size": 32, "strings": []},
            {"address": "0x140020000", "name": "RtlAllocateHeap",
             "callees": [], "callers": ["0x140002000"],
             "is_external": True, "is_thunk": False, "is_exported": False,
             "code_hash": "0", "instruction_count": 0, "size": 0, "strings": []},
            {"address": "0x140021000", "name": "CreateFileW",
             "callees": [], "callers": ["0x140004000"],
             "is_external": True, "is_thunk": False, "is_exported": False,
             "code_hash": "0", "instruction_count": 0, "size": 0, "strings": []},
            {"address": "0x140030000", "name": "j_CreateFileW",
             "callees": ["0x140021000"], "callers": [],
             "is_external": False, "is_thunk": True, "is_exported": False,
             "code_hash": "0", "instruction_count": 1, "size": 6, "strings": []},
            {"address": "0x140040000", "name": "FUN_140040000",
             "callees": [], "callers": [],
             "is_external": False, "is_thunk": False, "is_exported": False,
             "code_hash": "h_orphan", "instruction_count": 24, "size": 96,
             "strings": ["Initializing config", "C:\\ProgramData\\sample\\config.json"]},
        ],
    }


def _pass0_manifest() -> dict:
    return json.loads((FIXTURES / "sample_manifest_pass0_only.json").read_text())


def test_identify_survivors_excludes_already_renamed_at_medium_confidence():
    """0x140002000 was renamed by Pass 0 at confidence medium — must be excluded."""
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140002000" not in addrs


def test_identify_survivors_includes_FUN_with_no_pass0_rename():
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    # The Pass 1 candidates from the fixture:
    # 0x140003000, 0x140004000, 0x140005000, 0x140007000, 0x140040000
    assert {"0x140003000", "0x140004000", "0x140005000",
            "0x140007000", "0x140040000"} <= addrs


def test_identify_survivors_excludes_externals():
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140020000" not in addrs   # RtlAllocateHeap external
    assert "0x140021000" not in addrs   # CreateFileW external


def test_identify_survivors_excludes_thunks():
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140030000" not in addrs   # j_CreateFileW thunk


def test_identify_survivors_excludes_already_semantically_named():
    """entry, DllMain — these are not FUN_* so they are NOT Pass 1 candidates."""
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140001000" not in addrs   # entry
    assert "0x140006000" not in addrs   # DllMain


def test_identify_survivors_includes_pass0_low_confidence_for_override():
    """Pass 0 low-confidence renames are NOT locked; Pass 1 may override them.
    Construct a manifest where 0x140003000 has a low-confidence Pass 0 rename
    and verify it appears in the survivor list.
    """
    fi = _function_index_with_survivors()
    manifest = _pass0_manifest()
    # Append a low-confidence Pass 0 rename for 0x140003000.
    manifest["passes"][0]["proposed_renames"].append({
        "addr": "0x140003000",
        "from": "FUN_140003000",
        "to": "try_open_file_3000",
        "confidence": "low",
        "source": "string_xref",
        "rationale": "(test)",
    })
    survivors = batch.identify_survivors(fi, manifest)
    addrs = {s["address"] for s in survivors}
    assert "0x140003000" in addrs   # low-confidence still eligible
