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


def test_make_batches_groups_in_chunks_of_batch_size():
    survivors = [{"address": f"0x{i:08x}"} for i in range(45)]
    batches = batch.make_batches(survivors, batch_size=20)
    assert len(batches) == 3
    assert len(batches[0]) == 20
    assert len(batches[1]) == 20
    assert len(batches[2]) == 5


def test_make_batches_handles_empty_input():
    assert batch.make_batches([], batch_size=20) == []


def test_make_batches_rejects_zero_batch_size():
    with pytest.raises(ValueError):
        batch.make_batches([{"address": "0x1"}], batch_size=0)


def test_build_batch_input_includes_neighbor_names():
    fi = _function_index_with_survivors()
    survivors = batch.identify_survivors(fi, _pass0_manifest())
    payload = batch.build_batch_input(survivors[:2], fi)
    assert "functions" in payload
    items = payload["functions"]
    # Each item has neighbors with caller/callee names (not addresses).
    for it in items:
        assert "neighbors" in it
        assert "callers" in it["neighbors"]
        assert "callees" in it["neighbors"]
    # Confirm one specific neighbor mapping: 0x140003000's callee 0x140004000
    # should appear as the *name* "FUN_140004000" (not the raw address) since
    # we resolve via function_index lookup.
    by_addr = {it["addr"]: it for it in items}
    if "0x140003000" in by_addr:
        callees = by_addr["0x140003000"]["neighbors"]["callees"]
        assert "FUN_140004000" in callees


def test_write_batches_emits_batch_files_and_index(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    (recon_dir / "manifest.json").write_text(
        (FIXTURES / "sample_manifest_pass0_only.json").read_text()
    )
    fi = _function_index_with_survivors()
    summary = batch.write_batches(recon_dir, fi, json.loads(
        (FIXTURES / "sample_manifest_pass0_only.json").read_text()
    ))
    bdir = recon_dir / "pass1_batches"
    assert (bdir / "batch_000.json").is_file()
    assert (bdir / "index.json").is_file()
    idx = json.loads((bdir / "index.json").read_text())
    assert idx["survivor_count"] == summary["survivor_count"]
    assert len(idx["batches"]) == summary["batch_count"]
    assert all(b["status"] == "pending" for b in idx["batches"])
    b0 = json.loads((bdir / "batch_000.json").read_text())
    assert b0["batch_id"] == "batch_000"
    assert "functions" in b0


def test_cli_writes_batches_against_seeded_engagement(tmp_path):
    """End-to-end via subprocess: scaffold + pass0 manifest + function_index +
    invoke reconstruct_pass1_batch.py with VULNERABIN_ROOT."""
    # Seed engagement + decomp.
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    fi = _function_index_with_survivors()
    (eng / "decomp" / "function_index.json").write_text(json.dumps(fi))

    # Seed catalog dir + Pass 0 manifest.
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    shutil.copy(
        FIXTURES / "sample_manifest_pass0_only.json",
        recon_dir / "manifest.json",
    )

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass1_batch.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (recon_dir / "pass1_batches" / "batch_000.json").is_file()
    assert (recon_dir / "pass1_batches" / "index.json").is_file()


def test_cli_refuses_when_catalog_dir_missing(tmp_path):
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass1_batch.py"),
         "--engagement", "anything",
         "--binary", "missing", "--version", "v0"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "not found" in (result.stdout + result.stderr).lower()
