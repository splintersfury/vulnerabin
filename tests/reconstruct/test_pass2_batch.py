"""Tests for reconstruct_pass2_batch — candidate detection + batching."""
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

import reconstruct_pass2_batch as batch  # type: ignore


def _function_index_for_pass2() -> dict:
    return {
        "binary": "samplebin.exe",
        "functions": [
            {"address": "0x140001000", "name": "entry", "callees": [],
             "callers": [], "is_external": False, "is_thunk": False,
             "is_exported": True, "code_hash": "h1", "instruction_count": 42,
             "size": 256, "strings": []},
            {"address": "0x140002000", "name": "FUN_140002000",
             "callees": ["0x140020000"], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h2",
             "instruction_count": 2, "size": 12, "strings": []},
            {"address": "0x140003000", "name": "FUN_140003000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h3",
             "instruction_count": 128, "size": 512, "strings": []},
            {"address": "0x140004000", "name": "FUN_140004000",
             "callees": ["0x140021000"], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h4",
             "instruction_count": 1, "size": 8, "strings": []},
            {"address": "0x140005000", "name": "FUN_140005000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h5",
             "instruction_count": 64, "size": 256, "strings": []},
            {"address": "0x140006000", "name": "DllMain", "callees": [],
             "callers": [], "is_external": False, "is_thunk": False,
             "is_exported": True, "code_hash": "h6", "instruction_count": 32,
             "size": 128, "strings": []},
            {"address": "0x140007000", "name": "FUN_140007000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h7",
             "instruction_count": 8, "size": 32, "strings": []},
            {"address": "0x140020000", "name": "RtlAllocateHeap",
             "callees": [], "callers": ["0x140002000"], "is_external": True,
             "is_thunk": False, "is_exported": False, "code_hash": "0",
             "instruction_count": 0, "size": 0, "strings": []},
            {"address": "0x140021000", "name": "CreateFileW",
             "callees": [], "callers": ["0x140004000"], "is_external": True,
             "is_thunk": False, "is_exported": False, "code_hash": "0",
             "instruction_count": 0, "size": 0, "strings": []},
        ],
    }


def _manifest_pass1_done() -> dict:
    return json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())


def test_identify_candidates_includes_pass1_renamed_addresses():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140003000" in addrs
    assert "0x140004000" in addrs
    assert "0x140005000" in addrs


def test_identify_candidates_includes_pass0_renamed_addresses():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140002000" in addrs


def test_identify_candidates_includes_originally_named_exports():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140001000" in addrs
    assert "0x140006000" in addrs


def test_identify_candidates_excludes_FUN_survivors():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140007000" not in addrs


def test_identify_candidates_excludes_externals_and_thunks():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    addrs = {c["address"] for c in cands}
    assert "0x140020000" not in addrs
    assert "0x140021000" not in addrs


def test_make_batches_chunks_correctly():
    cands = [{"address": f"0x{i:08x}"} for i in range(45)]
    batches = batch.make_batches(cands, batch_size=20)
    assert len(batches) == 3
    assert len(batches[0]) == 20
    assert len(batches[1]) == 20
    assert len(batches[2]) == 5


def test_build_batch_input_includes_effective_name(monkeypatch):
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    target = next(c for c in cands if c["address"] == "0x140003000")
    payload = batch.build_batch_input([target], fi, manifest)
    item = payload["functions"][0]
    assert item["addr"] == "0x140003000"
    assert item["name"] == "DispatchCommand"


def test_build_batch_input_includes_neighbor_names():
    fi = _function_index_for_pass2()
    manifest = _manifest_pass1_done()
    cands = batch.identify_candidates(fi, manifest)
    payload = batch.build_batch_input(cands[:2], fi, manifest)
    for item in payload["functions"]:
        assert "neighbors" in item
        assert "callers" in item["neighbors"]
        assert "callees" in item["neighbors"]


def test_write_batches_emits_files_and_index(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    (recon_dir / "manifest.json").write_text(
        (FIXTURES / "sample_manifest_pass1_done.json").read_text()
    )
    fi = _function_index_for_pass2()
    summary = batch.write_batches(
        recon_dir, fi, _manifest_pass1_done(),
    )
    bdir = recon_dir / "pass2_batches"
    assert (bdir / "batch_000.json").is_file()
    assert (bdir / "index.json").is_file()
    idx = json.loads((bdir / "index.json").read_text())
    assert idx["candidate_count"] == summary["candidate_count"]
    assert len(idx["batches"]) == summary["batch_count"]
    assert all(b["status"] == "pending" for b in idx["batches"])


def test_cli_writes_batches_end_to_end(tmp_path):
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    fi = _function_index_for_pass2()
    (eng / "decomp" / "function_index.json").write_text(json.dumps(fi))
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    recon_dir.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass1_done.json",
                recon_dir / "manifest.json")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass2_batch.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (recon_dir / "pass2_batches" / "batch_000.json").is_file()


def test_cli_refuses_missing_catalog_dir(tmp_path):
    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass2_batch.py"),
         "--engagement", "x", "--binary", "missing", "--version", "v0"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "not found" in (result.stdout + result.stderr).lower()
