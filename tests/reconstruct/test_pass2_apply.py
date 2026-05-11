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


def _function_index_for_pass2_merge():
    return {
        "binary": "samplebin.exe",
        "functions": [
            {"address": "0x140003000", "name": "FUN_140003000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h3",
             "instruction_count": 128, "size": 512, "strings": []},
            {"address": "0x140004000", "name": "FUN_140004000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h4",
             "instruction_count": 1, "size": 8, "strings": []},
            {"address": "0x140005000", "name": "FUN_140005000",
             "callees": [], "callers": [], "is_external": False,
             "is_thunk": False, "is_exported": False, "code_hash": "h5",
             "instruction_count": 64, "size": 256, "strings": []},
        ],
    }


def test_merge_creates_pass2_entry_when_absent():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    assert not any(p["pass"] == "pass2" for p in manifest["passes"])
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result)
    pass2 = next(p for p in out["passes"] if p["pass"] == "pass2")
    addrs = {r["addr"] for r in pass2["retypes"]}
    assert addrs == {"0x140003000", "0x140004000"}


def test_merge_attaches_source_llm_retype_to_each_record():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result)
    pass2 = next(p for p in out["passes"] if p["pass"] == "pass2")
    for r in pass2["retypes"]:
        for p in r.get("params", []):
            assert p["source"] == "llm_retype"
        for l in r.get("locals", []):
            assert l["source"] == "llm_retype"


def test_merge_is_idempotent_when_same_result_re_applied():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    first = apply_mod.merge_into_manifest(manifest, result)
    second = apply_mod.merge_into_manifest(first, result)
    pass2 = next(p for p in second["passes"] if p["pass"] == "pass2")
    for r in pass2["retypes"]:
        param_indices = [p["index"] for p in r.get("params", [])]
        local_names = [l["name"] for l in r.get("locals", [])]
        assert len(param_indices) == len(set(param_indices))
        assert len(local_names) == len(set(local_names))


def test_merge_later_retype_overrides_earlier_for_same_param_index():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    first = {
        "pass": "pass2", "batch_id": "b0",
        "retypes": [{
            "addr": "0x140003000",
            "params": [{"index": 0, "to": "OldType", "confidence": "medium", "rationale": "..."}],
            "locals": [],
        }],
    }
    second = {
        "pass": "pass2", "batch_id": "b1",
        "retypes": [{
            "addr": "0x140003000",
            "params": [{"index": 0, "to": "NewType", "confidence": "high", "rationale": "..."}],
            "locals": [],
        }],
    }
    after_first = apply_mod.merge_into_manifest(manifest, first)
    after_second = apply_mod.merge_into_manifest(after_first, second)
    pass2 = next(p for p in after_second["passes"] if p["pass"] == "pass2")
    rec = next(r for r in pass2["retypes"] if r["addr"] == "0x140003000")
    p0 = next(p for p in rec["params"] if p["index"] == 0)
    assert p0["to"] == "NewType"
    assert p0["confidence"] == "high"


def test_recompute_coverage_includes_typed_block():
    manifest = json.loads((FIXTURES / "sample_manifest_pass1_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass2_result_valid.json").read_text())
    after = apply_mod.merge_into_manifest(manifest, result)
    cov = apply_mod.recompute_coverage(_function_index_for_pass2_merge(), after)
    assert "typed" in cov
    assert cov["typed"]["from_pass2"] == 2
    assert cov["typed"]["total_typed"] == 2


def test_cli_end_to_end(tmp_path):
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    (eng / "decomp" / "function_index.json").write_text(
        json.dumps(_function_index_for_pass2_merge())
    )
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass2_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass1_done.json",
                recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_pass2_result_valid.json",
                recon_dir / "pass2_batches" / "result_000.json")
    (recon_dir / "pass2_batches" / "index.json").write_text(json.dumps({
        "batches": [{"batch_id": "batch_000", "function_count": 2, "status": "pending"}],
        "candidate_count": 2,
    }, indent=2))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass2_apply.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass2_batches" / "result_000.json")],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    manifest = json.loads((recon_dir / "manifest.json").read_text())
    assert any(p["pass"] == "pass2" for p in manifest["passes"])
    cov = json.loads((recon_dir / "coverage.json").read_text())
    assert cov["typed"]["from_pass2"] == 2
    idx = json.loads((recon_dir / "pass2_batches" / "index.json").read_text())
    assert idx["batches"][0]["status"] == "applied"


def test_cli_refuses_malformed(tmp_path):
    eng = tmp_path / "engagements" / "test-eng"
    (eng / "decomp").mkdir(parents=True)
    (eng / "decomp" / "function_index.json").write_text(
        json.dumps(_function_index_for_pass2_merge())
    )
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass2_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass1_done.json",
                recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_pass2_result_malformed.json",
                recon_dir / "pass2_batches" / "result_999.json")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass2_apply.py"),
         "--engagement", "test-eng",
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass2_batches" / "result_999.json")],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "validation failed" in (r.stdout + r.stderr).lower()
