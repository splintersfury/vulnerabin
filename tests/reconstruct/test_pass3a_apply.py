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


def test_merge_creates_pass3a_entry_when_absent():
    manifest = json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())
    assert not any(p["pass"] == "pass3a" for p in manifest["passes"])
    result = json.loads((FIXTURES / "sample_pass3a_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result)
    pass3a = next(p for p in out["passes"] if p["pass"] == "pass3a")
    names = {s["name"] for s in pass3a["structs"]}
    assert "IPC_REQUEST_HEADER" in names


def test_merge_attaches_source_llm_structify():
    manifest = json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass3a_result_valid.json").read_text())
    out = apply_mod.merge_into_manifest(manifest, result)
    pass3a = next(p for p in out["passes"] if p["pass"] == "pass3a")
    for s in pass3a["structs"]:
        assert s["source"] == "llm_structify"


def test_merge_is_idempotent_when_same_result_re_applied():
    manifest = json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())
    result = json.loads((FIXTURES / "sample_pass3a_result_valid.json").read_text())
    first = apply_mod.merge_into_manifest(manifest, result)
    second = apply_mod.merge_into_manifest(first, result)
    pass3a = next(p for p in second["passes"] if p["pass"] == "pass3a")
    names = [s["name"] for s in pass3a["structs"]]
    assert len(names) == len(set(names))


def test_merge_later_result_overrides_earlier_for_same_struct_name():
    manifest = json.loads((FIXTURES / "sample_manifest_pass2_done.json").read_text())
    first = {
        "pass": "pass3a", "batch_id": "b0",
        "structs": [{
            "name": "IPC_REQUEST_HEADER",
            "supporting_functions": ["0x1"],
            "fields": [{"offset": 0, "type": "uint8_t", "name": "old", "rationale": "..."}],
            "confidence": "low",
            "rationale": "first try",
        }],
    }
    second = {
        "pass": "pass3a", "batch_id": "b1",
        "structs": [{
            "name": "IPC_REQUEST_HEADER",
            "supporting_functions": ["0x1", "0x2"],
            "fields": [{"offset": 0, "type": "uint32_t", "name": "new", "rationale": "..."}],
            "confidence": "high",
            "rationale": "refined",
        }],
    }
    after_first = apply_mod.merge_into_manifest(manifest, first)
    after_second = apply_mod.merge_into_manifest(after_first, second)
    pass3a = next(p for p in after_second["passes"] if p["pass"] == "pass3a")
    rec = next(s for s in pass3a["structs"] if s["name"] == "IPC_REQUEST_HEADER")
    assert rec["confidence"] == "high"
    assert rec["fields"][0]["name"] == "new"


def test_cli_end_to_end(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass3a_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass2_done.json",
                recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_pass3a_result_valid.json",
                recon_dir / "pass3a_batches" / "result_000.json")
    (recon_dir / "pass3a_batches" / "index.json").write_text(json.dumps({
        "batches": [{"batch_id": "batch_000", "cluster_name": "IPC_REQUEST_HEADER", "status": "pending"}],
        "cluster_count": 1,
    }, indent=2))

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass3a_apply.py"),
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass3a_batches" / "result_000.json")],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    manifest = json.loads((recon_dir / "manifest.json").read_text())
    assert any(p["pass"] == "pass3a" for p in manifest["passes"])
    idx = json.loads((recon_dir / "pass3a_batches" / "index.json").read_text())
    assert idx["batches"][0]["status"] == "applied"


def test_cli_refuses_malformed(tmp_path):
    recon_dir = tmp_path / "catalog" / "reconstructed" / "samplebin_v1_2_3"
    (recon_dir / "pass3a_batches").mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_manifest_pass2_done.json",
                recon_dir / "manifest.json")
    shutil.copy(FIXTURES / "sample_pass3a_result_malformed.json",
                recon_dir / "pass3a_batches" / "result_999.json")

    env = {**os.environ, "VULNERABIN_ROOT": str(tmp_path)}
    r = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reconstruct_pass3a_apply.py"),
         "--binary", "samplebin", "--version", "v1_2_3",
         "--result", str(recon_dir / "pass3a_batches" / "result_999.json")],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "validation failed" in (r.stdout + r.stderr).lower()
