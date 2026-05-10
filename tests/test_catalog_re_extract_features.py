"""Smoke test: catalog_re_extract calls feat_detectors and merges into YAML."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
RE_EXTRACT = SCRIPTS / "catalog_re_extract.py"


def _import():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("catalog_re_extract", RE_EXTRACT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["catalog_re_extract"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_process_features_idempotent_on_empty_yaml(tmp_path):
    mod = _import()
    fi = {
        "binary": "test.dll",
        "exports": [
            {"name": "Bd_Update_Run", "rva": "0x10001000"},
            {"name": "Bd_Update_Cancel", "rva": "0x10001100"},
        ],
    }
    binary_yaml = {
        "binary": "test.dll",
        "platform": "windows",
        "binary_kind": "dll",
    }
    from feat_detectors.base import DetectorContext
    ctx = DetectorContext(
        binary_path=Path("/dev/null"),
        decomp_dir=None,
        function_index=fi,
        chains=None,
        re_block={},
        existing_yaml=binary_yaml,
    )
    out1 = mod.process_features(binary_yaml, ctx)
    out2 = mod.process_features(out1, ctx)
    assert len(out1["features"]) == len(out2["features"]) == 1
    assert out1["features"][0]["slug"] == "bd-update"


def test_process_features_skips_rejected(tmp_path):
    mod = _import()
    binary_yaml = {
        "binary": "test.dll",
        "platform": "windows",
        "binary_kind": "dll",
        "features": [{
            "id": "FEAT-001",
            "slug": "bd-update",
            "rejected": True,
            "rejection_reason": "internal-only",
            "signal_sources": [{
                "detector": "exports",
                "evidence_type": "export_prefix",
                "evidence_value": "Bd_Update_",
            }],
        }],
    }
    fi = {
        "exports": [
            {"name": "Bd_Update_Run", "rva": "0x10001000"},
            {"name": "Bd_Update_Cancel", "rva": "0x10001100"},
        ],
    }
    from feat_detectors.base import DetectorContext
    ctx = DetectorContext(
        binary_path=Path("/dev/null"),
        decomp_dir=None,
        function_index=fi,
        chains=None,
        re_block={},
        existing_yaml=binary_yaml,
    )
    out = mod.process_features(binary_yaml, ctx)
    # Rejection prevents resurfacing — feature count stays at 1.
    assert len(out["features"]) == 1
    assert out["features"][0]["rejected"] is True
