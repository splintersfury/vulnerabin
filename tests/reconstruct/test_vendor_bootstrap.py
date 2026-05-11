"""Tests for vendor pinning skeleton."""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VENDOR = REPO_ROOT / "vendor"


def test_libghidra_version_file_present_and_well_formed():
    p = VENDOR / "libghidra.version"
    assert p.is_file()
    lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]
    keys = {ln.split("=", 1)[0]: ln.split("=", 1)[1] for ln in lines if "=" in ln}
    assert "url" in keys, "libghidra.version must declare url"
    assert "commit" in keys, "libghidra.version must declare commit"
    assert "sha256" in keys, "libghidra.version must declare sha256"


def test_ghidrasql_skills_version_file_present_and_well_formed():
    p = VENDOR / "ghidrasql_skills.version"
    assert p.is_file()
    lines = [ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.strip().startswith("#")]
    keys = {ln.split("=", 1)[0]: ln.split("=", 1)[1] for ln in lines if "=" in ln}
    assert {"url", "commit", "sha256"} <= set(keys)


def test_fid_db_versions_json_is_well_formed():
    p = VENDOR / "fid_db_versions.json"
    assert p.is_file()
    data = json.loads(p.read_text())
    assert isinstance(data, dict)
    # At minimum, declare the two baseline DBs that the spec calls out.
    assert "msvc_crt_19" in data
    assert "winapi_thunks" in data
    for name, meta in data.items():
        assert "version" in meta
        assert "sha256" in meta


def test_vendor_readme_present():
    p = VENDOR / "README.md"
    assert p.is_file()
    text = p.read_text()
    assert "libghidra" in text.lower()
    assert "ghidrasql" in text.lower()
