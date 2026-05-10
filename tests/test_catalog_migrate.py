"""Test catalog_migrate.py tier classifier."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
MIGRATE_PY = SCRIPTS / "catalog_migrate.py"


def _import():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("catalog_migrate", MIGRATE_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _yaml(tmp_path: Path, name: str, contents: dict) -> Path:
    bdir = tmp_path / "catalog" / "binaries"
    bdir.mkdir(parents=True, exist_ok=True)
    p = bdir / f"{name}.yml"
    p.write_text(yaml.safe_dump(contents))
    return p


def test_classify_frozen_when_lifecycle_submitted(tmp_path):
    mod = _import()
    p = _yaml(tmp_path, "x", {"binary": "x.dll", "engagements": [
        {"slug": "x-2026-01-01", "lifecycle": "submitted"}]})
    assert mod.classify_path(p) == "frozen"


def test_classify_active_when_recent_engagement(tmp_path):
    from datetime import datetime, timedelta, timezone
    mod = _import()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    p = _yaml(tmp_path, "x", {"binary": "x.dll", "engagements": [
        {"slug": f"x-{today}", "lifecycle": "active"}]})
    assert mod.classify_path(p) == "active"


def test_classify_catalog_only_when_no_recent_activity(tmp_path):
    mod = _import()
    p = _yaml(tmp_path, "x", {"binary": "x.dll", "engagements": [
        {"slug": "x-2024-01-01", "lifecycle": "open"}]})
    assert mod.classify_path(p) == "catalog_only"


def test_classify_respects_override(tmp_path):
    mod = _import()
    p = _yaml(tmp_path, "x", {"binary": "x.dll",
                              "migration_tier_override": "frozen",
                              "engagements": [{"slug": "x-2026-05-01"}]})
    assert mod.classify_path(p) == "frozen"
