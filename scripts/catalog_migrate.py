#!/usr/bin/env python3
"""Migration tier classifier for the FEAT layer rollout.

Reads each catalog/binaries/<name>.yml and classifies the binary as
'active' (recently engaged → walk in full), 'catalog_only' (auto-extract
only), or 'frozen' (skip, render with legacy matrix). Output is written
to catalog/_migration_plan.yml for hand-review before any walks run.

Override per-binary by setting `migration_tier_override:` to one of
{active, catalog_only, frozen} in the YAML.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalog" / "binaries"
PLAN_OUT = REPO_ROOT / "catalog" / "_migration_plan.yml"


def _eng_date(slug: str) -> datetime | None:
    """Engagement slugs end with -YYYY-MM-DD; extract that."""
    try:
        return datetime.strptime(slug[-10:], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def classify(data: dict) -> str:
    if (data.get("migration_tier_override") or "").strip():
        return data["migration_tier_override"].strip()
    engagements = data.get("engagements") or []
    for eng in engagements:
        if (eng.get("lifecycle") or "") in ("submitted", "frozen", "mitigated"):
            return "frozen"
    horizon = datetime.now(timezone.utc) - timedelta(days=30)
    for eng in engagements:
        d = _eng_date(eng.get("slug", ""))
        if d and d >= horizon:
            return "active"
    return "catalog_only"


def classify_path(p: Path) -> str:
    return classify(yaml.safe_load(p.read_text()) or {})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="print plan to stdout without writing _migration_plan.yml")
    args = ap.parse_args(argv)

    plan = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "binaries": []}
    for p in sorted(CATALOG_DIR.glob("*.yml")):
        tier = classify_path(p)
        plan["binaries"].append({
            "binary": p.stem,
            "tier": tier,
            "yaml": str(p.relative_to(REPO_ROOT)),
        })

    if args.dry_run:
        print(yaml.safe_dump(plan, sort_keys=False))
    else:
        PLAN_OUT.write_text(yaml.safe_dump(plan, sort_keys=False))
        print(f"wrote {PLAN_OUT.relative_to(REPO_ROOT)} ({len(plan['binaries'])} binaries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
