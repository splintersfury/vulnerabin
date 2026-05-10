#!/usr/bin/env python3
"""
Diff a binary's catalog entry across versions: what sources/sinks/chains were
added (or first confirmed) when the binary was inspected in version Y vs X?

Reads catalog/binaries/<binary>.yml. The same YAML holds all versions, so the
diff is computed by filtering on `first_seen_version` / `last_confirmed_version`
on sources, `first_seen_version` on sinks, and `confirmed_in_version` on chains.

Usage:
    python3 scripts/catalog_diff.py safeelevatedrun.dll --from "27" --to "27.1.1.28"
    python3 scripts/catalog_diff.py safeelevatedrun.dll --since "27"   # everything new since v27
    python3 scripts/catalog_diff.py safeelevatedrun.dll --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BINARIES = ROOT / "catalog" / "binaries"


def yaml_filename(binary_name: str) -> Path:
    base = re.sub(r"[^A-Za-z0-9]+", "_", binary_name.lower()).strip("_")
    return BINARIES / f"{base}.yml"


def load(binary: str) -> dict:
    p = yaml_filename(binary)
    if not p.is_file():
        raise SystemExit(f"not found: {p}")
    return yaml.safe_load(p.read_text()) or {}


def _versions_in(data: dict) -> list[str]:
    return [str(v.get("version", "")) for v in (data.get("versions") or []) if v.get("version")]


def _filter_new(items: list[dict], key: str, from_ver: str, to_ver: str | None) -> list[dict]:
    """Items where the version-stamp key is == to_ver (or > from_ver if to_ver is None)."""
    out = []
    for it in items:
        v = str(it.get(key, "") or "")
        if to_ver:
            if v == to_ver:
                out.append(it)
        else:
            # since-mode: anything strictly later than from_ver
            if v and v != from_ver:
                out.append(it)
    return out


def diff(data: dict, from_ver: str | None, to_ver: str | None) -> dict:
    sources = data.get("sources") or []
    sinks = data.get("sinks") or []
    chains = data.get("chains") or []

    if to_ver:
        # New in to_ver = items whose first_seen_version == to_ver
        added_sources = [s for s in sources if str(s.get("first_seen_version", "")) == to_ver]
        added_sinks = [s for s in sinks if str(s.get("first_seen_version", "")) == to_ver]
        added_chains = [c for c in chains if str(c.get("confirmed_in_version", "")) == to_ver]
        # Items present in from_ver and not later seen — useful for spotting regression candidates
        regressed_sources = [
            s for s in sources
            if str(s.get("first_seen_version", "")) == from_ver
            and str(s.get("last_confirmed_version", "")) and
            str(s.get("last_confirmed_version", "")) != to_ver
        ]
    else:
        # since-mode (no to_ver): everything later than from_ver
        added_sources = [s for s in sources if str(s.get("first_seen_version", "")) and str(s.get("first_seen_version", "")) != from_ver]
        added_sinks = [s for s in sinks if str(s.get("first_seen_version", "")) and str(s.get("first_seen_version", "")) != from_ver]
        added_chains = [c for c in chains if str(c.get("confirmed_in_version", "")) and str(c.get("confirmed_in_version", "")) != from_ver]
        regressed_sources = []

    return {
        "binary": data.get("binary"),
        "from_version": from_ver,
        "to_version": to_ver,
        "all_versions_seen": _versions_in(data),
        "added_sources": added_sources,
        "added_sinks": added_sinks,
        "added_chains": added_chains,
        "regressed_sources": regressed_sources,
    }


def render(d: dict) -> str:
    out = [f"# Diff: {d['binary']} {d['from_version'] or '(start)'} → {d['to_version'] or '(any later)'}"]
    out.append("")
    out.append(f"Versions seen: {', '.join(d['all_versions_seen']) or '(none)'}")
    out.append("")
    out.append(f"## Added sources ({len(d['added_sources'])})")
    for s in d["added_sources"]:
        out.append(f"- **{s.get('id')}** {s.get('name')} (via {s.get('via')}, type {s.get('type')})")
    if not d["added_sources"]:
        out.append("(none)")
    out.append("")
    out.append(f"## Added sinks ({len(d['added_sinks'])})")
    for s in d["added_sinks"]:
        out.append(f"- **{s.get('id')}** {s.get('name')} ({s.get('cwe')}, {s.get('impact')})")
    if not d["added_sinks"]:
        out.append("(none)")
    out.append("")
    out.append(f"## Added chains ({len(d['added_chains'])})")
    for c in d["added_chains"]:
        title = c.get("title", "(untitled)")
        out.append(f"- **{c.get('id')}** {title} — {c.get('source_id')} → {c.get('sink_id')} (status: {c.get('status')}, severity: {c.get('severity', '?')})")
    if not d["added_chains"]:
        out.append("(none)")
    out.append("")
    if d["regressed_sources"]:
        out.append(f"## Sources from from_ver no longer last-confirmed at to_ver ({len(d['regressed_sources'])})")
        out.append("(possible vendor patch or refactor; investigate)")
        for s in d["regressed_sources"]:
            out.append(f"- **{s.get('id')}** {s.get('name')} (last_confirmed: {s.get('last_confirmed_version')})")
        out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", help="binary filename, e.g. safeelevatedrun.dll")
    ap.add_argument("--from", dest="from_ver", help="baseline version", required=True)
    ap.add_argument("--to", dest="to_ver", help="newer version (omit for everything since --from)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    data = load(args.binary)
    result = diff(data, args.from_ver, args.to_ver)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
