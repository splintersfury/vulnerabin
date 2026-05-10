#!/usr/bin/env python3
"""
Auto-seed catalog/binaries/<name>.yml drafts from engagement data.

Two extraction modes:
  Default (deterministic): walk engagements/, identify binaries from
    decomp-<name>/ directory naming, group findings/scope.json/chains.json by
    binary, write skeleton YAMLs to catalog/_drafts/ with versions populated
    and sources/sinks/chains stubbed for the user to fill in.

  --enrich (LLM-assisted): for each draft, spawn an Agent that reads the
    associated finding markdown and emits structured source/condition/sink
    JSON. NOT IMPLEMENTED YET; prints a TODO and continues with deterministic
    output. Ship that in a follow-up iteration.

Usage:
    python3 scripts/catalog_seed.py                          # seed everything
    python3 scripts/catalog_seed.py --binary safeelevatedrun.dll
    python3 scripts/catalog_seed.py --eng bitdefender-total-security-2026-04-11
    python3 scripts/catalog_seed.py --binary foo --merge      # update existing
                                                              # catalog/binaries/foo.yml
                                                              # in place rather than
                                                              # writing a draft
    python3 scripts/catalog_seed.py --enrich                 # placeholder

The seeder NEVER overwrites a file in catalog/binaries/ unless you pass
--merge, which appends new versions/findings to an existing entry without
deleting hand-curated sources/sinks/chains.

Output goes to catalog/_drafts/ by default. Review, then `mv` to
catalog/binaries/.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
ENGAGEMENTS = ROOT / "engagements"
DRAFTS = CATALOG / "_drafts"
BINARIES = CATALOG / "binaries"

# Common decompilation-directory naming patterns
DECOMP_DIR_RES = [
    re.compile(r"^decomp-(?P<name>.+)$"),       # decomp-bztransmit
    re.compile(r"^(?P<name>.+)_decomp$"),         # bztransmit_decomp
    re.compile(r"^(?P<name>.+)-decomp$"),         # bztransmit-decomp
]


@dataclass
class BinaryRecord:
    binary: str                                   # canonical filename (no path)
    versions: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    decomp_dirs: list[str] = field(default_factory=list)


def normalise_binary_name(stem: str) -> str:
    """Map a decomp-dir stem like 'safeelevatedrun' or 'bztransmit-x64' to a
    plausible binary filename. Returns the lowercase token; we infer .dll/.exe/.sys
    later when we cross-check against extracted/ or target/ contents."""
    s = stem.strip().lower()
    # Common cleanup: drop suffixes that aren't part of the binary name
    s = re.sub(r"-(?:latest|x64|x86|v[0-9.]+|patched)$", "", s)
    # Map known cases that don't follow the convention
    return s


def binary_yaml_filename(binary_name: str) -> str:
    """Map 'safeelevatedrun.dll' -> 'safeelevatedrun_dll' for the YAML filename."""
    return re.sub(r"[^A-Za-z0-9]+", "_", binary_name.lower()).strip("_")


def detect_engagement_binaries(eng_dir: Path) -> list[str]:
    """Inspect an engagement folder and return likely binary base names."""
    found = set()
    for child in eng_dir.iterdir():
        if not child.is_dir():
            continue
        for rx in DECOMP_DIR_RES:
            m = rx.match(child.name)
            if m:
                found.add(normalise_binary_name(m.group("name")))
                break
    # Also check target/ for actual filenames (best signal of canonical name)
    target_dir = eng_dir / "target"
    if target_dir.is_dir():
        for f in target_dir.iterdir():
            if f.is_file() and f.suffix.lower() in (".dll", ".exe", ".sys", ".so"):
                found.add(f.name.lower())
    return sorted(found)


def parse_scope(eng_dir: Path) -> dict:
    sp = eng_dir / "scope.json"
    if not sp.is_file():
        return {}
    try:
        return json.loads(sp.read_text())
    except Exception:
        return {}


def list_findings(eng_dir: Path) -> list[Path]:
    fdir = eng_dir / "findings"
    if not fdir.is_dir():
        return []
    return sorted(p for p in fdir.glob("*.md") if not p.name.startswith("summary"))


def attribute_finding_to_binary(finding: Path, binaries: list[str]) -> str | None:
    """Best-effort: match a finding filename or content header to a known binary
    base name from the engagement. Returns the binary name (with extension if
    determinable, else the bare stem)."""
    name = finding.name.lower()
    # Strip leading "NNN-" numbering
    name_clean = re.sub(r"^\d+-", "", name).removesuffix(".md")

    # Try matching the finding stem against known binary names
    candidates = []
    for b in binaries:
        bare = b.split(".")[0]                      # strip .dll/.exe/.sys
        if bare in name_clean or name_clean.startswith(bare):
            candidates.append(b)

    if candidates:
        # Prefer the longest match
        return max(candidates, key=len)

    # Fall back to peeking at the markdown's first 2KB
    try:
        head = finding.read_text()[:2000].lower()
    except Exception:
        return None
    for b in binaries:
        bare = b.split(".")[0]
        if bare in head:
            return b
    return None


def _canonical_stem(name: str) -> str:
    """Strip any binary extension to get the bare stem ('foo.dll' -> 'foo')."""
    s = name.lower()
    for ext in (".dll", ".exe", ".sys", ".so"):
        if s.endswith(ext):
            return s[: -len(ext)]
    return s


def merge_bare_into_extensioned(records: dict[str, BinaryRecord]) -> dict[str, BinaryRecord]:
    """If both 'foo' (bare) and 'foo.dll' (extensioned) entries exist, fold the
    bare one into the extensioned one. The seeder produces both because decomp
    dirs (decomp-foo) and target/ filenames (foo.dll) both feed the registry.
    """
    # Build stem -> [keys] map
    by_stem: dict[str, list[str]] = {}
    for k, r in records.items():
        by_stem.setdefault(_canonical_stem(r.binary), []).append(k)

    out: dict[str, BinaryRecord] = {}
    for stem, keys in by_stem.items():
        # Prefer the entry whose binary name has an extension
        keys_sorted = sorted(
            keys,
            key=lambda k: (
                0 if "." in records[k].binary else 1,
                len(records[k].binary),
            ),
        )
        primary_key = keys_sorted[0]
        primary = records[primary_key]
        # Fold others into primary
        for k in keys_sorted[1:]:
            other = records[k]
            for v in other.versions:
                if not any(x.get("eng") == v.get("eng") for x in primary.versions):
                    primary.versions.append(v)
            for d in other.decomp_dirs:
                if d not in primary.decomp_dirs:
                    primary.decomp_dirs.append(d)
            for f in other.findings:
                if not any(x.get("ref") == f.get("ref") for x in primary.findings):
                    primary.findings.append(f)
        out[binary_yaml_filename(primary.binary)] = primary
    return out


def collect_records(eng_filter: str | None, bin_filter: str | None) -> dict[str, BinaryRecord]:
    records: dict[str, BinaryRecord] = {}
    if not ENGAGEMENTS.is_dir():
        raise SystemExit(f"engagements/ not found at {ENGAGEMENTS}")

    for eng_dir in sorted(ENGAGEMENTS.iterdir()):
        if not eng_dir.is_dir():
            continue
        if eng_filter and eng_filter not in eng_dir.name:
            continue

        scope = parse_scope(eng_dir)
        version = scope.get("version", "")
        target_name = scope.get("target", "")

        bins = detect_engagement_binaries(eng_dir)
        if not bins:
            continue

        findings = list_findings(eng_dir)

        for b in bins:
            if bin_filter and bin_filter.lower() not in b.lower():
                continue
            yaml_key = binary_yaml_filename(b)
            rec = records.setdefault(yaml_key, BinaryRecord(binary=b))
            # Update canonical binary name (prefer ones with extensions)
            if "." in b and "." not in rec.binary:
                rec.binary = b
            # Version entry
            if not any(v.get("eng") == eng_dir.name for v in rec.versions):
                rec.versions.append({
                    "version": str(version) if version else "",
                    "sha256": "",
                    "eng": eng_dir.name,
                    "seen": eng_dir.name.split("-")[-3:] and "-".join(eng_dir.name.split("-")[-3:]) or "",
                    "notes": f"Auto-seeded from {eng_dir.name}/scope.json (target: {target_name})" if target_name else "",
                })
            # Decomp dirs
            for child in eng_dir.iterdir():
                if not child.is_dir():
                    continue
                if any(rx.match(child.name) for rx in DECOMP_DIR_RES):
                    bare = b.split(".")[0]
                    if bare in child.name.lower() or child.name == "decomp":
                        rd = f"{eng_dir.name}/{child.name}"
                        if rd not in rec.decomp_dirs:
                            rec.decomp_dirs.append(rd)
            # Findings attributable to this binary
            for f in findings:
                attr = attribute_finding_to_binary(f, bins)
                if attr and attr.lower().split(".")[0] == b.lower().split(".")[0]:
                    ref = f"{eng_dir.name}/findings/{f.name}"
                    if not any(x.get("ref") == ref for x in rec.findings):
                        rec.findings.append({
                            "ref": ref,
                            "eng": eng_dir.name,
                            "version": str(version) if version else "",
                        })

    return merge_bare_into_extensioned(records)


def render_draft(rec: BinaryRecord, existing: dict | None = None) -> dict:
    """Build the YAML data for a draft, preserving any existing hand-curated
    sources/sinks/chains when --merge was passed."""
    binary = rec.binary
    if existing is None:
        existing = {}

    out = {
        "binary": existing.get("binary") or binary,
        "display_name": existing.get("display_name") or binary,
        "description": existing.get("description") or
                       f"(Auto-seeded; replace this description.) "
                       f"Catalogued in {len(rec.versions)} engagement(s).",
        "canonical_path": existing.get("canonical_path") or "",
        "arch": existing.get("arch") or "",
        "platform": existing.get("platform") or "",
        "binary_kind": existing.get("binary_kind") or _infer_kind(binary),
        "trust_boundary": existing.get("trust_boundary") or "",
        "versions": _merge_versions(existing.get("versions") or [], rec.versions),
        "sources": existing.get("sources") or [],
        "sinks": existing.get("sinks") or [],
        "chains": existing.get("chains") or [],
        # Extra: a `_seed_meta` block the seeder owns. Hand-edits are preserved.
        "_seed_meta": {
            "decomp_dirs": rec.decomp_dirs,
            "findings_seen": rec.findings,
            "seeded_at": _utc_now_str(),
        },
    }
    return out


def _utc_now_str() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _infer_kind(name: str) -> str:
    s = name.lower()
    if s.endswith(".dll"):
        return "dll"
    if s.endswith(".sys"):
        return "sys"
    if s.endswith(".exe"):
        return "exe"
    if s.endswith(".so"):
        return "so"
    return ""


def _merge_versions(existing: list, new: list) -> list:
    """Merge by `eng` name; new entries from the seeder are appended without
    overwriting existing user-edited versions."""
    seen = {v.get("eng"): v for v in existing}
    for v in new:
        eng = v.get("eng")
        if eng and eng not in seen:
            seen[eng] = v
        # Note: we do NOT update existing entries here; user edits win.
    return list(seen.values())


def write_draft(rec: BinaryRecord, merge: bool, force: bool) -> Path:
    yaml_key = binary_yaml_filename(rec.binary)
    if merge:
        out_dir = BINARIES
        out_path = BINARIES / f"{yaml_key}.yml"
        existing = None
        if out_path.is_file():
            existing = yaml.safe_load(out_path.read_text()) or {}
    else:
        DRAFTS.mkdir(exist_ok=True)
        out_dir = DRAFTS
        out_path = DRAFTS / f"{yaml_key}.yml"
        existing = None
        if out_path.is_file() and not force:
            print(f"  exists (skipping; pass --force to overwrite): {out_path}", file=sys.stderr)
            return out_path
    data = render_draft(rec, existing)
    out_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))

    # Auto-extract reverse_engineering: block from any decomp dirs we've seen.
    # Idempotent: extractor preserves hand-edited fields. Best-effort — never fails the seed.
    if rec.decomp_dirs and merge:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from catalog_re_extract import process_one as _re_process_one
            for ddir_str in rec.decomp_dirs:
                ddir = Path(ddir_str)
                if not ddir.is_absolute():
                    ddir = Path(__file__).resolve().parents[1] / ddir
                if not ddir.exists():
                    continue
                # eng dir = decomp dir's parent (typically engagements/<slug>/decomp-<x>/)
                eng_dir = ddir.parent
                _re_process_one(eng_dir, rec.binary, ddir, apply=True, verbose=False)
        except Exception as e:  # noqa: BLE001
            print(f"  [warn] catalog_re_extract failed for {rec.binary}: {e}", file=sys.stderr)
    return out_path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", help="filter to one binary (matched against decomp-* names)")
    ap.add_argument("--eng", help="filter to one engagement (substring match on folder name)")
    ap.add_argument("--merge", action="store_true",
                    help="write into catalog/binaries/, merging with any existing entry. "
                         "Without this flag, the seeder writes to catalog/_drafts/.")
    ap.add_argument("--force", action="store_true",
                    help="overwrite drafts that already exist in catalog/_drafts/")
    ap.add_argument("--enrich", action="store_true",
                    help="(stub) LLM-extract sources/sinks/chains from finding markdown. "
                         "Not yet implemented; prints a TODO and continues deterministic.")
    ap.add_argument("--list", action="store_true",
                    help="just print the binary registry, don't write any files")
    args = ap.parse_args()

    if args.enrich:
        print("[note] --enrich is a stub. The deterministic seed will run; "
              "no LLM extraction has been performed.\n", file=sys.stderr)

    records = collect_records(args.eng, args.binary)
    if not records:
        print("no binaries detected", file=sys.stderr)
        return 1

    if args.list:
        print(f"{'BINARY':40s}  VERS  FNDGS  DECOMP_DIRS")
        for k, r in sorted(records.items()):
            print(f"{r.binary:40s}  {len(r.versions):4d}  {len(r.findings):5d}  {len(r.decomp_dirs)}")
        return 0

    written = []
    for k, rec in sorted(records.items()):
        path = write_draft(rec, args.merge, args.force)
        written.append(path)

    print(f"\nseeded {len(written)} {'entries (merged into catalog/binaries/)' if args.merge else 'drafts (in catalog/_drafts/)'}:")
    for p in written:
        print(f"  {p.relative_to(ROOT)}")

    if not args.merge:
        print("\nReview drafts, then promote with:")
        print("    mv catalog/_drafts/<name>.yml catalog/binaries/")
        print("    python3 scripts/catalog_render.py")

    return 0


if __name__ == "__main__":
    sys.exit(main())
