#!/usr/bin/env python3
"""
Auto-enrich binary YAML drafts using `engagements/_audit/sources_observed.jsonl`
and engagement-finding markdowns.

For each `catalog/_drafts/<name>.yml` (or `catalog/binaries/<name>.yml`):
1. Resolve the engagement-binary mapping from `_seed_meta.findings_seen`.
2. Pull matching `sources_observed` records — these have already been
   classified under v2 taxonomy (source_class_ids, source_attacker_controlled,
   submission_status, etc.).
3. Generate `sources[]` entries, one per (engagement, finding) record, with
   `source_class_id` populated (first taxonomy ID) and `co_class_ids` (the rest).
4. Generate `sinks[]` from the source_class_id by looking up the canonical
   sink shape (read defense library for impact + cwe hints).
5. Generate `chains[]` linking each source to a sink, status inferred from
   the finding's submission state (`submitted_paid` → confirmed, `submitted` →
   partial, `not_submitted`/`unknown` → unexplored).
6. Generate `class_coverage[]` — relevant classes from defense library,
   marked `present` for classes seen, `unchecked` for the rest.
7. Best-effort `process_model.principal` from engagement scope.json + binary_kind.
8. Stub `defenses[]` entries per `present` class, pulling `defense_expected`
   from the defense library (so the YAML is editable but pre-filled).

Preserves any existing hand-curated content. Conservatively: never overwrites
fields already filled in.

Usage:
    python3 scripts/catalog_enrich.py                    # enrich all drafts
    python3 scripts/catalog_enrich.py --binary safeelevatedrun
    python3 scripts/catalog_enrich.py --promote          # also `mv _drafts/* binaries/` after enrich
    python3 scripts/catalog_enrich.py --dry-run          # show what would change
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
DRAFTS = CATALOG / "_drafts"
BINARIES = CATALOG / "binaries"
ENGAGEMENTS = ROOT / "engagements"
AUDIT_JSONL = ENGAGEMENTS / "_audit" / "sources_observed.jsonl"
DEFENSE_LIB = ROOT / "taxonomy" / "binary" / "defense_library.json"


def load_yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text()) or {}


def write_yaml(p: Path, data: dict):
    """Write YAML preserving key order (PyYAML respects dict insertion order in Py3.7+)."""
    p.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=120))


def load_audit_records() -> list[dict]:
    if not AUDIT_JSONL.is_file():
        return []
    return [json.loads(l) for l in AUDIT_JSONL.read_text().splitlines() if l.strip()]


def load_defense_library() -> dict:
    if not DEFENSE_LIB.is_file():
        return {}
    return json.loads(DEFENSE_LIB.read_text())


def relevant_classes_for(binary_yaml: dict, lib: dict) -> list[str]:
    pr = lib.get("platform_relevance", {})
    platform = (binary_yaml.get("platform") or "").lower()
    kind = (binary_yaml.get("binary_kind") or "").lower()
    candidates = set(pr.get(platform) or {c["id"] for c in lib.get("classes", [])})
    bk_map = pr.get("binary_kind", {})
    if kind in bk_map:
        kind_set = set()
        for token in bk_map[kind]:
            if token.endswith("-*"):
                prefix = token[:-2]
                for c in lib.get("classes", []):
                    if c["id"].startswith(prefix + "-"):
                        kind_set.add(c["id"])
            else:
                kind_set.add(token)
        candidates &= kind_set
    return sorted(candidates)


# Sink-shape lookup per source-class group: when we see a F-* source, the typical
# sink is "elevated file write/read"; for I-002 it's "command handler executing
# privileged action"; etc. These are stubs — the user can refine.
SINK_TEMPLATE_BY_GROUP = {
    "F": {"name": "Elevated file operation (write / set_acl / read)", "cwe": "CWE-269", "impact": "arbitrary file access at privileged principal's level"},
    "I": {"name": "IPC handler executes privileged operation", "cwe": "CWE-862", "impact": "arbitrary command execution as listening service"},
    "N": {"name": "Network parser memory corruption / logic flaw", "cwe": "CWE-787", "impact": "remote code execution or DoS"},
    "K": {"name": "Kernel-mode operation triggered by user-mode IOCTL", "cwe": "CWE-787", "impact": "kernel memory corruption or privilege escalation"},
    "U": {"name": "Privileged operation driven by user-input", "cwe": "CWE-269", "impact": "privilege transition via crafted input"},
    "T": {"name": "Trust check bypassed; downstream privileged operation accepted", "cwe": "CWE-285", "impact": "auth bypass leads to privileged action"},
    "UP": {"name": "Updater executes attacker-influenced binary", "cwe": "CWE-494", "impact": "code execution at updater's privilege"},
    "C": {"name": "Privileged action gated by attacker-writable config", "cwe": "CWE-732", "impact": "privilege transition via config injection"},
    "E": {"name": "Renderer-context API call reaches main process", "cwe": "CWE-94", "impact": "code execution in main process"},
    "W": {"name": "Server-side authorization bypass", "cwe": "CWE-285", "impact": "cross-tenant data access"},
    "CR": {"name": "Cryptographic primitive misuse exposes plaintext / forges ciphertext", "cwe": "CWE-326", "impact": "key recovery / impersonation"},
}


# Status inference from finding submission state
def infer_chain_status(submission_status: str, attacker_controlled: str) -> str:
    if submission_status == "submitted_paid":
        return "confirmed"
    if submission_status == "submitted":
        return "partial"
    if submission_status == "submitted_dropped":
        return "mitigated"
    if submission_status == "not_submitted":
        return "hypothesised"
    if attacker_controlled == "no":
        return "mitigated"
    if attacker_controlled == "unclear":
        return "hypothesised"
    return "unexplored"


# Principal inference: best-effort heuristic from binary name / scope context
def infer_principal(binary_name: str, binary_kind: str, scope_target: str) -> str:
    name = binary_name.lower()
    if binary_kind == "sys":
        return "kernel"
    # Common SYSTEM-context patterns
    if any(t in name for t in ("svc", "service", "agent", "daemon", "broker", "watchdog", "guard", "host")):
        return "SYSTEM"
    if any(t in name for t in ("setup", "install", "updater", "update")):
        return "installer-elevated"
    if any(t in name for t in ("ui", "tray", "gui", "view")):
        return "loggedInUser"
    return "unknown"


def enrich_one(yml_path: Path, audit_records: list[dict], lib: dict) -> dict:
    """Read a YAML, return the enriched copy. Caller writes if needed."""
    data = load_yaml(yml_path)
    if not data.get("binary"):
        return data

    # Find seed_meta to get engagement+finding linkage
    seed_meta = data.get("_seed_meta", {})
    findings_seen = seed_meta.get("findings_seen") or []

    # Match audit records by engagement+finding_file
    matched_records = []
    for f in findings_seen:
        ref = f.get("ref", "")
        # ref looks like "<eng>/findings/<file>"
        if "/findings/" in ref:
            eng, _, fname = ref.partition("/findings/")
            for r in audit_records:
                if r.get("engagement") == eng and r.get("finding_file") == fname:
                    matched_records.append((r, f.get("version", "")))

    # Skip if existing sources are already populated (preserve hand curation)
    has_real_sources = bool(data.get("sources"))
    has_real_chains = bool(data.get("chains"))

    # ----- Generate sources[] -----
    if not has_real_sources and matched_records:
        sources = []
        for i, (r, version) in enumerate(matched_records, start=1):
            class_ids = r.get("source_class_ids") or []
            class_ids = [c for c in class_ids if c != "UNCLASSIFIED"]
            if not class_ids:
                continue
            primary = class_ids[0]
            co = class_ids[1:]
            sources.append({
                "id": f"SRC-{i:03d}",
                "name": (r.get("source_one_line") or "")[:140],
                "source_class_id": primary,
                "co_class_ids": co,
                "via": "(see finding)",
                "type": "(unspecified)",
                "attacker_controlled": r.get("source_attacker_controlled", "unclear"),
                "caveat": r.get("source_attacker_caveat", ""),
                "function": "",
                "first_seen_version": version,
                "last_confirmed_version": version,
                "notes": f"Auto-enriched from {r.get('engagement')}/{r.get('finding_file')}. {r.get('notes', '')[:200]}".strip(),
            })
        if sources:
            data["sources"] = sources

    # ----- Generate sinks[] (one per distinct group seen) -----
    if not data.get("sinks"):
        groups_seen = set()
        for r, _ in matched_records:
            for cid in (r.get("source_class_ids") or []):
                if cid != "UNCLASSIFIED":
                    groups_seen.add(cid.split("-")[0])
        sinks = []
        for i, grp in enumerate(sorted(groups_seen), start=1):
            tmpl = SINK_TEMPLATE_BY_GROUP.get(grp)
            if not tmpl:
                continue
            sinks.append({
                "id": f"SNK-{i:03d}",
                "name": tmpl["name"],
                "cwe": tmpl["cwe"],
                "function": "(see finding evidence)",
                "impact": tmpl["impact"],
                "first_seen_version": "",
                "notes": f"Auto-generated stub for group {grp}. Refine with the actual sink function/line as documented in the finding.",
            })
        if sinks:
            data["sinks"] = sinks

    # ----- Generate chains[] (one per source linking to the matching-group sink) -----
    if not has_real_chains and data.get("sources") and data.get("sinks"):
        chains = []
        sinks_by_group = {s["name"]: s["id"] for s in data["sinks"]}
        # Map sink_id by group
        group_to_sink = {}
        for s in data["sinks"]:
            for grp_key, tmpl in SINK_TEMPLATE_BY_GROUP.items():
                if s.get("name") == tmpl["name"]:
                    group_to_sink[grp_key] = s["id"]
        for i, src in enumerate(data.get("sources") or [], start=1):
            cid = src.get("source_class_id") or ""
            grp = cid.split("-")[0]
            sink_id = group_to_sink.get(grp)
            if not sink_id:
                continue
            # Find matching record for status
            r = next((rec for (rec, _v) in matched_records if (rec.get("source_class_ids") or [None])[0] == cid), None)
            sub_status = r.get("submission_status", "unknown") if r else "unknown"
            ac = src.get("attacker_controlled", "unclear")
            status = infer_chain_status(sub_status, ac)
            chains.append({
                "id": f"CHAIN-{i:03d}",
                "title": src.get("name", "")[:80] or f"chain {i}",
                "source_id": src["id"],
                "sink_id": sink_id,
                "conditions": [
                    "(auto-stub: walk the source through any defenses, list each check that must pass)",
                ],
                "impact": SINK_TEMPLATE_BY_GROUP.get(grp, {}).get("impact", ""),
                "cwe": [SINK_TEMPLATE_BY_GROUP.get(grp, {}).get("cwe", "")],
                "severity": "",
                "cvss": "",
                "status": status,
                "confirmed_in_version": src.get("first_seen_version", "") if status == "confirmed" else "",
                "finding_ref": next((f.get("ref") for f in findings_seen if f.get("ref")), ""),
                "submission_ref": "",
                "bypasses_required": [],
                "notes": "Auto-generated chain stub. Fill conditions, severity, submission_ref from the finding.",
            })
        if chains:
            data["chains"] = chains

    # ----- process_model -----
    if not data.get("process_model"):
        principal = infer_principal(data.get("binary", ""), data.get("binary_kind", ""), "")
        data["process_model"] = {
            "loaded_by": "",
            "principal": principal,
            "start_trigger": "",
            "parent_processes": [],
            "ipc_peers": [],
            "impersonation_seen": False,
            "ppl_protected": False,
        }

    # ----- defenses[] (stub per present class) -----
    if not data.get("defenses") and data.get("sources"):
        defs = []
        seen_classes = set()
        for s in data["sources"]:
            cid = s.get("source_class_id")
            if cid and cid not in seen_classes:
                seen_classes.add(cid)
            for c2 in s.get("co_class_ids") or []:
                seen_classes.add(c2)
        class_meta = {c["id"]: c for c in lib.get("classes", [])}
        for cid in sorted(seen_classes):
            meta = class_meta.get(cid)
            if not meta:
                continue
            defs.append({
                "class_id": cid,
                "defense_expected": meta.get("canonical_defense", "")[:300],
                "observed": "(audit needed; fill from the finding's defense analysis)",
                "gap": "unknown",
                "bypass_attempts": "",
            })
        if defs:
            data["defenses"] = defs

    # ----- class_coverage[] (the comprehensive forcing function) -----
    if not data.get("class_coverage"):
        relevant = relevant_classes_for(data, lib)
        if relevant:
            present_classes = set()
            for s in (data.get("sources") or []):
                if s.get("source_class_id"):
                    present_classes.add(s["source_class_id"])
                for c2 in s.get("co_class_ids") or []:
                    present_classes.add(c2)
            cov = []
            chain_ids = [c["id"] for c in (data.get("chains") or [])]
            src_ids = [s["id"] for s in (data.get("sources") or [])]
            for cid in relevant:
                if cid in present_classes:
                    cov.append({
                        "class_id": cid,
                        "status": "present",
                        "rationale": "",
                        "refs": {
                            "sources": [s["id"] for s in (data.get("sources") or []) if s.get("source_class_id") == cid or cid in (s.get("co_class_ids") or [])],
                            "chains": [c["id"] for c in (data.get("chains") or []) if c.get("source_id") in src_ids],
                        },
                        "last_checked_version": (data.get("versions") or [{}])[0].get("version", "") if data.get("versions") else "",
                    })
                else:
                    cov.append({
                        "class_id": cid,
                        "status": "unchecked",
                        "rationale": "",
                        "refs": {"sources": [], "chains": []},
                        "last_checked_version": "",
                    })
            data["class_coverage"] = cov

    return data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", help="filter to one binary (substring on YAML filename)")
    ap.add_argument("--promote", action="store_true", help="after enrichment, mv all _drafts/*.yml to binaries/")
    ap.add_argument("--dry-run", action="store_true", help="don't write files; just print what would change")
    ap.add_argument("--source", choices=["drafts", "binaries", "both"], default="both",
                    help="which dir to enrich (default both)")
    args = ap.parse_args()

    audit = load_audit_records()
    lib = load_defense_library()
    print(f"audit records: {len(audit)}; defense library classes: {len(lib.get('classes', []))}")

    targets = []
    if args.source in ("drafts", "both"):
        targets += sorted(DRAFTS.glob("*.yml"))
    if args.source in ("binaries", "both"):
        targets += sorted(BINARIES.glob("*.yml"))
    if args.binary:
        targets = [p for p in targets if args.binary.lower() in p.stem.lower()]

    enriched_count = 0
    skipped_count = 0
    promoted_count = 0
    for p in targets:
        before = load_yaml(p)
        after = enrich_one(p, audit, lib)
        # Did anything change?
        before_keys = set(before.keys())
        after_keys = set(after.keys())
        added_keys = after_keys - before_keys
        # Also check if we filled previously-empty arrays
        filled_arrays = []
        for k in ("sources", "sinks", "chains", "defenses", "class_coverage"):
            if not before.get(k) and after.get(k):
                filled_arrays.append(k)
        if not added_keys and not filled_arrays:
            skipped_count += 1
            continue

        if args.dry_run:
            print(f"WOULD enrich {p.relative_to(ROOT)}: +{added_keys} filled={filled_arrays}")
        else:
            write_yaml(p, after)
            enriched_count += 1
            print(f"enriched {p.relative_to(ROOT)}: +{added_keys} filled={filled_arrays}")

    if args.promote and not args.dry_run:
        BINARIES.mkdir(exist_ok=True)
        for p in sorted(DRAFTS.glob("*.yml")):
            data = load_yaml(p)
            # Only promote drafts that have at least sources or class_coverage populated
            if not (data.get("sources") or data.get("class_coverage")):
                continue
            target = BINARIES / p.name
            if target.exists():
                continue  # don't overwrite existing canonical entries
            shutil.move(str(p), str(target))
            promoted_count += 1
            print(f"promoted {p.name} -> binaries/")

    print(f"\nenriched: {enriched_count}, skipped (already populated): {skipped_count}, promoted: {promoted_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
