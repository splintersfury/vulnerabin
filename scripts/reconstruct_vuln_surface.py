#!/usr/bin/env python3
"""Vuln-surface extractor from a reconstructed binary manifest.

Reads `catalog/reconstructed/<stem>_<tag>/manifest.json` and classifies its
named functions (from `passes[].proposed_renames` plus originally-named
non-FUN_* functions) into vuln-research categories:

- ipc_source          (handler / dispatcher / receiver / parser of external input)
- file_source         (file reads, config loads, JSON/XML parsers)
- registry_source     (registry reads, setting loads)
- trust_boundary      (is_trusted / verify_ / check_ / authenticate — bug goldmine)
- defense             (sanitize / normalize / canonicalize — bypass targets)
- crypto              (encrypt / decrypt / sign / hash / authenticode)
- process_sink        (CreateProcess / spawn / exec / start_service / launch)
- file_write_sink     (write / save / create file / set attrs)
- registry_write_sink (write registry / set value / install_*)
- dll_load_sink       (LoadLibrary / load_dll / resolve_export — LPE classic)
- privilege_sink      (install_service / register_service / install_certificate)
- path_handling       (sanitize_path / env_var — junction-LPE candidates)

Output is a markdown report at
`catalog/reconstructed/<stem>_<tag>/vuln_surface.md` plus a JSON sidecar
`vuln_surface.json` for downstream consumers (e.g. the existing walk phase
or catalog_re_extract).

This is the bridge from reconstruction → vuln hunting. A researcher running
the full pipeline (vb-add → reconstruct.py → pass1_batch → workers →
pass1_apply → THIS) gets a prioritized attack-surface list to start
chain-building from.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)

# Each category: list of (regex_pattern, weight) — weight is the priority
# for ranking within the category. Higher weights surface first.
# Patterns match against `to_lower` (the post-rename name lowercased).
_CATEGORIES: dict[str, list[tuple[str, int]]] = {
    "trust_boundary": [
        (r"is_trusted|is_authorized|is_valid", 10),
        (r"verify_signature|verify_authenticode|verify_certificate", 10),
        (r"check_signature|check_certificate|check_token", 9),
        (r"validate_caller|authenticate|authorize", 9),
        (r"verify_|validate_", 6),
        (r"check_permission|check_acl|check_dacl", 8),
    ],
    "ipc_source": [
        (r"on_control_handler|servicehandler|service_control", 10),
        (r"on_request|on_message|on_command|dispatch_command", 10),
        (r"pipe_handler|pipe_receive|named_pipe", 9),
        (r"ipc_|message_handler|command_handler|request_handler", 8),
        (r"parse_request|parse_message|parse_header", 7),
        (r"dispatch_|handler$", 6),
        (r"receive_|recv_", 5),
    ],
    "file_source": [
        (r"read_config|load_config|parse_config", 9),
        (r"parse_json|parse_xml|parse_yaml|parse_ini", 8),
        (r"read_file|open_file_read|load_file", 7),
        (r"parse_file|fopen|fread", 5),
    ],
    "registry_source": [
        (r"read_registry|get_reg_value|query_registry", 8),
        (r"load_setting|get_setting|read_config_key", 7),
    ],
    "defense": [
        (r"sanitize_path|sanitize_input|normalize_path|canonicalize_path", 10),
        (r"sanitize_|normalize_|canonicalize_|escape_", 7),
        (r"strip_|filter_", 5),
    ],
    "crypto": [
        (r"authenticode|wintrust|cryptverify", 8),
        (r"encrypt_|decrypt_|aes_|rsa_", 7),
        (r"sign_|verify_signature|hash_", 6),
    ],
    "process_sink": [
        (r"create_process_as|spawn_as|run_as_system", 10),
        (r"create_process|spawn_|exec_|launch_", 9),
        (r"start_service|start_process|run_command", 7),
        (r"system_call|popen", 6),
    ],
    "file_write_sink": [
        (r"write_file|save_file|create_file_write", 7),
        (r"set_file_attribute|set_file_security|set_file_acl", 8),
        (r"fwrite|fputs", 4),
    ],
    "registry_write_sink": [
        (r"write_registry|set_reg_value|create_reg_key", 8),
        (r"set_setting|update_config_key", 6),
        (r"install_setting|persist_", 6),
    ],
    "dll_load_sink": [
        (r"load_library|loadlibrary|load_dll", 9),
        (r"resolve_export|getprocaddress|get_proc_address", 7),
        (r"load_module|map_module", 6),
    ],
    "privilege_sink": [
        (r"install_service|create_service|register_service", 9),
        (r"install_certificate|install_cert|register_cert", 9),
        (r"change_service_config|set_service_security", 8),
        (r"install_driver|load_driver|register_driver", 9),
        (r"impersonate_|set_token|duplicate_token", 8),
        (r"install_|register_", 4),
    ],
    "path_handling": [
        (r"env_var|env_path|sanitize_path_env", 8),
        (r"resolve_path|expand_path|get_full_path", 6),
        (r"join_path|build_path|construct_path", 5),
    ],
}


def _named_functions(manifest: dict, function_index: dict | None = None) -> list[dict]:
    """Return a list of (addr, effective_name, source, confidence) records
    for every named function (originally-named OR renamed).
    """
    out: list[dict] = []
    seen: set[str] = set()

    # First: all proposed_renames from any pass.
    for p in manifest.get("passes", []):
        which = p.get("pass")
        for rec in p.get("proposed_renames", []) or []:
            addr = rec.get("addr")
            to = rec.get("to")
            if not addr or not to or addr in seen:
                continue
            seen.add(addr)
            out.append({
                "addr": addr,
                "name": to,
                "from_name": rec.get("from", ""),
                "source": rec.get("source", ""),
                "confidence": rec.get("confidence", ""),
                "pass": which,
                "rationale": rec.get("rationale", ""),
            })

    # Second: originally-named user-defined functions from function_index
    # (those that survived as semantic names without any pass renaming them).
    if function_index:
        fun_re = re.compile(r"^FUN_[0-9a-fA-F]+$")
        for f in function_index.get("functions", []):
            if f.get("is_external") or f.get("is_thunk"):
                continue
            name = f.get("name") or ""
            if not name or fun_re.match(name):
                continue
            addr = f.get("address")
            if not addr or addr in seen:
                continue
            seen.add(addr)
            out.append({
                "addr": addr,
                "name": name,
                "from_name": name,
                "source": "ghidra_original",
                "confidence": "n/a",
                "pass": None,
                "rationale": "",
            })
    return out


def classify_function(name: str) -> list[tuple[str, int, str]]:
    """Return all (category, weight, matched_pattern) triples that match `name`.

    A function may match multiple categories (e.g. a function with both
    "verify_signature" and "load_library" in its name). Returns sorted
    by descending weight.
    """
    lname = name.lower()
    matches: list[tuple[str, int, str]] = []
    for category, patterns in _CATEGORIES.items():
        for pat, weight in patterns:
            if re.search(pat, lname):
                matches.append((category, weight, pat))
                break   # first hit per category is enough
    matches.sort(key=lambda m: -m[1])
    return matches


def build_surface(manifest: dict, function_index: dict | None = None) -> dict:
    """Build the vuln-surface classification result."""
    named = _named_functions(manifest, function_index)
    classified: dict[str, list[dict]] = {c: [] for c in _CATEGORIES}
    unclassified: list[dict] = []

    for rec in named:
        matches = classify_function(rec["name"])
        if not matches:
            unclassified.append(rec)
            continue
        for category, weight, pattern in matches:
            entry = dict(rec)
            entry["category"] = category
            entry["weight"] = weight
            entry["matched_pattern"] = pattern
            classified[category].append(entry)

    # Sort each category by weight descending, then by name.
    for category in classified:
        classified[category].sort(key=lambda r: (-r["weight"], r["name"]))

    summary = {
        category: len(rs) for category, rs in classified.items() if rs
    }
    return {
        "summary": summary,
        "classified": classified,
        "unclassified_count": len(unclassified),
        "total_named": len(named),
    }


# Ordering used for the markdown report — highest vuln-research priority first.
_CATEGORY_ORDER = [
    "trust_boundary",
    "ipc_source",
    "privilege_sink",
    "process_sink",
    "dll_load_sink",
    "path_handling",
    "defense",
    "file_source",
    "registry_source",
    "registry_write_sink",
    "file_write_sink",
    "crypto",
]

_CATEGORY_BLURB = {
    "trust_boundary":      "Trust/auth/verify checks — bypass these and the rest doesn't matter. Top priority for vuln research.",
    "ipc_source":          "External-input entry points. Track every byte of caller-controlled data from here.",
    "privilege_sink":      "Privileged operations — service/cert/driver install. Hit these via IPC and you have an LPE.",
    "process_sink":        "Process creation. Path-injection or token-confusion here = code exec as the service principal.",
    "dll_load_sink":       "DLL load surface. Classic LPE vector if any load path is attacker-controllable.",
    "path_handling":       "Path resolution / env var manipulation — junction-LPE candidates.",
    "defense":             "Sanitization / canonicalization — bypass these and the sinks become reachable.",
    "file_source":         "File-content sources. Look for parser bugs (JSON/XML) and unbounded copies.",
    "registry_source":     "Registry-controlled inputs. Often used to configure behavior an attacker can influence.",
    "registry_write_sink": "Persistence sinks. Useful for chains that survive reboot or escalate later.",
    "file_write_sink":     "File-write sinks. Look at path control + content control independently.",
    "crypto":              "Crypto surface — replay, signature bypass, downgrade.",
}


def render_markdown(surface: dict, manifest: dict) -> str:
    binary = manifest.get("binary", {})
    out: list[str] = []
    out.append(f"# Vuln-research attack surface — {binary.get('stem')} @ {binary.get('version_tag')}\n")
    out.append(f"**Status:** `{binary.get('status', 'unknown')}`\n")
    out.append(f"**Total named functions:** {surface['total_named']}  ")
    out.append(f"**Classified:** {surface['total_named'] - surface['unclassified_count']}  ")
    out.append(f"**Unclassified:** {surface['unclassified_count']}\n")

    out.append("\n## Summary by category\n")
    out.append("| Category | Count | What to do with these |")
    out.append("|---|---:|---|")
    for cat in _CATEGORY_ORDER:
        n = surface["summary"].get(cat, 0)
        if not n:
            continue
        out.append(f"| **{cat}** | {n} | {_CATEGORY_BLURB[cat]} |")

    out.append("\n---\n")

    # Per-category tables, ordered by research priority.
    for cat in _CATEGORY_ORDER:
        rs = surface["classified"].get(cat, [])
        if not rs:
            continue
        out.append(f"\n## {cat} ({len(rs)})\n")
        out.append(f"_{_CATEGORY_BLURB[cat]}_\n")
        out.append("| Addr | Name | W | Source | Confidence | Rationale |")
        out.append("|---|---|---:|---|---|---|")
        for r in rs:
            rat = (r["rationale"] or "").replace("|", "\\|")
            if len(rat) > 100:
                rat = rat[:97] + "..."
            out.append(
                f"| `{r['addr']}` | `{r['name']}` | {r['weight']} | "
                f"{r['source']} | {r['confidence']} | {rat} |"
            )

    out.append("\n---\n")
    out.append("## How to use this report\n")
    out.append(
        "1. Start with `trust_boundary` — these are functions whose JOB is to enforce a policy. "
        "Any bypass becomes a bug regardless of what's downstream.\n"
        "2. Map `ipc_source` -> (intermediate calls) -> `privilege_sink` / `process_sink` / `dll_load_sink` "
        "to find privilege-elevation chains. Each chain is a source→sink candidate.\n"
        "3. Read the rationale strings — they cite the concrete signal the LLM rename worker found. "
        "That signal is your starting point for ACID analysis.\n"
        "4. Pair this report with the engagement's decomp .c files for body-level review of any function "
        "that looks promising.\n"
        "5. Functions surfaced here whose names start with `vb_` came from LLM passes — confidence levels "
        "matter; treat `low` as 'still worth checking but suspect the name'.\n"
    )

    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, help="Binary stem (matches catalog/binaries/<stem>.yml)")
    ap.add_argument("--version", required=True, help="Version tag")
    ap.add_argument("--engagement", default=None,
                    help="Engagement slug to also pull originally-named functions from "
                         "(optional but recommended for completeness)")
    ap.add_argument("--decomp-dir", default="decomp",
                    help="Decomp subdir under engagement (default: 'decomp')")
    args = ap.parse_args(argv)

    recon_dir = ROOT / "catalog" / "reconstructed" / f"{args.binary}_{args.version}"
    manifest_path = recon_dir / "manifest.json"
    if not manifest_path.is_file():
        print(f"error: manifest.json missing at {manifest_path}", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text())

    function_index = None
    if args.engagement:
        fi_path = ROOT / "engagements" / args.engagement / args.decomp_dir / "function_index.json"
        if fi_path.is_file():
            function_index = json.loads(fi_path.read_text())

    surface = build_surface(manifest, function_index)
    md = render_markdown(surface, manifest)

    out_md = recon_dir / "vuln_surface.md"
    out_json = recon_dir / "vuln_surface.json"
    out_md.write_text(md)
    out_json.write_text(json.dumps(surface, indent=2))

    print(f"wrote {out_md.relative_to(ROOT)}")
    print(f"wrote {out_json.relative_to(ROOT)}")
    print()
    print("Summary by category (vuln-research priority):")
    for cat in _CATEGORY_ORDER:
        n = surface["summary"].get(cat, 0)
        if n:
            print(f"  {cat:24s} {n:4d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
