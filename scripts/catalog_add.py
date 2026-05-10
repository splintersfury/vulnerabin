#!/usr/bin/env python3
"""One-line incremental updates to a binary's catalog YAML.

Designed for the workflow where you're reversing in Ghidra (or running multi_run
lenses) and want to record a discovery without context-switching to a YAML editor.
The live FastAPI server (catalog_serve.py) reads YAML at request time, so a
browser refresh shows the new entry immediately.

Subcommands:
  sink       Add a sink (CWE + impact + callsite RVA)
  input      Add an input (kind + path + reachability)
  capability Add a capability (links to one or more sinks)
  chain      Link source -> capability or source -> sink with conditions
  source     Add a source linked back to an input via derived_from

Common flags:
  --binary   Binary YAML stem or filename (e.g. productagentservice_exe or ProductAgentService.exe)
  --confirm  Mark the new entry confirmed=true (default: candidate)
  --note     Free-form note appended to the entry

Examples:
  # Add a sink discovered while decompiling
  vb-add sink --binary productagentservice_exe \\
      --name CreateProcessAsUserW --addr 0x140012a0 --function vb_spawn_helper \\
      --cwe CWE-269 --impact "SYSTEM code exec via attacker-controlled image path"

  # Add an input observed via ProcMon
  vb-add input --binary productagentservice_exe \\
      --kind ipc_pipe --path '\\\\.\\pipe\\BdAg' \\
      --attacker-reachable low_priv_user --reachability "DACL allows Authenticated Users"

  # Group sinks into a capability
  vb-add capability --binary productagentservice_exe \\
      --name "Spawn process as SYSTEM" --sinks SNK-005,SNK-009 \\
      --user-action "Send IPC message with type=spawn"

  # Build a chain
  vb-add chain --binary productagentservice_exe \\
      --source SRC-001 --capability CAP-001 --status hypothesised \\
      --condition "DACL on \\\\.\\pipe\\BdAg permits low-priv connect" \\
      --condition "Dispatch table routes type=spawn to vb_spawn_helper without auth check"
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ROOT / "catalog" / "binaries"


def yaml_path_for(binary: str) -> Path:
    """Accept either 'productagentservice_exe' (stem) or 'ProductAgentService.exe' (filename)."""
    if binary.endswith(".yml"):
        return BINARIES / binary
    # Treat as filename or stem
    if "." in binary:
        # filename: convert to stem
        stem = re.sub(r"[^A-Za-z0-9]+", "_", binary.lower()).strip("_")
        return BINARIES / f"{stem}.yml"
    return BINARIES / f"{binary}.yml"


def load_yaml(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"ERROR: YAML not found: {path}. Run catalog_seed.py / catalog_re_extract.py first.")
    return yaml.safe_load(path.read_text()) or {}


def save_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False, width=120, allow_unicode=True))


def next_id(items: list[dict], prefix: str) -> str:
    used = {it.get("id") for it in items if it.get("id")}
    n = 1
    while True:
        cand = f"{prefix}-{n:03d}"
        if cand not in used:
            return cand
        n += 1


def stamp_note(note: str | None) -> str:
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    if note:
        return f"[{when}] {note}"
    return f"[{when}] added via catalog_add"


# ---------------------------------------------------------------------------
def cmd_sink(args):
    path = yaml_path_for(args.binary)
    data = load_yaml(path)
    sinks = data.setdefault("sinks", [])
    # Detect category from name if not given
    category = args.category
    if not category:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from catalog_re_extract import API_TO_CATEGORY
            category = API_TO_CATEGORY.get(args.name, "")
        except Exception:
            pass
    new_id = next_id(sinks, "SNK")
    entry = {
        "id": new_id,
        "name": args.name,
        "category": category or "",
        "callsites": [{"addr": args.addr or "", "function": args.function or ""}] if (args.addr or args.function) else [],
        "cwe": args.cwe or "",
        "function": args.function or "",
        "impact": args.impact or "",
        "confirmed": bool(args.confirm),
        "notes": stamp_note(args.note),
    }
    sinks.append(entry)
    save_yaml(path, data)
    print(f"+ {new_id}  {args.name}  ({path.name})")


def cmd_input(args):
    path = yaml_path_for(args.binary)
    data = load_yaml(path)
    re_block = data.setdefault("reverse_engineering", {})
    inputs = re_block.setdefault("inputs", [])
    new_id = next_id(inputs, "INP")
    entry = {
        "id": new_id,
        "kind": args.kind,
        "path": args.path,
        "direction": args.direction or ("in" if args.kind in ("ioctl", "ipc_pipe", "ipc_alpc", "ipc_msgbus", "rpc", "scm_control", "network_listen") else "read"),
        "attacker_reachable": args.attacker_reachable or "",
        "reachability": args.reachability or "",
        "notes": stamp_note(args.note),
    }
    inputs.append(entry)
    save_yaml(path, data)
    print(f"+ {new_id}  {args.kind}  {args.path}  ({path.name})")


def cmd_capability(args):
    path = yaml_path_for(args.binary)
    data = load_yaml(path)
    caps = data.setdefault("capabilities", [])
    new_id = next_id(caps, "CAP")
    sinks = [s.strip() for s in (args.sinks or "").split(",") if s.strip()]
    inputs = [s.strip() for s in (args.inputs or "").split(",") if s.strip()]
    entry = {
        "id": new_id,
        "name": args.name,
        "category": args.category or "",
        "sinks": sinks,
        "reachable_from": {"entry_funcs": [], "inputs": inputs},
        "user_action": args.user_action or "",
        "preconditions": [args.precondition] if args.precondition else [],
        "impact": args.impact or "",
        "confirmed": bool(args.confirm),
        "notes": stamp_note(args.note),
    }
    caps.append(entry)
    save_yaml(path, data)
    print(f"+ {new_id}  {args.name}  sinks={sinks}  ({path.name})")


def cmd_chain(args):
    path = yaml_path_for(args.binary)
    data = load_yaml(path)
    chains = data.setdefault("chains", [])
    new_id = next_id(chains, "CHAIN")
    entry = {
        "id": new_id,
        "title": args.title or f"{args.source} → {args.sink or args.capability}",
        "source_id": args.source,
        "sink_id": args.sink or "",
        "capability_id": args.capability or "",
        "conditions": list(args.condition or []),
        "impact": args.impact or "",
        "cwe": [args.cwe] if args.cwe else [],
        "severity": args.severity or "",
        "status": args.status or "hypothesised",
        "notes": stamp_note(args.note),
    }
    chains.append(entry)
    save_yaml(path, data)
    print(f"+ {new_id}  {entry['title']}  status={entry['status']}  ({path.name})")


def cmd_source(args):
    path = yaml_path_for(args.binary)
    data = load_yaml(path)
    sources = data.setdefault("sources", [])
    new_id = next_id(sources, "SRC")
    entry = {
        "id": new_id,
        "derived_from": args.from_input,
        "name": args.name,
        "source_class_id": args.class_id or "",
        "via": args.via or "",
        "function": args.function or "",
        "attacker_controlled": args.attacker_controlled or "yes",
        "notes": stamp_note(args.note),
    }
    sources.append(entry)
    save_yaml(path, data)
    print(f"+ {new_id}  derived_from={args.from_input}  {args.name}  ({path.name})")


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--binary", required=True, help="binary YAML stem or filename")
    common.add_argument("--note", help="free-form note (timestamp prepended automatically)")
    common.add_argument("--confirm", action="store_true", help="mark confirmed=true (default: candidate)")

    p_sink = sp.add_parser("sink", parents=[common], help="add a sink")
    p_sink.add_argument("--name", required=True, help="API name, e.g. CreateProcessAsUserW")
    p_sink.add_argument("--category", help="auto-detected from API library if omitted")
    p_sink.add_argument("--addr", help="callsite RVA, e.g. 0x140012a0")
    p_sink.add_argument("--function", help="containing function name, e.g. spawn_helper")
    p_sink.add_argument("--cwe", help="primary CWE")
    p_sink.add_argument("--impact", help="one-line impact")
    p_sink.set_defaults(func=cmd_sink)

    p_input = sp.add_parser("input", parents=[common], help="add an input")
    p_input.add_argument("--kind", required=True, help="ioctl|ipc_pipe|ipc_alpc|file_read|file_write|registry_read|...")
    p_input.add_argument("--path", required=True, help="endpoint path/identifier")
    p_input.add_argument("--direction", help="in|out|bidirectional|read|write")
    p_input.add_argument("--attacker-reachable", help="low_priv_user|admin|network_unauth|network_auth|no")
    p_input.add_argument("--reachability", help="paragraph: ACL state, default config, prereqs")
    p_input.set_defaults(func=cmd_input)

    p_cap = sp.add_parser("capability", parents=[common], help="add a capability")
    p_cap.add_argument("--name", required=True, help="user-facing capability name")
    p_cap.add_argument("--category", help="process_creation|file_io|registry_write|...")
    p_cap.add_argument("--sinks", help="comma-separated SNK-* IDs")
    p_cap.add_argument("--inputs", help="comma-separated INP-* IDs known to reach this capability")
    p_cap.add_argument("--user-action", help="plain-English: how a user triggers this")
    p_cap.add_argument("--precondition", help="single precondition (use multiple --precondition args is unsupported here; edit YAML for multiple)")
    p_cap.add_argument("--impact", help="one-line impact")
    p_cap.set_defaults(func=cmd_cap if False else cmd_capability)

    p_chain = sp.add_parser("chain", parents=[common], help="add a chain (source -> capability/sink)")
    p_chain.add_argument("--source", required=True, help="SRC-* ID")
    p_chain.add_argument("--sink", help="SNK-* ID (or use --capability)")
    p_chain.add_argument("--capability", help="CAP-* ID (or use --sink)")
    p_chain.add_argument("--title", help="short headline")
    p_chain.add_argument("--condition", action="append", help="add a condition (repeatable)")
    p_chain.add_argument("--impact", help="one-line impact")
    p_chain.add_argument("--cwe", help="primary CWE")
    p_chain.add_argument("--severity", help="P1..P5 / Critical/High/Medium/Low")
    p_chain.add_argument("--status", help="confirmed|partial|hypothesised|unexplored|mitigated", default="hypothesised")
    p_chain.set_defaults(func=cmd_chain)

    p_src = sp.add_parser("source", parents=[common], help="add a source linked to an input")
    p_src.add_argument("--name", required=True, help="short, e.g. 'IRP_MJ_DEVICE_CONTROL.AssociatedIrp.SystemBuffer'")
    p_src.add_argument("--from-input", required=True, help="INP-* ID this source derives from")
    p_src.add_argument("--class-id", help="taxonomy class (F-001, I-002, K-001, ...)")
    p_src.add_argument("--via", help="e.g. 'DeviceIoControl from user-mode'")
    p_src.add_argument("--function", help="containing function name")
    p_src.add_argument("--attacker-controlled", help="yes|yes_with_caveat|no", default="yes")
    p_src.set_defaults(func=cmd_source)

    args = ap.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
