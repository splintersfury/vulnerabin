#!/usr/bin/env python3
"""vb walk — drive the FEAT walk pipeline (stages 2a → 2b → 2c).

Subcommands:
  status      <binary>             — current stage + pending counts (JSON-friendly)
  pending     <binary> --stage S   — list pending candidates for a stage
  inspect     <binary> <id>        — full context for one candidate
  confirm     <binary> <id> ...    — apply a confirm decision (gate-checked)
  reject      <binary> <id> --reason ...  — apply a reject decision
  close-stage <binary> --stage S   — close a stage (refuses if pending > 0)
  refresh     <binary>             — re-run detectors mid-walk

CWD must contain catalog/binaries/<binary>.yml. Falls back to the global
catalog under the script's repo root if `./catalog/` is absent.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml


def _catalog_dir() -> Path:
    """Resolve catalog/binaries — local CWD wins, repo root is fallback."""
    here = Path.cwd() / "catalog" / "binaries"
    if here.is_dir():
        return here
    return Path(__file__).resolve().parent.parent / "catalog" / "binaries"


def _load_binary(name: str) -> tuple[Path, dict[str, Any]]:
    cdir = _catalog_dir()
    p = cdir / f"{name}.yml"
    if not p.exists():
        raise SystemExit(f"binary YAML not found: {p}")
    return p, yaml.safe_load(p.read_text()) or {}


def _current_stage(walk_state: dict) -> str:
    stages = walk_state.get("stages") or {}
    for sname in ("2a-inputs", "2b-sinks", "2c-features"):
        s = stages.get(sname) or {}
        st = (s.get("status") or "").lower()
        if st == "open":
            return sname
    # If any stage is closed but the next is not_started, the next is the
    # implicit current. If all are closed, return done.
    closed = sum(
        1 for sname in ("2a-inputs", "2b-sinks", "2c-features")
        if ((stages.get(sname) or {}).get("status") or "").lower() == "closed"
    )
    if closed == 3:
        return "done"
    return "not_started"


def _pending_counts(yaml_data: dict) -> dict[str, int]:
    re_block = yaml_data.get("reverse_engineering") or {}
    inputs = re_block.get("inputs") or []
    sinks = yaml_data.get("sinks") or []
    features = yaml_data.get("features") or []

    def _unconfirmed(items: list) -> int:
        return sum(1 for it in items if not it.get("confirmed") and not it.get("rejected"))

    return {
        "inputs_unconfirmed": _unconfirmed(inputs),
        "sinks_unconfirmed": _unconfirmed(sinks),
        "features_unconfirmed": _unconfirmed(features),
    }


def cmd_status(args) -> int:
    _, data = _load_binary(args.binary)
    ws = data.get("walk_state") or {}
    out = {
        "binary": args.binary,
        "current_stage": _current_stage(ws),
        "pending_counts": _pending_counts(data),
    }
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"binary: {args.binary}")
        print(f"current stage: {out['current_stage']}")
        print(f"pending: {out['pending_counts']}")
    return 0


STAGE_KEY_MAP = {
    "2a-inputs":   ("reverse_engineering", "inputs"),
    "2b-sinks":    (None, "sinks"),
    "2c-features": (None, "features"),
}


def _stage_items(data: dict, stage: str) -> list:
    container, key = STAGE_KEY_MAP[stage]
    parent = data.get(container) if container else data
    if not isinstance(parent, dict):
        parent = {}
    return parent.get(key) or []


def _save_binary(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def cmd_pending(args) -> int:
    _, data = _load_binary(args.binary)
    items = _stage_items(data, args.stage)
    pending = [it for it in items if not it.get("confirmed") and not it.get("rejected")]
    if args.json:
        print(json.dumps(pending, indent=2))
    else:
        for it in pending:
            print(f"{it.get('id', '?')}: {it.get('slug') or it.get('name') or ''}")
    return 0


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def cmd_reject(args) -> int:
    p, data = _load_binary(args.binary)
    if not args.reason or len(args.reason.strip()) < 5:
        print("--reason must be at least 5 chars", file=sys.stderr)
        return 1
    found = False
    for stage in STAGE_KEY_MAP:
        items = _stage_items(data, stage)
        for it in items:
            if it.get("id") == args.id:
                it["rejected"] = True
                it["confirmed"] = False
                it["rejection_reason"] = args.reason.strip()
                it["rejected_at"] = _now()
                found = True
                break
        if found:
            break
    if not found:
        print(f"id not found: {args.id}", file=sys.stderr)
        return 1
    _save_binary(p, data)
    return 0


def cmd_close_stage(args) -> int:
    p, data = _load_binary(args.binary)
    items = _stage_items(data, args.stage)
    pending = [it for it in items if not it.get("confirmed") and not it.get("rejected")]
    if pending:
        print(f"refusing to close: {len(pending)} pending entries in {args.stage}",
              file=sys.stderr)
        return 1
    ws = data.setdefault("walk_state", {}).setdefault("stages", {})
    s = ws.setdefault(args.stage, {})
    s["status"] = "closed"
    s["closed_at"] = _now()
    history = data["walk_state"].setdefault("history", [])
    history.append({
        "stage": args.stage,
        "action": "closed",
        "at": s["closed_at"],
        "actor": "claude",
        "target": "",
        "reason": "",
        "confirmed": sum(1 for it in items if it.get("confirmed")),
        "rejected": sum(1 for it in items if it.get("rejected")),
    })
    _save_binary(p, data)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vb walk", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("status", help="show current stage + pending counts")
    sp.add_argument("binary")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("pending", help="list pending candidates for a stage")
    sp.add_argument("binary")
    sp.add_argument("--stage", required=True, choices=list(STAGE_KEY_MAP))
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_pending)

    sp = sub.add_parser("reject", help="reject a candidate")
    sp.add_argument("binary")
    sp.add_argument("id")
    sp.add_argument("--reason", required=True)
    sp.set_defaults(func=cmd_reject)

    sp = sub.add_parser("close-stage", help="close a stage (refuses with pending entries)")
    sp.add_argument("binary")
    sp.add_argument("--stage", required=True, choices=list(STAGE_KEY_MAP))
    sp.set_defaults(func=cmd_close_stage)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
