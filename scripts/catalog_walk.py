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


def _stake_gated(payload: dict) -> tuple[bool, str]:
    reasons = []
    sev = (payload.get("severity_ceiling") or "").lower()
    if sev in ("high", "critical"):
        reasons.append(f"severity={payload['severity_ceiling']}")
    if payload.get("cwe"):
        reasons.append(f"cwe={','.join(payload['cwe'])}")
    if payload.get("product_feature_id"):
        reasons.append("product_feature_id-set")
    if (payload.get("confidence") or "").lower() == "low":
        reasons.append("confidence=low")
    return (bool(reasons), ",".join(reasons))


def cmd_confirm(args) -> int:
    p, data = _load_binary(args.binary)
    feat = None
    items = _stage_items(data, "2c-features")
    for it in items:
        if it.get("id") == args.id:
            feat = it
            break
    if feat is None:
        print(f"id not found in features: {args.id}", file=sys.stderr)
        return 1

    payload = {
        "description": args.description,
        "cwe": [c.strip() for c in (args.cwe or "").split(",") if c.strip()],
        "severity_ceiling": args.severity_ceiling or "",
        "product_feature_id": args.product_feature_id or "",
        "confidence": args.confidence or "",
        "user_observable": args.user_observable or "",
        "capabilities": [c.strip() for c in (args.capabilities or "").split(",") if c.strip()],
        "sources": [c.strip() for c in (args.sources or "").split(",") if c.strip()],
        "inputs": [c.strip() for c in (args.inputs or "").split(",") if c.strip()],
    }

    needs_review, trigger = _stake_gated(payload)
    review_data = None
    if needs_review:
        if not args.review_verdict:
            print(f"stake-gated confirm requires --review-verdict (triggers: {trigger})",
                  file=sys.stderr)
            return 1
        rp = Path(args.review_verdict)
        if not rp.exists():
            print(f"review verdict file not found: {rp}", file=sys.stderr)
            return 1
        try:
            review_data = json.loads(rp.read_text())
        except json.JSONDecodeError as e:
            print(f"review verdict not valid JSON: {e}", file=sys.stderr)
            return 1
        if review_data.get("verdict") != "ship":
            print(f"review verdict is {review_data.get('verdict')!r}; not confirming",
                  file=sys.stderr)
            return 1
        if review_data.get("candidate_id") and review_data["candidate_id"] != args.id:
            print(f"review verdict is for {review_data.get('candidate_id')}, not {args.id}",
                  file=sys.stderr)
            return 1

    feat["confirmed"] = True
    feat["rejected"] = False
    if payload["description"]:
        feat["description"] = payload["description"]
    for k in ("severity_ceiling", "product_feature_id", "user_observable", "confidence"):
        if payload[k]:
            feat[k] = payload[k]
    if payload["cwe"]:
        feat["cwe"] = payload["cwe"]
    for k in ("capabilities", "sources", "inputs"):
        if payload[k]:
            feat[k] = payload[k]

    cr = feat.setdefault("confirmation_review", {})
    cr["required"] = needs_review
    cr["agent_id"] = args.inspect_worker
    cr["reviewed_at"] = _now()
    cr["trigger_reason"] = trigger
    if review_data:
        cr["reviewed_by"] = review_data.get("agent_id", "")
        cr["verdict"] = "ship"
        cr["artifact_path"] = str(rp)
    else:
        cr["reviewed_by"] = ""
        cr["verdict"] = "auto-confirm"
        cr["artifact_path"] = ""

    # Reverse-pointer backfill: append FEAT-id to capabilities[].feature_ids etc.
    for cap_id in payload["capabilities"]:
        for cap in data.get("capabilities") or []:
            if cap.get("id") == cap_id:
                fids = cap.setdefault("feature_ids", [])
                if args.id not in fids:
                    fids.append(args.id)
    for src_id in payload["sources"]:
        for src in data.get("sources") or []:
            if src.get("id") == src_id:
                fids = src.setdefault("feature_ids", [])
                if args.id not in fids:
                    fids.append(args.id)
    for inp_id in payload["inputs"]:
        re_block = data.setdefault("reverse_engineering", {})
        for inp in re_block.get("inputs") or []:
            if inp.get("id") == inp_id:
                fids = inp.setdefault("feature_ids", [])
                if args.id not in fids:
                    fids.append(args.id)

    _save_binary(p, data)
    return 0


def cmd_inspect(args) -> int:
    _, data = _load_binary(args.binary)
    for stage in STAGE_KEY_MAP:
        for it in _stage_items(data, stage):
            if it.get("id") == args.id:
                if args.json:
                    print(json.dumps(it, indent=2))
                else:
                    print(yaml.safe_dump(it, sort_keys=False))
                return 0
    print(f"id not found: {args.id}", file=sys.stderr)
    return 1


def cmd_refresh(args) -> int:
    if args.dry_run:
        print(f"(dry-run) would re-run detector framework against {args.binary}")
        return 0
    # Real run: import process_features and apply.
    sys.path.insert(0, str(Path(__file__).parent))
    import importlib.util
    re_path = Path(__file__).parent / "catalog_re_extract.py"
    spec = importlib.util.spec_from_file_location("catalog_re_extract", re_path)
    if spec is None or spec.loader is None:
        print("could not import catalog_re_extract", file=sys.stderr)
        return 1
    mod = importlib.util.module_from_spec(spec)
    sys.modules["catalog_re_extract"] = mod
    spec.loader.exec_module(mod)

    p, data = _load_binary(args.binary)
    # Build a minimal DetectorContext: function_index from existing
    # reverse_engineering, decomp_dir from coverage[].decomp_dirs[0] if any.
    from feat_detectors.base import DetectorContext  # type: ignore
    fi = data.get("reverse_engineering", {}) or {}
    coverage = data.get("coverage") or {}
    decomp_dirs = coverage.get("decomp_dirs") or []
    decomp_dir = Path(decomp_dirs[0]) if decomp_dirs else None
    ctx = DetectorContext(
        binary_path=Path(data.get("canonical_path") or ""),
        decomp_dir=decomp_dir,
        function_index=fi,
        chains=None,
        re_block=fi,
        existing_yaml=data,
    )
    out = mod.process_features(data, ctx)
    _save_binary(p, out)
    print(f"refreshed; features now: {len(out.get('features', []))}")
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

    sp = sub.add_parser("confirm", help="confirm a feature (gate-checked)")
    sp.add_argument("binary")
    sp.add_argument("id")
    sp.add_argument("--description", default="")
    sp.add_argument("--cwe", default="")
    sp.add_argument("--severity-ceiling", default="")
    sp.add_argument("--product-feature-id", default="")
    sp.add_argument("--confidence", default="")
    sp.add_argument("--user-observable", default="")
    sp.add_argument("--capabilities", default="")
    sp.add_argument("--sources", default="")
    sp.add_argument("--inputs", default="")
    sp.add_argument("--inspect-worker", required=True)
    sp.add_argument("--review-verdict", default="")
    sp.set_defaults(func=cmd_confirm)

    sp = sub.add_parser("inspect", help="full context for one candidate")
    sp.add_argument("binary")
    sp.add_argument("id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_inspect)

    sp = sub.add_parser("refresh", help="re-run detectors against this binary")
    sp.add_argument("binary")
    sp.add_argument("--dry-run", action="store_true")
    sp.set_defaults(func=cmd_refresh)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
