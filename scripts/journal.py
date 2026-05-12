#!/usr/bin/env python3
"""Append-only execution journal for vulnerabin engagements.

Each engagement gets `engagements/<id>/journal.jsonl`. Entries are linked by a
parent-sha chain so tampering is detectable and replay is deterministic.

Schema (one JSON object per line):
    {
      "sha":     <16-hex chain id of this event>,
      "parent":  <sha of prior event in this engagement, or null for the first>,
      "ts":      <ISO-8601 UTC>,
      "phase":   acquisition|preparation|triage|deep|validation|exec|report|kb|meta,
      "actor":   human|opus|sonnet|haiku|opencode|script:<name>,
      "event":   phase_start|phase_end|artifact|finding|decision|exec_result|note,
      "ref":     <relative path to artifact, or null>,
      "summary": <=240 chars,
      "meta":    {...}
    }

Library:
    from journal import append, tail, iter_events, current_state, append_if_engagement

CLI:
    journal.py append    <eng> --phase X --actor Y --event Z --summary "..."
                                [--ref PATH] [--meta KEY=VAL ...]
    journal.py view      <eng> [--phase X] [--actor Y] [--since ISO] [--last N]
    journal.py replay    <eng>            # derived state summary
    journal.py validate  <eng>            # check chain integrity

Legacy-safety: scripts that want to opt in without changing default behavior
should call `append_if_engagement(...)` which is a no-op unless
`VULNERABIN_JOURNAL=1` is set.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parent.parent
ENG_ROOT = ROOT / "engagements"

PHASES = {"acquisition", "preparation", "reconstruct", "comprehend", "triage", "deep",
          "validation", "exec", "report", "kb", "meta"}
EVENTS = {"phase_start", "phase_end", "artifact", "finding", "decision",
          "exec_result", "note"}
SUMMARY_MAX = 240


def _journal_path(eng_id: str) -> Path:
    return ENG_ROOT / eng_id / "journal.jsonl"


def _now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def _compute_sha(event_no_sha: dict) -> str:
    return hashlib.sha256(_canonical(event_no_sha).encode()).hexdigest()[:16]


def _last_sha(path: Path) -> str | None:
    if not path.is_file():
        return None
    last = None
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if not last:
        return None
    return json.loads(last).get("sha")


def append(
    engagement_id: str,
    *,
    phase: str,
    actor: str,
    event: str,
    summary: str,
    ref: str | None = None,
    meta: dict | None = None,
) -> str:
    """Append one event to an engagement's journal. Returns the event sha."""
    if phase not in PHASES:
        raise ValueError(f"unknown phase: {phase} (allowed: {sorted(PHASES)})")
    if event not in EVENTS:
        raise ValueError(f"unknown event: {event} (allowed: {sorted(EVENTS)})")
    if len(summary) > SUMMARY_MAX:
        raise ValueError(f"summary >{SUMMARY_MAX} chars; truncate or move detail to ref/meta")

    eng_dir = ENG_ROOT / engagement_id
    if not eng_dir.is_dir():
        raise FileNotFoundError(f"engagement not found: {eng_dir}")

    path = _journal_path(engagement_id)
    parent = _last_sha(path)

    event_no_sha = {
        "parent": parent,
        "ts": _now_utc(),
        "phase": phase,
        "actor": actor,
        "event": event,
        "ref": ref,
        "summary": summary,
        "meta": meta or {},
    }
    sha = _compute_sha(event_no_sha)
    record = {"sha": sha, **event_no_sha}

    with path.open("a") as f:
        f.write(_canonical(record) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return sha


def append_if_engagement(engagement_id: str, **kwargs) -> str | None:
    """No-op unless VULNERABIN_JOURNAL=1. Use from existing scripts."""
    if os.environ.get("VULNERABIN_JOURNAL") != "1":
        return None
    try:
        return append(engagement_id, **kwargs)
    except Exception as e:
        # Never break a host script because the journal failed
        print(f"[journal] WARN: append failed: {e}", file=sys.stderr)
        return None


def iter_events(engagement_id: str) -> Iterator[dict]:
    path = _journal_path(engagement_id)
    if not path.is_file():
        return
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def tail(engagement_id: str, n: int = 20) -> list[dict]:
    return list(iter_events(engagement_id))[-n:]


def current_state(engagement_id: str) -> dict:
    """Replay-derived summary: current phase, last actor, counts by phase/event,
    findings touched, exec results."""
    counts_phase: dict = {}
    counts_event: dict = {}
    findings: list[str] = []
    exec_results: list[dict] = []
    last_phase = None
    last_event = None
    last_actor = None
    last_ts = None
    n = 0

    for ev in iter_events(engagement_id):
        n += 1
        p = ev.get("phase")
        e = ev.get("event")
        counts_phase[p] = counts_phase.get(p, 0) + 1
        counts_event[e] = counts_event.get(e, 0) + 1
        if e == "phase_start":
            last_phase = p
        if e == "finding" and ev.get("ref"):
            findings.append(ev["ref"])
        if e == "exec_result":
            exec_results.append({
                "ref": ev.get("ref"),
                "verdict": (ev.get("meta") or {}).get("verdict"),
                "summary": ev.get("summary"),
            })
        last_event = e
        last_actor = ev.get("actor")
        last_ts = ev.get("ts")

    return {
        "engagement": engagement_id,
        "events_total": n,
        "current_phase": last_phase,
        "last_event": last_event,
        "last_actor": last_actor,
        "last_ts": last_ts,
        "counts_by_phase": counts_phase,
        "counts_by_event": counts_event,
        "findings_touched": sorted(set(findings)),
        "exec_results": exec_results,
    }


def validate(engagement_id: str) -> tuple[bool, list[str]]:
    errs: list[str] = []
    prev_sha: str | None = None
    for i, ev in enumerate(iter_events(engagement_id)):
        # parent link
        if ev.get("parent") != prev_sha:
            errs.append(f"event #{i}: parent={ev.get('parent')} expected {prev_sha}")
        # sha integrity
        no_sha = {k: v for k, v in ev.items() if k != "sha"}
        recomputed = _compute_sha(no_sha)
        if recomputed != ev.get("sha"):
            errs.append(f"event #{i}: sha mismatch (stored={ev.get('sha')} recomputed={recomputed})")
        prev_sha = ev.get("sha")
    return (not errs, errs)


# ---- CLI ---------------------------------------------------------------------

def _parse_meta(items: list[str]) -> dict:
    out: dict = {}
    for it in items or []:
        if "=" not in it:
            raise SystemExit(f"--meta expects KEY=VAL, got: {it}")
        k, v = it.split("=", 1)
        # Best-effort typed parse: int, float, bool, json, else str
        try:
            out[k] = json.loads(v)
        except Exception:
            out[k] = v
    return out


def _cmd_append(a) -> int:
    sha = append(
        a.engagement,
        phase=a.phase,
        actor=a.actor,
        event=a.event,
        summary=a.summary,
        ref=a.ref,
        meta=_parse_meta(a.meta),
    )
    print(sha)
    return 0


def _cmd_view(a) -> int:
    events = list(iter_events(a.engagement))
    if a.phase:
        events = [e for e in events if e.get("phase") == a.phase]
    if a.actor:
        events = [e for e in events if e.get("actor") == a.actor]
    if a.since:
        events = [e for e in events if e.get("ts", "") >= a.since]
    if a.last:
        events = events[-a.last:]
    for e in events:
        ts = e.get("ts", "")
        ph = e.get("phase", "")
        ac = e.get("actor", "")
        ev = e.get("event", "")
        ref = e.get("ref") or "-"
        sm = e.get("summary", "")
        print(f"{ts}  {ph:12s} {ac:14s} {ev:12s} {ref}  {sm}")
    return 0


def _cmd_replay(a) -> int:
    print(json.dumps(current_state(a.engagement), indent=2))
    return 0


def _cmd_validate(a) -> int:
    ok, errs = validate(a.engagement)
    if ok:
        print(f"OK: {a.engagement}")
        return 0
    print(f"INVALID: {a.engagement}", file=sys.stderr)
    for e in errs:
        print(f"  {e}", file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("append")
    sp.add_argument("engagement")
    sp.add_argument("--phase", required=True, choices=sorted(PHASES))
    sp.add_argument("--actor", required=True)
    sp.add_argument("--event", required=True, choices=sorted(EVENTS))
    sp.add_argument("--summary", required=True)
    sp.add_argument("--ref")
    sp.add_argument("--meta", action="append", default=[],
                    help="KEY=VAL (repeatable; values parsed as JSON when possible)")
    sp.set_defaults(func=_cmd_append)

    vp = sub.add_parser("view")
    vp.add_argument("engagement")
    vp.add_argument("--phase", choices=sorted(PHASES))
    vp.add_argument("--actor")
    vp.add_argument("--since", help="ISO-8601 lower bound, e.g. 2026-05-01T00:00:00Z")
    vp.add_argument("--last", type=int)
    vp.set_defaults(func=_cmd_view)

    rp = sub.add_parser("replay")
    rp.add_argument("engagement")
    rp.set_defaults(func=_cmd_replay)

    val = sub.add_parser("validate")
    val.add_argument("engagement")
    val.set_defaults(func=_cmd_validate)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
