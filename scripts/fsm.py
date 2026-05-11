#!/usr/bin/env python3
"""FSM helper for vulnerabin.

Reads pipeline.yml and the engagement's journal to answer:
  state    <eng>     -- what phase is the engagement in? what gates are unmet?
  next     <eng>     -- which phases are legal to enter next?
  validate <eng>     -- check all gate invariants

The FSM is a checklist consulted by the Strategist (interactive) and
orchestrate.py (headless). It does NOT execute phases.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIPELINE = ROOT / "pipeline.yml"
ENG_ROOT = ROOT / "engagements"
CATALOG_BINARIES = ROOT / "catalog" / "binaries"


def _check_walk_state_started() -> tuple[bool, str]:
    """True if at least one binary in catalog/binaries has 2a-inputs opened.

    Returns (ok, evidence_string).
    """
    try:
        import yaml as _y  # type: ignore
    except Exception as e:
        return False, f"PyYAML unavailable: {e}"
    if not CATALOG_BINARIES.is_dir():
        return False, "catalog/binaries/ not present"
    binary_yamls = list(CATALOG_BINARIES.glob("*.yml"))
    opened = 0
    for p in binary_yamls:
        try:
            d = _y.safe_load(p.read_text()) or {}
        except Exception:
            continue
        s = ((d.get("walk_state") or {}).get("stages") or {}).get("2a-inputs") or {}
        if s.get("opened_at"):
            opened += 1
    return opened > 0, f"{opened}/{len(binary_yamls)} binaries have 2a-inputs.opened_at"


def _check_walk_state_done() -> tuple[bool, str]:
    """True if every binary in catalog/binaries has all three stages closed."""
    try:
        import yaml as _y  # type: ignore
    except Exception as e:
        return False, f"PyYAML unavailable: {e}"
    if not CATALOG_BINARIES.is_dir():
        return False, "catalog/binaries/ not present"
    binary_yamls = list(CATALOG_BINARIES.glob("*.yml"))
    if not binary_yamls:
        return False, "no binaries in catalog/binaries/"
    closed = 0
    for p in binary_yamls:
        try:
            d = _y.safe_load(p.read_text()) or {}
        except Exception:
            return False, f"parse error on {p.name}"
        stages = ((d.get("walk_state") or {}).get("stages") or {})
        if all((stages.get(k) or {}).get("status") == "closed"
               for k in ("2a-inputs", "2b-sinks", "2c-features")):
            closed += 1
    return closed == len(binary_yamls), f"{closed}/{len(binary_yamls)} binaries fully closed"

# Reuse the tiny YAML loader from route_model
sys.path.insert(0, str(ROOT / "scripts"))
from route_model import _load_yaml  # type: ignore


def load_pipeline() -> dict:
    return _load_yaml(PIPELINE)


def _eng_dir(eng: str) -> Path:
    p = ENG_ROOT / eng
    if not p.is_dir():
        raise SystemExit(f"engagement not found: {p}")
    return p


def artifact_present(eng_dir: Path, ref: str) -> bool:
    """Check 'foo.json' (file) or 'foo/' (dir, must be non-empty)."""
    p = eng_dir / ref.rstrip("/")
    if ref.endswith("/"):
        return p.is_dir() and any(p.iterdir())
    return p.is_file()


def journal_events(eng: str) -> list[dict]:
    p = _eng_dir(eng) / "journal.jsonl"
    if not p.is_file():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def phase_completed(eng_dir: Path, phase: dict) -> bool:
    req = phase.get("produces_artifacts", [])
    any_req = phase.get("produces_artifacts_any", [])
    if req and not all(artifact_present(eng_dir, a) for a in req):
        return False
    if any_req and not any(artifact_present(eng_dir, a) for a in any_req):
        return False
    return bool(req or any_req)


def phase_entryable(eng_dir: Path, phase: dict) -> tuple[bool, list[str]]:
    missing: list[str] = []
    req = phase.get("requires_artifacts", [])
    any_req = phase.get("requires_artifacts_any", [])
    for a in req:
        if not artifact_present(eng_dir, a):
            missing.append(a)
    if any_req and not any(artifact_present(eng_dir, a) for a in any_req):
        missing.append(f"any of {any_req}")
    return (not missing, missing)


def gate_status(eng: str, eng_dir: Path, phase_name: str, phase_def: dict) -> list[dict]:
    """Best-effort gate check. Mostly reads journal for evidence."""
    events = journal_events(eng)
    out = []
    for g in phase_def.get("gates", []):
        gid = g.get("id")
        kind = g.get("kind", "post")
        ok = False
        evidence = ""

        if gid == "kb_prime":
            kb_events = [e for e in events
                         if e.get("phase") in (phase_name, "kb")
                         and "kb_query" in (e.get("summary", "") + (e.get("ref") or ""))]
            ok = bool(kb_events)
            evidence = f"{len(kb_events)} kb_query events"

        elif gid == "schema_valid":
            triage = eng_dir / "triage.json"
            if triage.is_file():
                try:
                    data = json.loads(triage.read_text())
                    rs = data.get("results", [])
                    has_reasoning = all("reasoning" in r for r in rs)
                    ok = has_reasoning and "engagement" in data
                    evidence = f"{len(rs)} rows, reasoning_present={has_reasoning}"
                except Exception as e:
                    evidence = f"parse error: {e}"

        elif gid == "acid_complete":
            findings = list((eng_dir / "findings").glob("*.md")) if (eng_dir / "findings").is_dir() else []
            with_acid = [f for f in findings if "ACID" in f.read_text() or "acid" in f.read_text()]
            ok = bool(findings) and len(with_acid) == len(findings)
            evidence = f"{len(with_acid)}/{len(findings)} findings have ACID block"

        elif gid == "aup_decomposed":
            poc_dirs = list((eng_dir / "pocs").iterdir()) if (eng_dir / "pocs").is_dir() else []
            decomposed = [d for d in poc_dirs if d.is_dir() and any(d.glob("step_*"))]
            ok = bool(poc_dirs) and len(decomposed) == len(poc_dirs)
            evidence = f"{len(decomposed)}/{len(poc_dirs)} poc dirs use step_<k>_ layout"

        elif gid == "sandbox_declared":
            sb = ROOT / "sandboxes.yml"
            ok = sb.is_file()
            evidence = "sandboxes.yml present" if ok else "sandboxes.yml missing"

        elif gid == "evidence_recorded":
            exec_dir = eng_dir / "exec"
            if exec_dir.is_dir():
                results = list(exec_dir.glob("*/result.json"))
                with_v = []
                for r in results:
                    try:
                        d = json.loads(r.read_text())
                        if "verdict" in d and "evidence_hash" in d:
                            with_v.append(r)
                    except Exception:
                        pass
                ok = bool(results) and len(with_v) == len(results)
                evidence = f"{len(with_v)}/{len(results)} result.json have verdict+hash"
            else:
                evidence = "no exec/ dir"

        elif gid == "walk_state_started":
            ok, evidence = _check_walk_state_started()

        elif gid == "walk_state_done":
            ok, evidence = _check_walk_state_done()

        elif gid == "libghidra_alive":
            import os
            url = os.environ.get("LIBGHIDRA_HEALTHZ_URL", "")
            if not url:
                ok = False
                evidence = "LIBGHIDRA_HEALTHZ_URL not set; libghidra endpoint not configured"
            else:
                # Real healthz probe (libghidra_connect implemented in foundation Task 9).
                import sys as _sys
                _sys.path.insert(0, str(ROOT / "scripts"))
                import libghidra_connect as _lg  # type: ignore
                ok = _lg.healthz(url, timeout=2.0)
                evidence = (
                    f"libghidra healthz OK at {url}"
                    if ok
                    else f"libghidra healthz FAILED at {url}"
                )

        elif gid == "no_concurrent_writer":
            import fcntl, json as _json
            try:
                import yaml as _y  # type: ignore
            except Exception as e:
                ok, evidence = False, f"PyYAML unavailable: {e}"
            else:
                scope = eng_dir / "scope.json"
                stem = ""
                if scope.is_file():
                    try:
                        stem = _json.loads(scope.read_text()).get("binary", "")
                    except Exception:
                        stem = ""
                if not stem:
                    ok, evidence = False, "scope.json#binary not set"
                else:
                    yml = CATALOG_BINARIES / f"{stem}.yml"
                    if not yml.is_file():
                        ok, evidence = True, f"no lock to check: catalog/binaries/{stem}.yml absent"
                    else:
                        try:
                            ydata = _y.safe_load(yml.read_text()) or {}
                        except Exception as e:
                            ok, evidence = False, f"parse error on {yml.name}: {e}"
                        else:
                            ref = (ydata.get("reconstruction") or {}).get("ref")
                            if not ref:
                                ok, evidence = True, "no reconstruction.ref set; no lock to check"
                            else:
                                lock_path = ROOT / ref / ".lock"
                                if not lock_path.is_file():
                                    ok, evidence = True, f"no lock file at {lock_path.relative_to(ROOT)}"
                                else:
                                    # Try to acquire non-blocking exclusive flock; release immediately.
                                    try:
                                        lf = open(lock_path, "w")
                                        try:
                                            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                            fcntl.flock(lf, fcntl.LOCK_UN)
                                            ok, evidence = True, f"lock file present but not held: {lock_path.name}"
                                        except BlockingIOError:
                                            ok, evidence = False, f"lock held by another process on {lock_path.relative_to(ROOT)}"
                                        finally:
                                            lf.close()
                                    except Exception as e:
                                        ok, evidence = False, f"flock probe error: {e}"

        elif gid in ("reachable_named_100pct", "tail_named_80pct"):
            import json as _json
            try:
                import yaml as _y  # type: ignore
            except Exception as e:
                ok, evidence = False, f"PyYAML unavailable: {e}"
            else:
                scope = eng_dir / "scope.json"
                stem = ""
                if scope.is_file():
                    try:
                        stem = _json.loads(scope.read_text()).get("binary", "")
                    except Exception:
                        stem = ""
                if not stem:
                    ok, evidence = False, "scope.json#binary not set"
                else:
                    yml = CATALOG_BINARIES / f"{stem}.yml"
                    if not yml.is_file():
                        ok, evidence = False, f"catalog/binaries/{stem}.yml missing"
                    else:
                        try:
                            ydata = _y.safe_load(yml.read_text()) or {}
                        except Exception as e:
                            ok, evidence = False, f"parse error on {yml.name}: {e}"
                        else:
                            ref = (ydata.get("reconstruction") or {}).get("ref")
                            if not ref:
                                ok, evidence = False, "no reconstruction.ref in binary YAML"
                            else:
                                cov_path = ROOT / ref / "coverage.json"
                                if not cov_path.is_file():
                                    ok, evidence = False, f"coverage.json missing at {cov_path.relative_to(ROOT)}"
                                else:
                                    try:
                                        cov = _json.loads(cov_path.read_text())
                                    except Exception as e:
                                        ok, evidence = False, f"parse error on coverage.json: {e}"
                                    else:
                                        if gid == "reachable_named_100pct":
                                            ok = bool(cov.get("hard_gate_pass"))
                                            r = cov.get("reachable", {})
                                            evidence = f"reachable named {r.get('named', '?')}/{r.get('function_count', '?')}"
                                        else:  # tail_named_80pct
                                            ok = bool(cov.get("soft_gate_pass"))
                                            t = cov.get("tail", {})
                                            evidence = f"tail named {t.get('named', '?')}/{t.get('function_count', '?')}"

        elif gid == "exec_required_or_justified":
            findings_dir = eng_dir / "findings"
            confirmed: list[str] = []
            if findings_dir.is_dir():
                for f in findings_dir.glob("*.md"):
                    txt = f.read_text()
                    if "CONFIRMED" in txt:
                        confirmed.append(f.stem)
            satisfied = []
            for stem in confirmed:
                # An exec_result OR a waiver mentioning this finding
                has_exec = any(
                    e.get("event") == "exec_result"
                    and stem in ((e.get("ref") or "") + (e.get("summary") or ""))
                    for e in events
                )
                has_waiver = any(
                    e.get("event") == "note"
                    and (e.get("meta") or {}).get("waived") is True
                    and stem.startswith(str((e.get("meta") or {}).get("finding", "")))
                    for e in events
                )
                if has_exec or has_waiver:
                    satisfied.append(stem)
            ok = (not confirmed) or len(satisfied) == len(confirmed)
            evidence = f"{len(satisfied)}/{len(confirmed)} CONFIRMED findings satisfied"

        else:
            evidence = "unknown gate id — manual check required"

        out.append({"id": gid, "kind": kind, "ok": ok, "evidence": evidence})
    return out


def cmd_state(args) -> int:
    cfg = load_pipeline()
    phases = cfg.get("phases", {})
    eng_dir = _eng_dir(args.engagement)

    completed = [p for p, d in phases.items() if phase_completed(eng_dir, d)]
    print(f"engagement: {args.engagement}")
    print(f"completed phases ({len(completed)}): {', '.join(completed) or '-'}")

    # Current phase = last completed's `next`, if entry-able
    current = "preparation"  # default starting guess
    events = journal_events(args.engagement)
    for ev in reversed(events):
        if ev.get("event") == "phase_start":
            current = ev.get("phase")
            break
    print(f"current phase (per journal): {current}")

    if current in phases:
        gates = gate_status(args.engagement, eng_dir, current, phases[current])
        if gates:
            print("gates:")
            for g in gates:
                mark = "OK" if g["ok"] else "MISS"
                print(f"  [{mark}] {g['kind']:5s} {g['id']:30s} -- {g['evidence']}")

    return 0


def cmd_next(args) -> int:
    cfg = load_pipeline()
    phases = cfg.get("phases", {})
    eng_dir = _eng_dir(args.engagement)
    completed = {p for p, d in phases.items() if phase_completed(eng_dir, d)}
    candidates = set()
    for p in completed:
        for n in phases[p].get("next", []):
            candidates.add(n)
    candidates -= completed

    print(f"legal next phases for {args.engagement}:")
    for c in sorted(candidates):
        if c not in phases:
            continue
        ok, missing = phase_entryable(eng_dir, phases[c])
        mark = "READY" if ok else "BLOCKED"
        miss = (" (missing: " + ", ".join(missing) + ")") if missing else ""
        print(f"  [{mark}] {c}{miss}")
    if not candidates:
        print("  (none — engagement may be complete or fresh)")
    return 0


def cmd_validate(args) -> int:
    cfg = load_pipeline()
    phases = cfg.get("phases", {})
    eng_dir = _eng_dir(args.engagement)
    rc = 0
    for p, d in phases.items():
        gates = gate_status(args.engagement, eng_dir, p, d)
        for g in gates:
            if g["kind"] == "pre":
                continue   # pre-gates only checked when about to enter
            if not g["ok"] and phase_completed(eng_dir, d):
                print(f"FAIL {p:20s} gate={g['id']:30s} -- {g['evidence']}")
                rc = 1
    if rc == 0:
        print(f"OK: {args.engagement}")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in [("state", cmd_state), ("next", cmd_next), ("validate", cmd_validate)]:
        sp = sub.add_parser(name)
        sp.add_argument("engagement")
        sp.set_defaults(func=fn)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
