#!/usr/bin/env python3
"""Model routing wrapper for vulnerabin.

Reads `models.yml` and emits (or executes) the correct CLI invocation for a
given stage. Two backends supported:
    claude     -> `claude -p --model <m> --permission-mode dontAsk ...`
    opencode   -> `opencode run --model <m> -- <prompt>`

Default behavior is to PRINT the command for the operator to inspect; pass
`--exec` to actually run it.

Usage:
    # Show the command for a stage:
    python3 scripts/route_model.py plan inspect_function \\
        --prompt-file /tmp/inspect.txt --add-dir engagements/foo/decomp

    # Execute it (capture stdout/stderr):
    python3 scripts/route_model.py exec inspect_function \\
        --prompt-file /tmp/inspect.txt --add-dir engagements/foo/decomp \\
        --output /tmp/inspect_result.json

    # List configured stages:
    python3 scripts/route_model.py list
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS_YML = ROOT / "models.yml"


def _load_yaml(p: Path) -> dict:
    """Load YAML via PyYAML (already a dependency in the runtime)."""
    import yaml
    return yaml.safe_load(p.read_text()) or {}


def load_config() -> dict:
    return _load_yaml(MODELS_YML)


def stage_route(cfg: dict, stage: str) -> dict:
    routing = cfg.get("routing", {})
    if stage in routing:
        merged = {**cfg.get("defaults", {}), **routing[stage]}
        merged["_stage"] = stage
        return merged
    fallback = cfg.get("fallback", {})
    merged = {**cfg.get("defaults", {}), **fallback, "_stage": stage, "_fallback": True}
    return merged


def build_command(route: dict, prompt: str, *, add_dirs: list[str], system_prompt: str | None,
                  output_format: str | None, output_file: str | None) -> list[str]:
    cli = route.get("cli", "claude")
    model = route["model"]

    if cli == "claude":
        cmd = ["claude", "-p", "--model", model, "--permission-mode",
               route.get("permission_mode", "dontAsk")]
        cmd += ["--output-format", output_format or route.get("output_format", "text")]
        # No session persistence for stateless workers
        cmd += ["--no-session-persistence"]
        for d in add_dirs:
            cmd += ["--add-dir", d]
        if system_prompt:
            cmd += ["--append-system-prompt", system_prompt]
        cmd += [prompt]
        return cmd

    if cli == "opencode":
        cmd = ["opencode", "run", "--model", model, "--", prompt]
        return cmd

    raise SystemExit(f"unknown cli: {cli}")


def cmd_list(_args) -> int:
    cfg = load_config()
    routing = cfg.get("routing", {})
    print(f"{'STAGE':24s}  {'CLI':10s}  {'MODEL':38s}  RATIONALE")
    for k, v in routing.items():
        print(f"{k:24s}  {v.get('cli','?'):10s}  {v.get('model','?'):38s}  {v.get('rationale','')}")
    return 0


def _resolve_inputs(args) -> tuple[str, str | None]:
    prompt = args.prompt
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text()
    if prompt is None:
        raise SystemExit("--prompt or --prompt-file required")
    sysp = None
    if args.system_prompt_file:
        sysp = Path(args.system_prompt_file).read_text()
    elif args.system_prompt:
        sysp = args.system_prompt
    return prompt, sysp


def cmd_plan(args) -> int:
    cfg = load_config()
    route = stage_route(cfg, args.stage)
    prompt, sysp = _resolve_inputs(args)
    cmd = build_command(route, prompt, add_dirs=args.add_dir or [], system_prompt=sysp,
                        output_format=args.output_format, output_file=args.output)
    if args.json:
        print(json.dumps({"route": route, "cmd": cmd}, indent=2, default=str))
    else:
        print(f"# stage: {args.stage}  cli: {route['cli']}  model: {route['model']}")
        print(" ".join(shlex.quote(c) for c in cmd))
    return 0


def cmd_exec(args) -> int:
    cfg = load_config()
    route = stage_route(cfg, args.stage)
    prompt, sysp = _resolve_inputs(args)
    cmd = build_command(route, prompt, add_dirs=args.add_dir or [], system_prompt=sysp,
                        output_format=args.output_format, output_file=args.output)
    print(f"[route_model] exec: {route['cli']} {route['model']} (stage={args.stage})", file=sys.stderr)
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - t0
    print(f"[route_model] elapsed: {elapsed:.1f}s rc={proc.returncode}", file=sys.stderr)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(proc.stdout)
        print(f"[route_model] wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(proc.stdout)
    return proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, fn in [("plan", cmd_plan), ("exec", cmd_exec)]:
        sp = sub.add_parser(name)
        sp.add_argument("stage")
        sp.add_argument("--prompt")
        sp.add_argument("--prompt-file")
        sp.add_argument("--system-prompt")
        sp.add_argument("--system-prompt-file")
        sp.add_argument("--add-dir", action="append", default=[])
        sp.add_argument("--output-format", choices=["text", "json", "stream-json"])
        sp.add_argument("--output", help="write stdout to this file")
        if name == "plan":
            sp.add_argument("--json", action="store_true")
        sp.set_defaults(func=fn)

    lp = sub.add_parser("list")
    lp.set_defaults(func=cmd_list)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
