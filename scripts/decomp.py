#!/usr/bin/env python3
"""Ghidra headless batch decompilation for VulneraBin.

Runs Ghidra analyzeHeadless to decompile a binary and export:
- decompiled.c — all decompiled functions
- function_index.json — function metadata with call graph, xrefs, strings

Adapted from SurfaceStorm's GhidraBridge pattern.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Default Ghidra installation path
DEFAULT_GHIDRA_HOME = os.environ.get(
    "GHIDRA_INSTALL_DIR",
    os.path.expanduser("~/tools/ghidra_11.3.1_PUBLIC")
)

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ghidra_scripts")


def find_ghidra(ghidra_home=None):
    """Find analyzeHeadless binary."""
    candidates = [
        ghidra_home,
        DEFAULT_GHIDRA_HOME,
        os.environ.get("GHIDRA_HOME", ""),
        "/opt/ghidra",
        "/usr/share/ghidra",
    ]

    for base in candidates:
        if not base:
            continue
        headless = os.path.join(base, "support", "analyzeHeadless")
        if os.path.isfile(headless):
            return headless

    return None


def run_ghidra_headless(binary_path, output_dir, ghidra_home=None, timeout=600, java_mem="4G"):
    """Run Ghidra headless analysis with decompilation scripts."""
    headless = find_ghidra(ghidra_home)
    if not headless:
        return {"error": "Ghidra analyzeHeadless not found. Set GHIDRA_INSTALL_DIR."}

    binary_path = os.path.abspath(binary_path)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # Create temp project directory
    project_dir = os.path.join(output_dir, ".ghidra_project")
    os.makedirs(project_dir, exist_ok=True)

    binary_hash = hashlib.sha256(open(binary_path, "rb").read(4096)).hexdigest()[:12]
    project_name = f"VulneraBin_{binary_hash}"

    # Build command
    cmd = [
        headless,
        project_dir,
        project_name,
        "-import", binary_path,
        "-overwrite",
        "-scriptPath", os.path.abspath(SCRIPTS_DIR),
        "-postScript", "ExportDecompiled.py", output_dir,
        "-postScript", "ExportFunctionIndex.py", output_dir,
    ]

    # Add Java memory setting
    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = f"-Xmx{java_mem}"

    print(f"Running Ghidra headless analysis on {binary_path}...", file=sys.stderr)
    print(f"Output directory: {output_dir}", file=sys.stderr)
    start = time.time()

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env
        )
        duration = time.time() - start

        if proc.returncode != 0:
            # Ghidra often returns non-zero but still produces output
            print(f"Ghidra exit code: {proc.returncode}", file=sys.stderr)
            if proc.stderr:
                # Print last 500 chars of stderr
                print(proc.stderr[-500:], file=sys.stderr)

    except subprocess.TimeoutExpired:
        return {"error": f"Ghidra analysis timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": f"analyzeHeadless not found at {headless}"}

    # Collect results
    result = {
        "binary": binary_path,
        "output_dir": output_dir,
        "duration_seconds": round(duration, 1),
        "files": {},
    }

    # Check for output files
    decompiled = os.path.join(output_dir, "decompiled.c")
    func_index = os.path.join(output_dir, "function_index.json")

    if os.path.isfile(decompiled):
        result["files"]["decompiled"] = decompiled
        size = os.path.getsize(decompiled)
        result["decompiled_size_bytes"] = size
        print(f"Decompiled output: {size} bytes", file=sys.stderr)

    if os.path.isfile(func_index):
        result["files"]["function_index"] = func_index
        with open(func_index) as f:
            index = json.load(f)
        result["total_functions"] = len(index.get("functions", []))
        print(f"Function index: {result['total_functions']} functions", file=sys.stderr)

    if not result["files"]:
        result["error"] = "Ghidra produced no output files"
        if proc.stderr:
            result["stderr_tail"] = proc.stderr[-1000:]

    # Split decompiled.c into per-function files for Claude Code to read individually
    if os.path.isfile(decompiled):
        funcs_dir = os.path.join(output_dir, "functions")
        os.makedirs(funcs_dir, exist_ok=True)
        split_decompiled(decompiled, funcs_dir)
        result["files"]["functions_dir"] = funcs_dir

    return result


def split_decompiled(decompiled_path, output_dir):
    """Split a monolithic decompiled.c into per-function files."""
    with open(decompiled_path, encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Split on function boundaries (Ghidra decompiled output format)
    # Functions typically start with a type and function name
    import re
    # Match function definitions: "type funcname(params) {"
    pattern = re.compile(r'^(\w[\w\s\*]+?)\s+(\w+)\s*\([^)]*\)\s*\{', re.MULTILINE)

    matches = list(pattern.finditer(content))
    count = 0

    for i, match in enumerate(matches):
        func_name = match.group(2)
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)

        func_code = content[start:end].strip()
        if func_code:
            # Sanitize filename
            safe_name = re.sub(r'[^\w]', '_', func_name)[:100]
            func_file = os.path.join(output_dir, f"{safe_name}.c")
            with open(func_file, "w") as f:
                f.write(func_code)
            count += 1

    print(f"Split into {count} function files in {output_dir}", file=sys.stderr)
    return count


def main():
    parser = argparse.ArgumentParser(description="Ghidra headless decompilation for VulneraBin")
    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("--output", "-o", required=True, help="Output directory")
    parser.add_argument("--ghidra", help="Ghidra installation directory")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds (default: 600)")
    parser.add_argument("--memory", default="4G", help="Java max memory (default: 4G)")
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(json.dumps({"error": f"Binary not found: {args.binary}"}))
        sys.exit(1)

    result = run_ghidra_headless(
        args.binary, args.output,
        ghidra_home=args.ghidra,
        timeout=args.timeout,
        java_mem=args.memory,
    )

    print(json.dumps(result, indent=2))
    sys.exit(0 if "error" not in result else 1)


if __name__ == "__main__":
    main()
