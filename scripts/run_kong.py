#!/usr/bin/env python3
"""Kong integration wrapper for function renaming on stripped binaries.

Runs Kong (https://github.com/amruth-sn/kong) to:
- Rename stripped functions with meaningful names
- Recover type information
- Build enriched context (xrefs, strings, callers/callees)

If Kong is not installed, this is a no-op that passes through.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys


def check_kong_available():
    """Check if Kong is installed and accessible."""
    try:
        result = subprocess.run(
            ["kong", "--help"], capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check if it's available as a Python module
    try:
        result = subprocess.run(
            [sys.executable, "-m", "kong", "--help"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return False


def run_kong(binary_path, output_dir, provider="anthropic", model=None, headless=True):
    """Run Kong on a binary for function renaming and enrichment."""

    if not check_kong_available():
        print("Kong not installed. Skipping function renaming.", file=sys.stderr)
        print("Install from: https://github.com/amruth-sn/kong", file=sys.stderr)
        return {
            "status": "skipped",
            "reason": "kong_not_installed",
            "binary": binary_path,
        }

    binary_path = os.path.abspath(binary_path)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    cmd = ["kong", "analyze", binary_path, "--output", output_dir]

    if provider:
        cmd.extend(["--provider", provider])
    if model:
        cmd.extend(["--model", model])
    if headless:
        cmd.append("--headless")

    print(f"Running Kong on {binary_path}...", file=sys.stderr)

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=1800  # 30 min timeout
        )

        if proc.returncode != 0:
            print(f"Kong exit code: {proc.returncode}", file=sys.stderr)
            if proc.stderr:
                print(proc.stderr[-500:], file=sys.stderr)

        # Check for output
        analysis_json = os.path.join(output_dir, "analysis.json")
        if os.path.isfile(analysis_json):
            with open(analysis_json) as f:
                analysis = json.load(f)

            return {
                "status": "success",
                "binary": binary_path,
                "output_dir": output_dir,
                "analysis_file": analysis_json,
                "total_functions": analysis.get("stats", {}).get("total_functions", 0),
                "renamed": analysis.get("stats", {}).get("renamed", 0),
                "confidence": analysis.get("stats", {}).get("confidence_levels", {}),
            }
        else:
            return {
                "status": "error",
                "reason": "no_output",
                "binary": binary_path,
                "stderr": proc.stderr[-500:] if proc.stderr else "",
            }

    except subprocess.TimeoutExpired:
        return {"status": "error", "reason": "timeout", "binary": binary_path}
    except Exception as e:
        return {"status": "error", "reason": str(e), "binary": binary_path}


def main():
    parser = argparse.ArgumentParser(description="Run Kong for function renaming")
    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("--output", "-o", required=True, help="Output directory")
    parser.add_argument("--provider", default="anthropic", help="LLM provider (default: anthropic)")
    parser.add_argument("--model", help="Model override")
    parser.add_argument("--check", action="store_true", help="Just check if Kong is available")
    args = parser.parse_args()

    if args.check:
        available = check_kong_available()
        print(json.dumps({"kong_available": available}))
        sys.exit(0 if available else 1)

    result = run_kong(args.binary, args.output, provider=args.provider, model=args.model)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("status") != "error" else 1)


if __name__ == "__main__":
    main()
