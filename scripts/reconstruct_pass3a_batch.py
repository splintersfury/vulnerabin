"""Pass 3a batch emission — cluster struct hypotheses from Pass 2 retypes.

Reads `manifest.json#passes[].pass2.retypes` and finds parameter retypes
whose `to` value is a custom struct pointer type (e.g., `IPC_REQUEST_HEADER *`).
Groups occurrences by struct base name and writes one batch JSON per cluster
under <reconstruction.ref>/pass3a_batches/.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("VULNERABIN_ROOT") or Path(__file__).resolve().parent.parent)

_WIN_BUILTIN_TYPES = {
    "LPCWSTR", "LPWSTR", "LPCSTR", "LPSTR",
    "HANDLE", "HMODULE", "HWND", "HKEY",
    "NTSTATUS", "HRESULT", "WINBOOL", "BOOL", "BOOLEAN",
    "DWORD", "WORD", "BYTE", "LONG", "ULONG", "ULONGLONG", "LONGLONG",
    "QWORD", "DWORDLONG", "INT", "UINT", "UINT8", "UINT16", "UINT32", "UINT64",
    "INT8", "INT16", "INT32", "INT64",
    "SIZE_T", "PSIZE_T", "PVOID", "LPVOID", "LPCVOID",
    "PWSTR", "PSTR", "PWCHAR", "PCHAR",
    "FILETIME", "SYSTEMTIME", "GUID", "UUID",
    "VOID", "NULL", "TRUE", "FALSE",
}
_C_BUILTIN_TYPES = {
    "char", "short", "int", "long", "float", "double",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "size_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "bool", "void",
}

_STRUCT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def extract_struct_name(type_str: str) -> str | None:
    """Return the candidate struct base name from a type string, or None
    if the type is not a custom struct pointer."""
    s = (type_str or "").strip()
    if not s:
        return None
    if s.lower().startswith("const "):
        s = s[6:].strip()
    if "*" not in s:
        return None
    s = s.rstrip().rstrip("*").strip()
    if not s:
        return None
    if s in _WIN_BUILTIN_TYPES or s in _C_BUILTIN_TYPES:
        return None
    if not _STRUCT_NAME_RE.match(s):
        return None
    return s


def cluster_struct_hypotheses(manifest: dict) -> list[dict]:
    """Walk all pass2 retypes and group params with matching struct base names."""
    clusters: dict[str, dict] = {}
    for p in manifest.get("passes", []):
        if p.get("pass") != "pass2":
            continue
        for retype in p.get("retypes", []) or []:
            addr = retype.get("addr")
            if not addr:
                continue
            for param in retype.get("params", []) or []:
                struct_name = extract_struct_name(param.get("to", ""))
                if not struct_name:
                    continue
                cluster = clusters.setdefault(struct_name, {
                    "name": struct_name,
                    "supporting_functions": [],
                    "occurrences": [],
                })
                if addr not in cluster["supporting_functions"]:
                    cluster["supporting_functions"].append(addr)
                cluster["occurrences"].append({
                    "addr": addr,
                    "param_index": param.get("index"),
                    "from_type": param.get("from", ""),
                    "confidence": param.get("confidence", ""),
                    "rationale": param.get("rationale", ""),
                })
    return sorted(clusters.values(), key=lambda c: c["name"])


def make_batches(clusters: list[dict]) -> list[list[dict]]:
    """One cluster per batch."""
    return [[c] for c in clusters]


def write_batches(recon_dir: Path, manifest: dict) -> dict:
    clusters = cluster_struct_hypotheses(manifest)
    batches = make_batches(clusters)
    bdir = recon_dir / "pass3a_batches"
    bdir.mkdir(parents=True, exist_ok=True)

    index_entries: list[dict] = []
    for i, b in enumerate(batches):
        batch_id = f"batch_{i:03d}"
        payload = {"batch_id": batch_id, "clusters": b}
        (bdir / f"{batch_id}.json").write_text(json.dumps(payload, indent=2))
        index_entries.append({
            "batch_id": batch_id,
            "cluster_name": b[0]["name"] if b else "",
            "status": "pending",
        })

    (bdir / "index.json").write_text(json.dumps({
        "batches": index_entries,
        "cluster_count": len(clusters),
    }, indent=2))

    return {
        "batch_count": len(batches),
        "cluster_count": len(clusters),
        "batches_dir": str(bdir),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--version", required=True)
    args = ap.parse_args(argv)

    recon_dir = ROOT / "catalog" / "reconstructed" / f"{args.binary}_{args.version}"
    if not recon_dir.is_dir():
        print(f"error: {recon_dir} not found", file=sys.stderr)
        return 2
    manifest_path = recon_dir / "manifest.json"
    if not manifest_path.is_file():
        print(f"error: manifest.json missing at {manifest_path}", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text())

    summary = write_batches(recon_dir, manifest)
    print(
        f"wrote {summary['batch_count']} pass3a batch(es) covering "
        f"{summary['cluster_count']} struct cluster(s) under "
        f"{Path(summary['batches_dir']).relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
