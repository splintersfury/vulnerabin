#!/usr/bin/env python3
"""Extract a `reverse_engineering:` block for one binary from engagement RE artifacts.

This is the integration point between vulnerabin's decomp pipeline and the
binary catalog. After `decomp.py` produces `decomp{,-<suffix>}/function_index.json`
(and optionally chains.json + triage.json), this script reads those artifacts
and synthesises the structured RE brief that the catalog renders at the top
of each binary page.

Heuristic flow (no LLM needed):
  1. Locate the decomp directory for the requested binary.
  2. Parse function_index.json: pick entrypoint, mine import/dynamic-load
     candidates, aggregate strings, build RVA anchors.
  3. Optionally parse chains.json: every chain.source becomes an INP-* candidate
     (classified by taxonomy/binary/sources.json).
  4. Optionally parse triage.json: high-rated functions become RVA anchors.
  5. Match path-shaped strings against kind heuristics (file/registry/ipc/network).
  6. Merge into catalog/binaries/<name>.yml WITHOUT overwriting hand-edited fields.
     - `entrypoint`/`behavior`/`notes`: leave existing if non-empty.
     - `loaded_modules`/`inputs`/`notable_strings`/`rva_anchors`: dedup-merge by stable key.
     - Existing INP-* IDs are preserved; new inputs get the next free ID.
  7. After merge, run derivation back-link: for every `sources[].id` lacking
     `derived_from`, try to match it against an INP-* by path/function overlap.
     Only fills if the match is unambiguous.

Usage:
  catalog_re_extract.py --eng <slug> --binary <name>          # print to stdout
  catalog_re_extract.py --eng <slug> --binary <name> --apply  # merge into catalog YAML
  catalog_re_extract.py --eng <slug> --all --apply            # all binaries with decomp
  catalog_re_extract.py --decomp-dir <path> --binary <name>   # explicit decomp dir
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ENG = ROOT / "engagements"
CATALOG = ROOT / "catalog" / "binaries"
TAXONOMY = ROOT / "taxonomy" / "binary" / "sources.json"

# Canonical entry-function names — first match wins.
CANONICAL_ENTRIES = [
    "wWinMain", "WinMain", "wmain", "main",
    "DriverEntry", "DllMain", "ServiceMain",
    "_DllMainCRTStartup", "DllMainCRTStartup",
]
# CRT bootstrap functions — listed as a fallback when no real entry symbol is present.
CRT_ENTRIES = ["__scrt_common_main_seh", "_scrt_common_main_seh", "mainCRTStartup", "wmainCRTStartup"]

# Path / endpoint detectors. Each yields a kind hint when matched.
PATH_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^\\\\\.\\pipe\\", re.IGNORECASE), "ipc_pipe"),
    (re.compile(r"^\\\\\.\\[A-Za-z][A-Za-z0-9_]+$"), "ioctl"),  # \\.\DeviceName
    (re.compile(r"^\\Device\\", re.IGNORECASE), "ioctl"),
    (re.compile(r"^[A-Z]:\\\\?ProgramData\\\\?", re.IGNORECASE), "file_read"),
    (re.compile(r"^[A-Z]:\\\\?Users\\\\?", re.IGNORECASE), "file_read"),
    (re.compile(r"^[A-Z]:\\\\?Windows\\\\?Temp", re.IGNORECASE), "file_write"),
    (re.compile(r"^[A-Z]:\\\\?Windows\\\\?", re.IGNORECASE), "file_read"),
    (re.compile(r"^[A-Z]:\\\\?Program ?Files", re.IGNORECASE), "file_read"),
    (re.compile(r"^HKLM\\|^HKEY_LOCAL_MACHINE\\", re.IGNORECASE), "registry_read"),
    (re.compile(r"^HKCU\\|^HKEY_CURRENT_USER\\", re.IGNORECASE), "registry_read"),
    (re.compile(r"^Software\\", re.IGNORECASE), "registry_read"),
    (re.compile(r"^https?://", re.IGNORECASE), "network_connect"),
    (re.compile(r"^\\\\\?\\", re.IGNORECASE), "file_read"),
]

LIBRARY_PATTERNS = re.compile(r"\.(dll|sys|so|dylib)$", re.IGNORECASE)
DYNAMIC_LOAD_APIS = {"LoadLibraryW", "LoadLibraryExW", "LoadLibraryA", "LoadLibraryExA",
                     "GetModuleHandleW", "GetModuleHandleExW", "LdrLoadDll"}
IPC_HANDLER_APIS = {"DeviceIoControl", "IoCreateDeviceSecure", "IoCreateDevice",
                    "CreateNamedPipeW", "ConnectNamedPipe",
                    "RpcServerRegisterIf", "RpcServerListen",
                    "AlpcCreatePort", "NtCreatePort"}

# ---------------------------------------------------------------------------
# Sink-API library — keyed by category. The user said "aggressive", so this
# list is broad. Each category maps to a default capability template.
# ---------------------------------------------------------------------------
SINK_API_LIBRARY: dict[str, dict] = {
    "process_creation": {
        "apis": {"CreateProcessAsUserW", "CreateProcessAsUserA", "CreateProcessWithTokenW",
                 "CreateProcessWithLogonW", "CreateProcessW", "CreateProcessA",
                 "ShellExecuteW", "ShellExecuteA", "ShellExecuteExW", "ShellExecuteExA",
                 "WinExec", "ZwCreateProcess", "NtCreateProcess",
                 "ZwCreateProcessEx", "NtCreateProcessEx",
                 "ZwCreateUserProcess", "NtCreateUserProcess",
                 "RtlCreateUserProcess"},
        "capability_name": "Spawn process",
        "default_cwe": "CWE-269",
        "impact": "Code execution under the binary's privilege",
    },
    "command_exec": {
        "apis": {"system", "_wsystem", "popen", "_popen", "_wpopen",
                 "execv", "execvp", "execve", "execlp", "_wexecv", "_wexecvp"},
        "capability_name": "Execute shell command",
        "default_cwe": "CWE-78",
        "impact": "Command injection if the argv is attacker-controlled",
    },
    "file_io": {
        "apis": {"CreateFileW", "CreateFileA", "CreateFile2",
                 "ZwCreateFile", "NtCreateFile", "ZwOpenFile", "NtOpenFile",
                 "MoveFileW", "MoveFileExW", "MoveFileA", "MoveFileExA",
                 "CopyFileW", "CopyFileExW", "CopyFile2",
                 "DeleteFileW", "DeleteFileA", "ZwDeleteFile",
                 "WriteFile", "WriteFileEx", "ZwWriteFile", "NtWriteFile",
                 "SetFileInformationByHandle", "ZwSetInformationFile",
                 "CreateSymbolicLinkW", "CreateHardLinkW",
                 "FltCreateFile", "FltWriteFile"},
        "capability_name": "Create / modify file (junction, write, delete)",
        "default_cwe": "CWE-22",
        "impact": "Arbitrary file write or follow-the-link primitive if path is attacker-controlled",
    },
    "registry_write": {
        "apis": {"RegSetValueExW", "RegSetValueExA", "RegSetKeyValueW", "RegSetKeyValueA",
                 "RegCreateKeyExW", "RegCreateKeyExA", "RegDeleteValueW", "RegDeleteValueA",
                 "RegDeleteKeyW", "RegDeleteKeyExW",
                 "ZwSetValueKey", "NtSetValueKey", "ZwCreateKey", "NtCreateKey",
                 "ZwDeleteKey", "NtDeleteKey", "ZwDeleteValueKey", "NtDeleteValueKey"},
        "capability_name": "Modify registry",
        "default_cwe": "CWE-732",
        "impact": "Persistence / configuration tampering if path is attacker-controlled",
    },
    "memory_unsafe": {
        "apis": {"ExAllocatePool", "ExAllocatePoolWithTag", "ExAllocatePool2",
                 "ExAllocatePool3", "ExAllocatePoolUninitialized",
                 "MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPages",
                 "MmMapLockedPagesSpecifyCache", "MmCopyMemory",
                 "ZwAllocateVirtualMemory", "NtAllocateVirtualMemory",
                 "ZwMapViewOfSection", "NtMapViewOfSection",
                 "memcpy", "memmove", "RtlCopyMemory", "wcscpy", "strcpy", "lstrcpyW", "lstrcpyA",
                 "wcscat", "strcat", "lstrcatW", "lstrcatA", "sprintf", "wsprintf"},
        "capability_name": "Allocate / map / copy memory",
        "default_cwe": "CWE-119",
        "impact": "Heap/buffer overflow / kernel-pool corruption if size is attacker-controlled",
    },
    "token_manipulation": {
        "apis": {"OpenProcessToken", "ZwOpenProcessToken", "NtOpenProcessToken",
                 "AdjustTokenPrivileges", "ZwAdjustPrivilegesToken", "NtAdjustPrivilegesToken",
                 "SetThreadToken", "ImpersonateLoggedOnUser", "ImpersonateNamedPipeClient",
                 "ImpersonateAnonymousToken", "RevertToSelf",
                 "DuplicateTokenEx", "DuplicateToken",
                 "ZwSetInformationToken", "NtSetInformationToken",
                 "ZwOpenProcess", "NtOpenProcess"},
        "capability_name": "Manipulate process token / impersonate",
        "default_cwe": "CWE-269",
        "impact": "Privilege escalation if the impersonation/token comes from a less-trusted caller",
    },
    "device_creation": {
        "apis": {"IoCreateDevice", "IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure",
                 "IoCreateSymbolicLink", "IoCreateUnprotectedSymbolicLink"},
        "capability_name": "Create kernel device object",
        "default_cwe": "CWE-732",
        "impact": "Exposes IOCTL surface — DACL on the device controls who can reach the dispatch handler",
    },
    "network": {
        "apis": {"WSAConnect", "connect", "WSASend", "send", "InternetOpenUrlW",
                 "InternetReadFile", "WinHttpOpenRequest", "WinHttpSendRequest",
                 "URLDownloadToFileW", "WSARecv", "recv", "DnsQuery_W"},
        "capability_name": "Make network connection",
        "default_cwe": "CWE-918",
        "impact": "SSRF / data exfil if URL is attacker-controlled",
    },
    "rpc_ipc": {
        "apis": {"RpcServerRegisterIf", "RpcServerRegisterIf2", "RpcServerRegisterIfEx",
                 "RpcServerListen", "RpcServerInqCallAttributesW",
                 "AlpcCreatePort", "NtAlpcCreatePort", "AlpcSendWaitReceivePort",
                 "CreateNamedPipeW", "CreateNamedPipeA", "ConnectNamedPipe",
                 "TransactNamedPipe"},
        "capability_name": "Expose IPC endpoint",
        "default_cwe": "CWE-862",
        "impact": "Unauthenticated callers can drive privileged behaviour if no auth check",
    },
    "kernel_handle": {
        "apis": {"ObReferenceObjectByHandle", "ObReferenceObjectByPointer",
                 "ObOpenObjectByName", "ObOpenObjectByPointer",
                 "ZwOpenSection", "NtOpenSection", "ZwOpenKey", "NtOpenKey",
                 "IoGetDeviceObjectPointer", "ObfDereferenceObject"},
        "capability_name": "Acquire kernel object handle",
        "default_cwe": "CWE-732",
        "impact": "Kernel handle dereference under attacker influence — UAF / type confusion vector",
    },
}

# Reverse map: API name -> category (built once)
API_TO_CATEGORY: dict[str, str] = {
    api: cat for cat, body in SINK_API_LIBRARY.items() for api in body["apis"]
}

# Strings that are decompiler/CRT noise — exclude from notable_strings.
NOISE_PATTERNS = [
    re.compile(r"^FUN_[0-9a-f]+$", re.IGNORECASE),
    re.compile(r"^LAB_[0-9a-f]+$", re.IGNORECASE),
    re.compile(r"^thunk_"),
    re.compile(r"^_+[A-Z]"),
    re.compile(r"^[a-z_]+::~?[a-z_]+$"),  # C++ ctor/dtor mangled
    re.compile(r"^Catch_?All|^Catch@"),
    re.compile(r"^vector deleting destructor|scalar deleting destructor"),
    re.compile(r"^[A-Z][a-z]{1,4}$"),  # very short tokens
]


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
@dataclass
class DecompData:
    binary: str
    function_index_path: Path
    functions: list[dict] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    triage: list[dict] = field(default_factory=list)


def find_decomp_dir(eng_dir: Path, binary: str) -> Path | None:
    """Walk engagement dir looking for a decomp folder whose function_index.json
    has binary == requested binary (case-insensitive on filename)."""
    candidates = sorted(eng_dir.glob("decomp*")) + sorted(eng_dir.glob("*_decomp"))
    target = binary.lower()
    for d in candidates:
        idx = d / "function_index.json"
        if not idx.exists():
            continue
        try:
            data = json.loads(idx.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        # match on binary name (Ghidra reports filename)
        bn = (data.get("binary") or "").lower()
        if bn == target or Path(bn).name == target or target in bn:
            return d
    return None


def load_decomp(decomp_dir: Path, binary: str) -> DecompData:
    idx = decomp_dir / "function_index.json"
    raw = json.loads(idx.read_text())
    funcs = raw.get("functions") or []
    return DecompData(binary=binary, function_index_path=idx, functions=funcs)


def attach_chains_triage(d: DecompData, eng_dir: Path) -> None:
    chains_path = eng_dir / "chains.json"
    if chains_path.exists():
        try:
            data = json.loads(chains_path.read_text())
            chains = data.get("chains") if isinstance(data, dict) else data
            d.chains = chains or []
        except (json.JSONDecodeError, OSError):
            pass
    triage_path = eng_dir / "triage.json"
    if triage_path.exists():
        try:
            data = json.loads(triage_path.read_text())
            triage = data.get("results") if isinstance(data, dict) and "results" in data else data
            if isinstance(triage, list):
                d.triage = triage
        except (json.JSONDecodeError, OSError):
            pass


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------
def _is_real_symbol(name: str) -> bool:
    """True if `name` looks like a real symbol vs Ghidra-generated."""
    if not name:
        return False
    for pat in NOISE_PATTERNS:
        if pat.match(name):
            return False
    return True


def detect_entrypoint(funcs: list[dict]) -> str:
    by_name: dict[str, dict] = {f.get("name", ""): f for f in funcs}
    # Prefer canonical
    for ce in CANONICAL_ENTRIES:
        if ce in by_name:
            f = by_name[ce]
            return f"{ce} @ 0x{f['address']}"
    # CRT fallback — try to follow callees one hop to find the user entry
    for crt in CRT_ENTRIES:
        if crt in by_name:
            f = by_name[crt]
            for callee in f.get("callees") or []:
                if callee in CANONICAL_ENTRIES and callee in by_name:
                    inner = by_name[callee]
                    return f"{callee} @ 0x{inner['address']} (called by {crt} @ 0x{f['address']})"
            return f"{crt} @ 0x{f['address']} (CRT bootstrap; user entry not symbolised)"
    # Any exported function as last resort
    exports = [f for f in funcs if f.get("is_exported")]
    if exports:
        f = exports[0]
        return f"{f.get('name')} @ 0x{f['address']} (first export — entrypoint not detected)"
    return ""


def detect_loaded_modules(funcs: list[dict]) -> list[dict]:
    """Two pools: static (callees that look like Windows APIs we can attribute
    to known DLLs) and dynamic (strings that end in .dll/.sys, observed near
    LoadLibrary callsites)."""
    out: list[dict] = []
    seen: set[str] = set()

    # Dynamic: scan funcs that call LoadLibrary*; collect .dll/.sys strings in those funcs
    dynamic_libs: set[str] = set()
    for f in funcs:
        callees = set(f.get("callees") or [])
        if callees & DYNAMIC_LOAD_APIS:
            for s in f.get("strings") or []:
                if LIBRARY_PATTERNS.search(s):
                    name = s.strip("\\/").lower()
                    if name and name not in dynamic_libs:
                        dynamic_libs.add(name)
    for lib in sorted(dynamic_libs):
        if lib in seen:
            continue
        seen.add(lib)
        out.append({"name": lib, "via": "dynamic_LoadLibrary", "role": ""})

    # Static: anywhere a callee looks like a known DLL prefix (heuristic), record.
    # This is intentionally conservative — we only catch high-signal cases.
    KNOWN_PREFIXES = {
        "Bcrypt": "bcrypt.dll", "Ncrypt": "ncrypt.dll",
        "Wininet": "wininet.dll", "Winhttp": "winhttp.dll",
        "Ws2_32": "ws2_32.dll", "WSA": "ws2_32.dll",
        "Crypt32": "crypt32.dll", "Advapi32": "advapi32.dll",
        "User32": "user32.dll",
    }
    api_dll: dict[str, str] = {}
    for f in funcs:
        for callee in f.get("callees") or []:
            for prefix, dll in KNOWN_PREFIXES.items():
                if callee.startswith(prefix):
                    api_dll[dll] = api_dll.get(dll, "") + (callee + ", ")[:0]  # noqa
                    api_dll[dll] = "static_import"
                    break
    for dll, _via in sorted(api_dll.items()):
        if dll in seen:
            continue
        seen.add(dll)
        out.append({"name": dll, "via": "static_import", "role": ""})
    return out


def detect_inputs_from_strings(funcs: list[dict]) -> list[dict]:
    """Path-shaped strings → input candidates."""
    found: dict[tuple, dict] = {}  # (kind, path) -> dict
    for f in funcs:
        for s in f.get("strings") or []:
            if not s or len(s) < 4 or len(s) > 256:
                continue
            kind = None
            for pat, k in PATH_HINTS:
                if pat.search(s):
                    kind = k
                    break
            if not kind:
                continue
            key = (kind, s)
            if key in found:
                continue
            found[key] = {
                "kind": kind,
                "path": s,
                "direction": "read" if "read" in kind else ("write" if "write" in kind else "in"),
                "attacker_reachable": "",
                "reachability": "",
                "notes": f"Detected as string in {f.get('name', '?')} @ 0x{f.get('address')}",
            }
    return list(found.values())


def detect_inputs_from_chains(chains: list[dict], taxonomy: dict) -> list[dict]:
    """Each chain.source whose `source_calls` overlaps a known taxonomy category
    becomes an input candidate, classified by category."""
    out: list[dict] = []
    seen: set[tuple] = set()
    # Map symbol -> taxonomy category
    sym_cat: dict[str, str] = {}
    for cat, body in taxonomy.items():
        for sym in body.get("symbols") or []:
            sym_cat[sym] = cat
    for ch in chains:
        calls = ch.get("source_calls") or []
        cats = {sym_cat[c] for c in calls if c in sym_cat}
        if not cats:
            continue
        for cat in cats:
            kind_map = {
                "network_input": "network_listen",
                "ioctl_input": "ioctl",
                "file_input": "file_read",
                "ipc_input": "ipc_alpc",
                "user_kernel_boundary": "ioctl",
                "argv": "cmdline",
                "stdin_input": "stdin",
                "cgi_input": "network_listen",
                "dbus_input": "ipc_dbus",
            }
            kind = kind_map.get(cat, cat)
            path = f"{ch.get('source_name', '?')} @ 0x{ch.get('source_addr', '?')}"
            key = (kind, path)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "kind": kind,
                "path": path,
                "direction": "in",
                "attacker_reachable": "",
                "reachability": "",
                "notes": f"From chains.json (taxonomy category: {cat}; APIs: {', '.join(calls[:3])})",
            })
    return out


def aggregate_notable_strings(funcs: list[dict], cap: int = 30) -> list[str]:
    counts: dict[str, int] = {}
    for f in funcs:
        for s in f.get("strings") or []:
            if not s or len(s) < 6 or len(s) > 80:
                continue
            # Filter noise
            if any(p.match(s) for p in NOISE_PATTERNS):
                continue
            # Prefer interesting characters: paths, dots, slashes
            score = 1
            if any(c in s for c in (":\\", "\\\\", ".dll", ".json", ".sys", "://", "HKEY", "HKLM", "HKCU")):
                score += 5
            if any(s.lower().startswith(p) for p in ("c:\\", "\\\\.", "\\\\?", "\\device\\", "hkey")):
                score += 5
            counts[s] = counts.get(s, 0) + score
    # Top N by score
    return [s for s, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:cap]]


def build_rva_anchors(funcs: list[dict], triage: list[dict]) -> dict:
    out: dict[str, str] = {}
    by_addr = {f.get("address"): f for f in funcs}
    by_name = {f.get("name"): f for f in funcs}
    # Add canonical entries
    for ce in CANONICAL_ENTRIES + CRT_ENTRIES:
        if ce in by_name:
            out[ce] = "0x" + by_name[ce]["address"]
    # Add user-renamed (vb_ prefix from Ghidra MCP convention)
    for f in funcs:
        n = f.get("name", "")
        if n.startswith("vb_") and n not in out:
            out[n] = "0x" + f["address"]
    # Add triage-rated >=3 functions
    for entry in (triage or []):
        if not isinstance(entry, dict):
            continue
        rating = entry.get("rating") or entry.get("score") or 0
        try:
            rating = int(rating)
        except (TypeError, ValueError):
            rating = 0
        if rating < 3:
            continue
        addr = entry.get("address") or entry.get("addr")
        name = entry.get("name") or entry.get("function") or ""
        if addr and name and name not in out:
            addr_str = str(addr)
            if addr_str.startswith("0x"):
                addr_str = addr_str[2:]
            out[name] = f"0x{addr_str}"
    # Cap
    return dict(list(out.items())[:15])


# ---------------------------------------------------------------------------
# Sink scan + capability synthesis + backward reachability
# ---------------------------------------------------------------------------
def detect_sinks(funcs: list[dict]) -> list[dict]:
    """Aggressive scan: every callee that matches a known sink API becomes a
    SNK candidate, with one callsite per containing function."""
    by_api: dict[str, dict] = {}  # api_name -> {category, callsites: [{addr, function}]}
    for f in funcs:
        for callee in f.get("callees") or []:
            cat = API_TO_CATEGORY.get(callee)
            if not cat:
                continue
            entry = by_api.setdefault(callee, {"name": callee, "category": cat, "callsites": []})
            entry["callsites"].append({
                "addr": "0x" + f["address"],
                "function": f.get("name") or f"FUN_{f['address']}",
            })
    out: list[dict] = []
    for name, entry in sorted(by_api.items()):
        meta = SINK_API_LIBRARY.get(entry["category"], {})
        out.append({
            "name": name,
            "category": entry["category"],
            "callsites": entry["callsites"][:25],  # cap per-API
            "cwe": meta.get("default_cwe", ""),
            "impact": meta.get("impact", ""),
            "function": entry["callsites"][0]["function"] if entry["callsites"] else "",
            "confirmed": False,
            "notes": f"Auto-detected from function_index.json scan ({len(entry['callsites'])} callsite(s))",
        })
    return out


def synthesize_capabilities(sinks: list[dict]) -> list[dict]:
    """Group sinks by category into capability candidates."""
    by_cat: dict[str, list[str]] = {}  # category -> [sink names]
    for s in sinks:
        cat = s.get("category")
        if not cat:
            continue
        by_cat.setdefault(cat, []).append(s.get("name", ""))
    caps: list[dict] = []
    for cat, sink_names in sorted(by_cat.items()):
        meta = SINK_API_LIBRARY.get(cat, {})
        caps.append({
            "name": meta.get("capability_name", cat),
            "category": cat,
            "sinks_by_name": sink_names,  # caller will resolve to SNK-* IDs
            "reachable_from": {"entry_funcs": [], "inputs": []},
            "user_action": "",
            "preconditions": [],
            "impact": meta.get("impact", ""),
            "confirmed": False,
            "notes": f"Auto-synthesised from {len(sink_names)} sink callee(s) in this category",
        })
    return caps


def compute_backward_reachability(funcs: list[dict], sinks: list[dict],
                                   max_hops: int = 8) -> dict[str, list[str]]:
    """For each sink, BFS backward through the `callers` chain to find which
    top-level functions (zero callers OR canonical-entry name) can reach it.
    Returns: sink_api -> sorted list of entry function names."""
    by_addr: dict[str, dict] = {f["address"]: f for f in funcs}
    by_name: dict[str, dict] = {f.get("name", ""): f for f in funcs}

    def is_entry_candidate(f: dict) -> bool:
        n = f.get("name", "")
        if any(ce in n for ce in (CANONICAL_ENTRIES + CRT_ENTRIES)):
            return True
        if not f.get("callers"):
            return True
        if f.get("is_exported"):
            return True
        # Heuristic: looks like an IPC dispatch/handler if name contains common patterns
        if any(p in n.lower() for p in ("dispatch", "handler", "ioctl", "ipchandler", "request", "command")):
            return True
        return False

    out: dict[str, list[str]] = {}
    for s in sinks:
        api = s.get("name", "")
        # Seed BFS from each callsite
        seeds = []
        for cs in s.get("callsites") or []:
            addr = (cs.get("addr") or "")
            if addr.startswith("0x"):
                addr = addr[2:]
            if addr in by_addr:
                seeds.append(by_addr[addr])
        visited: set[str] = set()
        entries: set[str] = set()
        frontier = [(seed, 0) for seed in seeds]
        while frontier:
            cur, hops = frontier.pop(0)
            key = cur.get("address", "")
            if key in visited:
                continue
            visited.add(key)
            n = cur.get("name", "")
            valid_callers = [c for c in (cur.get("callers") or []) if c in by_name]
            # Mark as entry if EITHER a recognised entry candidate, OR we cannot walk further
            # (top of the reachable call-tree). Skip CRT bootstrap and Ghidra-noise leaf names.
            is_terminal = not valid_callers or hops >= max_hops
            qualifies = is_entry_candidate(cur) or is_terminal
            if qualifies and n and n not in CRT_ENTRIES and not _is_pure_noise(n):
                entries.add(n)
            if hops >= max_hops:
                continue
            for caller_name in valid_callers:
                frontier.append((by_name[caller_name], hops + 1))
        out[api] = sorted(entries)[:15]
    return out


def _is_pure_noise(name: str) -> bool:
    """Drop only the CRT/runtime helpers; keep FUN_* (they're real top-of-tree handlers)."""
    if not name:
        return True
    return name.startswith(("__scrt_", "__crt", "__std_", "_initterm", "_security_", "__report_"))


def map_entries_to_inputs(entries: list[str], inputs: list[dict], funcs: list[dict]) -> list[str]:
    """Heuristic: an entry function name -> probable INP-* IDs by string-overlap
    against input paths/names. Look at the entry function's strings AND its name."""
    out: set[str] = set()
    by_name = {f.get("name", ""): f for f in funcs}
    for entry_name in entries:
        f = by_name.get(entry_name)
        haystack_parts = [entry_name]
        if f:
            haystack_parts.extend(f.get("strings") or [])
        haystack = " ".join(haystack_parts).lower()
        for inp in inputs:
            inp_id = inp.get("id")
            inp_path = (inp.get("path") or "").lower()
            if not inp_id or not inp_path:
                continue
            # match: full path or distinctive token
            if inp_path in haystack:
                out.add(inp_id)
                continue
            tokens = [t for t in re.split(r"[\\/\s.]+", inp_path) if len(t) > 5]
            for t in tokens:
                if t in haystack:
                    out.add(inp_id)
                    break
    return sorted(out)


# ---------------------------------------------------------------------------
# Build & merge
# ---------------------------------------------------------------------------
def build_re_block(d: DecompData, taxonomy: dict | None) -> dict:
    funcs = d.functions
    inputs_str = detect_inputs_from_strings(funcs)
    inputs_chain = detect_inputs_from_chains(d.chains, taxonomy or {})
    # Dedupe by (kind, path); chain-derived wins over string-derived for the same (kind, path)
    merged: dict[tuple, dict] = {}
    for inp in inputs_str:
        merged[(inp["kind"], inp["path"])] = inp
    for inp in inputs_chain:
        merged[(inp["kind"], inp["path"])] = inp
    inputs = list(merged.values())

    # Cap to 50; sort: ioctl/network first, then ipc, then file/registry
    kind_order = {"ioctl": 0, "network_listen": 1, "network_connect": 1,
                  "ipc_pipe": 2, "ipc_alpc": 2, "ipc_dbus": 2, "ipc_msgbus": 2,
                  "file_read": 3, "file_write": 3, "registry_read": 4, "registry_write": 4,
                  "cmdline": 5, "stdin": 5}
    inputs.sort(key=lambda i: (kind_order.get(i["kind"], 9), i["path"]))
    inputs = inputs[:50]

    return {
        "entrypoint": detect_entrypoint(funcs),
        "loaded_modules": detect_loaded_modules(funcs),
        "inputs": inputs,
        "behavior": "",
        "notable_strings": aggregate_notable_strings(funcs),
        "rva_anchors": build_rva_anchors(funcs, d.triage),
        "notes": "",
    }


def assign_ids(items: list[dict], prefix: str, existing_ids: set[str]) -> list[dict]:
    """Generic ID assigner — used for SNK-* / CAP-* / INP-*."""
    used = set(existing_ids)
    counter = 1
    for item in items:
        if item.get("id"):
            used.add(item["id"])
            continue
        while True:
            cand = f"{prefix}-{counter:03d}"
            counter += 1
            if cand not in used:
                used.add(cand)
                item["id"] = cand
                break
    return items


def merge_sinks(existing: list[dict], new: list[dict]) -> tuple[list[dict], int]:
    """Merge by `name` (the API name). Existing entries' hand-edited fields win."""
    existing_by_name: dict[str, dict] = {s.get("name"): s for s in existing if s.get("name")}
    existing_ids: set[str] = {s.get("id") for s in existing if s.get("id")}
    additions: list[dict] = []
    for ns in new:
        name = ns.get("name")
        if name in existing_by_name:
            cur = existing_by_name[name]
            # Backfill empty fields only
            for k in ("category", "cwe", "impact", "function"):
                if not (cur.get(k) or "") and ns.get(k):
                    cur[k] = ns[k]
            # Merge callsites by addr
            cur_cs = {(cs.get("addr"), cs.get("function")) for cs in (cur.get("callsites") or [])}
            for cs in ns.get("callsites") or []:
                key = (cs.get("addr"), cs.get("function"))
                if key not in cur_cs:
                    cur.setdefault("callsites", []).append(cs)
                    cur_cs.add(key)
            continue
        additions.append(ns)
    additions = assign_ids(additions, "SNK", existing_ids)
    return existing + additions, len(additions)


def merge_capabilities(existing: list[dict], new: list[dict],
                       sink_name_to_id: dict[str, str]) -> tuple[list[dict], int]:
    """Merge by category. Existing capabilities' hand-edited names/notes/user_action win.
    Resolve `sinks_by_name` -> SNK-* IDs."""
    existing_by_cat: dict[str, dict] = {c.get("category"): c for c in existing if c.get("category")}
    existing_ids: set[str] = {c.get("id") for c in existing if c.get("id")}
    additions: list[dict] = []
    for nc in new:
        cat = nc.get("category")
        sink_ids = sorted({sink_name_to_id[n] for n in (nc.get("sinks_by_name") or []) if n in sink_name_to_id})
        nc.pop("sinks_by_name", None)
        nc["sinks"] = sink_ids
        if cat in existing_by_cat:
            cur = existing_by_cat[cat]
            # Merge sink list
            cur_sinks = set(cur.get("sinks") or [])
            for sid in sink_ids:
                if sid not in cur_sinks:
                    cur.setdefault("sinks", []).append(sid)
                    cur_sinks.add(sid)
            # Backfill empty fields
            for k in ("name", "user_action", "impact"):
                if not (cur.get(k) or "") and nc.get(k):
                    cur[k] = nc[k]
            # Merge reachable_from.entry_funcs
            cur_rf = cur.setdefault("reachable_from", {"entry_funcs": [], "inputs": []})
            for ef in (nc.get("reachable_from") or {}).get("entry_funcs", []):
                if ef not in cur_rf.get("entry_funcs", []):
                    cur_rf.setdefault("entry_funcs", []).append(ef)
            for ip in (nc.get("reachable_from") or {}).get("inputs", []):
                if ip not in cur_rf.get("inputs", []):
                    cur_rf.setdefault("inputs", []).append(ip)
            continue
        additions.append(nc)
    additions = assign_ids(additions, "CAP", existing_ids)
    return existing + additions, len(additions)


def assign_input_ids(inputs: list[dict], existing_ids: set[str]) -> list[dict]:
    """Assign INP-NNN to entries lacking an ID; preserve existing IDs."""
    used = set(existing_ids)
    counter = 1
    for inp in inputs:
        if inp.get("id"):
            used.add(inp["id"])
            continue
        while True:
            cand = f"INP-{counter:03d}"
            counter += 1
            if cand not in used:
                used.add(cand)
                inp["id"] = cand
                break
    return inputs


def merge_re_block(existing_re: dict, new_re: dict) -> dict:
    """Idempotent merge — never clobber hand-edited fields."""
    out = dict(existing_re or {})

    # Scalar fields: keep existing if non-empty
    for k in ("entrypoint", "behavior", "notes"):
        if not (out.get(k) or "").strip():
            out[k] = new_re.get(k, "")

    # loaded_modules: merge by name
    existing_mods = {m.get("name"): m for m in (out.get("loaded_modules") or []) if m.get("name")}
    for m in new_re.get("loaded_modules") or []:
        n = m.get("name")
        if n and n not in existing_mods:
            existing_mods[n] = m
    out["loaded_modules"] = list(existing_mods.values())

    # inputs: merge by (kind, path); preserve existing IDs
    existing_inputs = list(out.get("inputs") or [])
    existing_keys = {(i.get("kind"), i.get("path")): i for i in existing_inputs}
    existing_ids = {i.get("id") for i in existing_inputs if i.get("id")}
    additions = []
    for inp in new_re.get("inputs") or []:
        key = (inp.get("kind"), inp.get("path"))
        if key in existing_keys:
            # Backfill empty fields on the existing entry from the auto-extract
            cur = existing_keys[key]
            for k in ("direction", "reachability", "notes", "attacker_reachable"):
                if not (cur.get(k) or "").strip() and inp.get(k):
                    cur[k] = inp[k]
        else:
            additions.append(inp)
    additions = assign_input_ids(additions, existing_ids)
    out["inputs"] = existing_inputs + additions

    # notable_strings: union, preserving existing order
    existing_ns = list(out.get("notable_strings") or [])
    extras = [s for s in (new_re.get("notable_strings") or []) if s not in existing_ns]
    out["notable_strings"] = existing_ns + extras[:max(0, 30 - len(existing_ns))]

    # rva_anchors: merge dict, existing wins
    existing_anchors = dict(out.get("rva_anchors") or {})
    for k, v in (new_re.get("rva_anchors") or {}).items():
        if k not in existing_anchors:
            existing_anchors[k] = v
    out["rva_anchors"] = existing_anchors

    return out


def derive_back_links(binary_yaml: dict) -> int:
    """For every source without `derived_from`, try to find the unambiguous
    matching INP-* by path/function overlap. Returns count of links added."""
    sources = binary_yaml.get("sources") or []
    re_block = binary_yaml.get("reverse_engineering") or {}
    inputs = re_block.get("inputs") or []
    if not inputs:
        return 0
    added = 0
    for src in sources:
        if src.get("derived_from"):
            continue
        haystack = " ".join([
            (src.get("name") or ""),
            (src.get("function") or ""),
            (src.get("via") or ""),
            (src.get("notes") or ""),
        ]).lower()
        if not haystack.strip():
            continue
        candidates = []
        for inp in inputs:
            inp_path = (inp.get("path") or "").lower()
            if not inp_path:
                continue
            # match: input path occurs in source haystack, OR vice-versa
            if inp_path in haystack or any(tok in haystack for tok in inp_path.split("\\") if len(tok) > 4):
                candidates.append(inp.get("id"))
        if len(candidates) == 1:
            src["derived_from"] = candidates[0]
            added += 1
    return added


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def load_taxonomy() -> dict:
    if TAXONOMY.exists():
        try:
            return json.loads(TAXONOMY.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def yaml_path_for_binary(binary: str) -> Path:
    """Use the same lowercase-snake-cased convention as catalog_seed.binary_yaml_filename."""
    stem = re.sub(r"[^A-Za-z0-9]+", "_", binary.lower()).strip("_")
    return CATALOG / f"{stem}.yml"


def discover_binaries_in_eng(eng_dir: Path) -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    for d in sorted(eng_dir.glob("decomp*")) + sorted(eng_dir.glob("*_decomp")):
        idx = d / "function_index.json"
        if not idx.exists():
            continue
        try:
            data = json.loads(idx.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        binary = Path(data.get("binary") or "").name
        if binary:
            out.append((binary, d))
    return out


def process_one(eng_dir: Path, binary: str, decomp_dir: Path | None,
                apply: bool, verbose: bool) -> dict:
    if decomp_dir is None:
        decomp_dir = find_decomp_dir(eng_dir, binary)
    if decomp_dir is None:
        return {"binary": binary, "status": "no_decomp_found"}

    d = load_decomp(decomp_dir, binary)
    attach_chains_triage(d, eng_dir)
    taxonomy = load_taxonomy()
    new_re = build_re_block(d, taxonomy)

    # Aggressive sink scan + capability synthesis
    new_sinks = detect_sinks(d.functions)
    new_caps = synthesize_capabilities(new_sinks)
    # Backward reachability per sink → entries
    backward = compute_backward_reachability(d.functions, new_sinks)

    yaml_path = yaml_path_for_binary(binary)
    existing_yaml = {}
    if yaml_path.exists():
        try:
            existing_yaml = yaml.safe_load(yaml_path.read_text()) or {}
        except yaml.YAMLError as e:
            return {"binary": binary, "status": "yaml_parse_error", "error": str(e)}

    existing_re = existing_yaml.get("reverse_engineering") or {}
    # Preserve existing IDs by walking inputs already present
    new_re_inputs = new_re.get("inputs") or []
    existing_ids = {i.get("id") for i in (existing_re.get("inputs") or []) if i.get("id")}
    new_re["inputs"] = assign_input_ids(new_re_inputs, existing_ids)

    merged_re = merge_re_block(existing_re, new_re)

    # Merge sinks (top-level YAML key)
    existing_sinks = existing_yaml.get("sinks") or []
    merged_sinks, sinks_added = merge_sinks(existing_sinks, new_sinks)
    sink_name_to_id = {s.get("name"): s.get("id") for s in merged_sinks if s.get("name") and s.get("id")}

    # Inject backward-reachability entry_funcs into capabilities
    for cap in new_caps:
        entry_funcs: set[str] = set()
        for sink_name in (cap.get("sinks_by_name") or []):
            entry_funcs.update(backward.get(sink_name, []))
        # Map entries to inputs (best-effort)
        cap["reachable_from"]["entry_funcs"] = sorted(entry_funcs)[:15]
        cap["reachable_from"]["inputs"] = map_entries_to_inputs(
            list(entry_funcs), merged_re.get("inputs") or [], d.functions
        )

    # Merge capabilities
    existing_caps = existing_yaml.get("capabilities") or []
    merged_caps, caps_added = merge_capabilities(existing_caps, new_caps, sink_name_to_id)

    summary = {
        "binary": binary,
        "decomp_dir": str(decomp_dir.relative_to(ROOT)),
        "yaml_path": str(yaml_path.relative_to(ROOT)) if yaml_path.exists() else None,
        "entrypoint": merged_re.get("entrypoint"),
        "loaded_modules": len(merged_re.get("loaded_modules") or []),
        "inputs_total": len(merged_re.get("inputs") or []),
        "inputs_added": len(merged_re.get("inputs") or []) - len(existing_re.get("inputs") or []),
        "sinks_total": len(merged_sinks),
        "sinks_added": sinks_added,
        "capabilities_total": len(merged_caps),
        "capabilities_added": caps_added,
        "notable_strings": len(merged_re.get("notable_strings") or []),
        "rva_anchors": len(merged_re.get("rva_anchors") or {}),
    }

    if apply and yaml_path.exists():
        existing_yaml["reverse_engineering"] = merged_re
        existing_yaml["sinks"] = merged_sinks
        existing_yaml["capabilities"] = merged_caps
        added = derive_back_links(existing_yaml)
        summary["derived_from_added"] = added
        yaml_path.write_text(yaml.safe_dump(existing_yaml, sort_keys=False, width=120))
        summary["status"] = "applied"
    elif apply and not yaml_path.exists():
        # Create a minimal stub YAML
        stub = {
            "binary": binary,
            "display_name": binary,
            "description": "(Auto-created by catalog_re_extract — fill in.)",
            "platform": "windows",
            "binary_kind": "exe" if binary.endswith(".exe") else ("dll" if binary.endswith(".dll") else "sys" if binary.endswith(".sys") else ""),
            "reverse_engineering": merged_re,
            "sources": [],
            "sinks": merged_sinks,
            "capabilities": merged_caps,
            "chains": [],
        }
        yaml_path.write_text(yaml.safe_dump(stub, sort_keys=False, width=120))
        summary["status"] = "created_stub"
    else:
        summary["status"] = "preview"
        summary["preview_yaml"] = yaml.safe_dump(
            {"reverse_engineering": merged_re,
             "sinks": merged_sinks,
             "capabilities": merged_caps}, sort_keys=False, width=120)

    if verbose:
        print(json.dumps({k: v for k, v in summary.items() if k != "preview_yaml"}, indent=2), file=sys.stderr)
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--eng", help="engagement slug under engagements/")
    ap.add_argument("--binary", help="binary filename (e.g. ProductAgentService.exe)")
    ap.add_argument("--decomp-dir", help="explicit decomp dir (overrides auto-discovery)")
    ap.add_argument("--all", action="store_true", help="all binaries with decomp in the engagement")
    ap.add_argument("--apply", action="store_true", help="merge into catalog/binaries/<name>.yml (default: preview)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if not args.eng and not args.decomp_dir:
        ap.error("must pass --eng or --decomp-dir")

    eng_dir = ENG / args.eng if args.eng else (Path(args.decomp_dir).resolve().parent)
    if not eng_dir.exists():
        print(f"ERROR: engagement not found: {eng_dir}", file=sys.stderr)
        return 2

    targets: list[tuple[str, Path | None]] = []
    if args.all:
        for binary, ddir in discover_binaries_in_eng(eng_dir):
            targets.append((binary, ddir))
    elif args.binary:
        ddir = Path(args.decomp_dir).resolve() if args.decomp_dir else None
        targets.append((args.binary, ddir))
    else:
        ap.error("must pass --binary or --all")

    if not targets:
        print(f"no binaries with decomp in {eng_dir}", file=sys.stderr)
        return 1

    results = []
    for binary, ddir in targets:
        r = process_one(eng_dir, binary, ddir, args.apply, args.verbose)
        results.append(r)
        if not args.apply and r.get("preview_yaml"):
            print(f"# === {binary} (preview only — pass --apply to merge) ===")
            print(r["preview_yaml"])
        else:
            status_label = r.get("status", "?")
            extras = []
            if r.get("inputs_added") is not None:
                extras.append(f"inputs_added={r['inputs_added']}")
            if r.get("derived_from_added") is not None:
                extras.append(f"derived_from_added={r['derived_from_added']}")
            print(f"{binary:40s} {status_label:18s} {' '.join(extras)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
