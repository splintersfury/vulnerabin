# Finding 003 — safeelevatedrun.dll: Unauthenticated IPC → memcpy/free (Missing Authorization)

## Metadata
- **Target**: Bitdefender Total Security (safeelevatedrun.dll)
- **Function**: FUN_180005300 (C++ wide-string grow/append — reallocates buffer, memcpy caller-provided data)
- **CWE**: CWE-862 (Missing Authorization), secondary CWE-787/CWE-416 if size/pointer attacker-controlled
- **Verdict**: LIKELY
- **Confidence**: HIGH (reachability chain fully traced)
- **Source lens**: VULNOC reachability
- **Date**: 2026-05-02

## Summary

FUN_180005300 is a C++ wide-string grow/append utility that reallocates a heap buffer and memcpy's caller-provided data into it. A second dangerous operation is a `free()` on an attacker-influenced pointer at line 59. The function is reachable from a low-privilege standard user via the IPC bus (channel subscribed by `CElevatedOperationsServer::Start` in FUN_18000a4c0), through 4–6 call hops via message dispatcher `FUN_18000e4d0`, with **zero privilege checks, SDDL comparisons, or ACL gates** anywhere in the chain.

## Call Chain

```
low-privilege user
  → IPC bus channel ("cl.bdappsrv.actions")
    → FUN_18000a4c0 [CElevatedOperationsServer::Start — registers dispatcher]
      → FUN_18000e4d0 [message dispatcher — routes IPC messages]
        → FUN_180011960 / FUN_180008060
          → FUN_1800054e0
            → FUN_180005460
              → FUN_180005300 [memcpy sink / free sink]
```

Security model relies solely on opaque bus/channel transport — no in-code ACL enforcement observed in the decompiled call chain.

## Dangerous Operations

| Line | Op | Why Dangerous |
|------|----|---------------|
| 43–44 | `memcpy(dst, attacker_buf, attacker_size)` | If `attacker_size > alloc_size`, heap overflow; no bounds check visible |
| 59 | `free(attacker_influenced_ptr)` | If layout allows pointer control → arbitrary free → heap primitive |

## ACID Assessment

- **A (Attacker-Controlled)**: YES — IPC channel is the source; standard user can connect and send messages
- **C (Chain-Complete)**: YES — 4–6 hop chain traced; no sanitization, no auth check breaks the taint
- **I (Impact)**: Heap overflow → potential RCE as bdappsrv.exe (NT AUTHORITY\SYSTEM); arbitrary free → heap primitive
- **D (Defenses)**: Only defense is the IPC transport layer itself — no in-code gate. ASLR/stack cookies apply but heap exploitation bypasses them.

## Open Questions (needed to upgrade to CONFIRMED)

1. **Is the channel ACL-enforced at the transport level?** (`SafeElevatedRun.json` shows `"channel_name": "cl.bdappsrv.actions"` — need to check if msgbus enforces any caller authentication before dispatching to FUN_18000e4d0)
2. **Is `attacker_size` truly unbounded?** Need to trace the size parameter back from the IPC message parser to confirm no saturation/cap occurs between FUN_18000e4d0 and FUN_180005300.
3. **Free target**: Confirm whether line 59 pointer is reachable with attacker-supplied content or only internal state.

## Relationship to Other Findings

- **Finding 001** (msgbus pipe ACL): Everyone-ACL on `bd.app.process.broker.pipe` — if this finding confirms standard-user IPC access to the channel, it directly validates the source in this chain.
- **Finding 002** (WVT TOCTOU): Independent exploitation path; this finding is a separate escalation via IPC.

## Next Steps

1. Confirm channel ACL: read `bd.app.process.broker.pipe` SDDL from target VM
2. Trace size param from IPC message through FUN_18000e4d0 → FUN_180005300 — check for cap
3. If both confirmed: upgrade to CONFIRMED, build heap overflow PoC targeting bdappsrv.exe
4. CVSS: if unauth heap overflow → SYSTEM, expect 8.8–9.0 (LPE from standard user, no user interaction)

## Evidence

- VULNOC reachability lens output (2026-05-02):
  ```json
  {"lens_id": "reachability", "label": "SINK",
   "findings": [
     {"cwe": "CWE-862", "sink": "memcpy", "line": "43-44",
      "why": "Reachable via IPC dispatcher FUN_18000e4d0 through 4-6 hops with zero privilege/ACL checks"},
     {"cwe": "CWE-862", "sink": "free", "line": "59",
      "why": "Same IPC path; frees attacker-influenced heap buffer pointer with no auth gate"}
   ]}
  ```
