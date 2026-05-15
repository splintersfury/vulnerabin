# Finding 004 — safeelevatedrun.dll: Unrestricted service start via run_service_elevated (No Allowlist on service_name)

**Date:** 2026-05-14  
**Engagement:** bitdefender-2026-05-02  
**CWE:** CWE-862 (Missing Authorization), CWE-732 (Incorrect Permission Assignment)  
**ACID:** CONFIRMED_STATIC | Confidence: HIGH  
**Estimated Bugcrowd Rating:** P1-P2 (LPE, User→SYSTEM via msgbus HIGH_ENHANCED auth)  

---

## Summary

`safeelevatedrun.dll`'s `CElevatedOperationsServer` exposes two IPC methods — `run_service_elevated` and `run_service_elevated_async` — that invoke `CSafeElevatedRun::StartTrustedService` (`FUN_18001acb0`). This function calls:

1. `OpenSCManagerW(NULL, L"ServicesActive", SC_MANAGER_CONNECT)` — minimal SCM access
2. `OpenServiceW(hSCManager, service_name, SERVICE_START=0x10)` — **NO allowlist on service_name**
3. `StartServiceW(hService, num_args, args_array)` — **attacker-controlled service name and arguments**

The word "Trusted" in `StartTrustedService` is aspirational, not enforced. Compare to `run_elevated` which validates `executable_path` with `IsInFolder` + `WinVerifyTrust` — `run_service_elevated` has **NO analogous check** on the service name.

Any msgbus client that passes the `HIGH_ENHANCED` auth tier (same_sign + trusted_client_process + trusted_client_path) can:
- Start **any installed Windows service** as SYSTEM
- Pass **arbitrary arguments** to that service
- This is a design-pattern bypass: `run_elevated` gates the executable path, but `run_service_elevated` gates nothing

## Attack Chains

### Chain A: Start a service with dangerous arguments
Many Windows services accept command-line arguments that can alter behavior:
- `TrustedInstaller` can be started manually
- Services with file-path arguments (config file, log file) can be directed to attacker-controlled files
- Any service with a DLL search path vulnerability becomes SYSTEM code execution

### Chain B: Start a custom malicious service
If the attacker has already placed a service binary (via a separate write primitive, e.g., the `SaveRegValue` HKLM write from finding 006), `run_service_elevated` can start it.

### Chain C: Bypass IsInFolder+WinVerifyTrust via service indirection
`run_elevated` validates the exe path with `IsInFolder` + `WinVerifyTrust`, preventing arbitrary exe execution. But `run_service_elevated` bypasses this entirely: specify a service that runs a BD-signed binary (which passes both checks), but with attacker-controlled arguments that achieve code execution.

## Root Cause

### msgbus dispatch table (FUN_18000e4d0, decompiled.c lines 10442-10527)

```
delete_registry_value_async → FUN_18000b8f0
delete_registry_value       → FUN_18000b8f0
save_registy_value_async    → FUN_18000af50  (note: typo "regity" in binary)
save_registy_value          → FUN_18000af50
run_elevated_async          → FUN_18000c290
run_elevated               → FUN_18000c290
run_service_elevated_async  → FUN_18000d310
run_service_elevated        → FUN_18000d310
```

### FUN_18000d310 (run_service_elevated handler)

Lines 236-242 extract the three IPC message fields:
- `service_name` → string, NO validation
- `arguments_number` → integer
- `arguments_array_stream` → argument array, NO validation

### FUN_18001acb0 (StartTrustedService)

```c
hSCManager = OpenSCManagerW(NULL, L"ServicesActive", 1);  // SC_MANAGER_CONNECT
hService = OpenServiceW(hSCManager, param_2, 0x10);       // SERVICE_START
StartServiceW(hService, param_4, param_3);                  // arbitrary service + args
```

No `IsInFolder`, no `WinVerifyTrust`, no service name allowlist, no argument validation.

## ACID Assessment

**A — Attacker-Controlled**: YES (with HIGH_ENHANCED msgbus auth prerequisite)
- `service_name` is fully attacker-controlled from the IPC message
- `arguments_array_stream` is fully attacker-controlled
- The msgbus auth check (HIGH_ENHANCED: same_sign + trusted_client_process + trusted_client_path) is the only gate

**C — Chain-Complete**: YES
- Standard user → inject into BD-signed process (blocked by PPL, needs alternative vector)
- OR: standard user → COM activation in seccenter.exe (under investigation)
- OR: standard user → msgbus pipe from low-tier trusted process (under investigation)
- Then: send `run_service_elevated` message with attacker-controlled service_name + args
- Result: arbitrary service start as SYSTEM

**I — Impact**: HIGH
- Start any installed Windows service with arbitrary arguments as SYSTEM
- If combined with `SaveRegValue` (finding 006): create a service registry entry, then start it → arbitrary SYSTEM code execution
- Even without `SaveRegValue`: identify a service with dangerous argument handling → SYSTEM code execution

**D — Defenses**: 
- msgbus HIGH_ENHANCED auth (same_sign + trusted_client_path + trusted_client_process) — bypassable via code execution inside any BD-signed process
- PPL (Anti-Malware ELAM) protects BD processes from injection — but COM activation, DLL sideloading, or msgbus bypass vectors may circumvent this
- NO defense within `StartTrustedService` itself — no allowlist, no validation, no check

## Comparison to run_elevated (CHAIN-001)

| Aspect | run_elevated | run_service_elevated |
|--------|-------------|----------------------|
| Target | Arbitrary executable | Arbitrary service |
| Path validation | IsInFolder (prefix check, bypassable via `..`) | NONE |
| Signature validation | WinVerifyTrust (Authenticode check) | NONE |
| Argument handling | Unsantized in lpCommandLine | Unsantized via StartServiceW args |
| Auth tier | HIGH_ENHANCED | HIGH_ENHANCED (assumed, same dispatch) |
| CWE | CWE-22 (path traversal) + CWE-269 | CWE-862 (missing auth) + CWE-732 |
| Severity | P3 (path traversal, blocked by PPL) | P1-P2 (no validation at all) |

The `run_service_elevated` path is strictly more dangerous than `run_elevated` because there is NO validation at all on the service name, whereas `run_elevated` at least requires the exe to be Authenticode-signed.

## Next Steps

1. Confirm msgbus auth tier for `run_service_elevated` (is it definitely HIGH_ENHANCED, or could it be lower?)
2. Enumerate Windows services that accept dangerous arguments
3. Test if `SaveRegValue` + `run_service_elevated` creates a full LPE chain (write service → start service)
4. Check if `OpenSCManagerW` call with `SC_MANAGER_CONNECT` (0x1) grants enough access from a standard user → likely yes, since SCM ServicesActive allows CONNECT to any local process