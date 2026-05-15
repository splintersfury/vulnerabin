# Finding 002: CSafeElevatedRun::Run — WinVerifyTrust TOCTOU (CWE-367)

## Status
UNCERTAIN — requires VM timing verification

## Summary
`CSafeElevatedRun::Run` (FUN_180017440 in safeelevatedrun.dll) verifies the Authenticode signature of a target executable with `WinVerifyTrust`, then passes the same path to `CreateProcessAsUserW`. There is a race window between the signature check and process launch. An attacker who can substitute the file between these calls can execute unsigned/malicious code in a different user's session.

## ACID Assessment

### A — Attacker-Controlled
- The executable path (`param_2`) is supplied by the msgbus caller
- `CSafeElevatedRun::Run` is invoked via `CElevatedOperationsServer::_SafeElevatedRun` over the ElevatedOperations msgbus channel
- Caller must pass the `trusted_client_process` check to reach this code
- Attack pre-condition: ability to call ElevatedOperations::SafeElevatedRun AND write access to the path specified

### C — Chain-Complete
```
ElevatedOperations msgbus caller
    → CElevatedOperationsServer::_SafeElevatedRun (FUN_18000c290)
    → CSafeElevatedRun::Run (FUN_180017440)
    → FUN_1800184c0: calls FUN_180016d00 → WinVerifyTrust(path) → returns success
    [RACE WINDOW: attacker swaps file at path to malicious binary]
    → FUN_180002f20 → FUN_180003120: CreateProcessAsUserW(token, NULL, path, ...)
    → malicious binary executes in target session
```

### I — Impact
- Execute arbitrary code in another Windows session (e.g., admin session) as that session's user
- If the target session is an admin, this achieves LPE from standard user to admin

### D — Defenses
1. **WinVerifyTrust**: Validates Authenticode signature — requires initial path to point to a valid signed binary
2. **Access to ElevatedOperations**: Caller must be trusted process
3. **Race window**: Must be exploitable — depends on filesystem latency and path. Tight races on local NTFS may be hard to win reliably.
4. **File locking**: WinVerifyTrust may hold a file handle open, blocking substitution

## Evidence

### FUN_180017440 (CSafeElevatedRun::Run)
`decomp-safeelevatedrun/functions/FUN_180017440.c`:
```c
cVar5 = FUN_1800184c0(param_1, param_2);  // Signature check
if (cVar5 != '\0') {
    // [TOCTOU WINDOW HERE]
    uVar6 = FUN_180002f20(param_2, param_5, param_4, param_3);  // Execute
}
```

### FUN_1800184c0 (authorization + WinVerifyTrust)
```c
FUN_180016d00((LPCWSTR)pppppWVar7, (DWORD *)&local_100);  // WinVerifyTrust wrapper
// logs: "signature for", "failed get signature for", "not trusted path="
```

### FUN_180016d00 (WinVerifyTrust wrapper)
```c
local_38.Data1 = 0xaac56b;  // WINTRUST_ACTION_GENERIC_VERIFY_V2
local_50 = param_1;          // the file path
uVar2 = WinVerifyTrust((HWND)0x0, &local_38, &local_b8);
if (uVar2 == 0) { *param_2 = 0; /* trusted */ }
```

### FUN_180003120 (ExecuteProcessAsUser)
```c
CreateProcessAsUserW(param_3, (LPCWSTR)0x0, local_4f8, ...)
// local_4f8 built from param_1 (same path as WinVerifyTrust target)
```

## PoC Sketch
```
Prerequisites:
1. Trusted BD process access (or run from trusted path)
2. Write permission to a path pointing to a Bitdefender-signed executable

Steps:
1. Create a racing thread that continuously replaces target.exe between signed and malicious copies
2. Send ElevatedOperations::SafeElevatedRun(path="<writable path>\\bd_signed_stub.exe", session=1)
3. Race: when WinVerifyTrust completes on the signed stub, swap to malicious.exe before CreateProcessAsUserW
4. Malicious binary executes in session 1
```

## Verdict
UNCERTAIN — moderate complexity TOCTOU, blocked by:
- Access gate (need trusted_client_process)
- File locking during WinVerifyTrust (may close handle before CreateProcessAsUserW)
- Need writable path with signed binary

Requires VM testing. CWE-367 (TOCTOU Race Condition During File Access).
