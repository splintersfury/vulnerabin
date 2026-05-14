# Finding 005: SafeElevatedRun Registry Operations Have Zero Method-Level Auth Checks

**Severity**: P1 — SYSTEM registry write/delete without authentication checks  
**Status**: CONFIRMED (static analysis)  
**Bead**: vulbead-pmx  
**CVSS**: 6.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N) — pending auth tier confirmation  
**Component**: safeelevatedrun.dll  
**Binary SHA256**: (see catalog)

## Summary

Two of SafeElevatedRun's eight IPC handler methods — `_SaveRegValue` and `_DeleteRegValue` — have **zero method-level authentication checks**. Unlike `_RunElevated` (which validates via `IsInFolder` + `IsTrusted`/WinVerifyTrust), the registry handlers accept their IPC message, parse a GUID-based registry structure, and directly write/delete registry values with no verification of the caller's executable path, signature, or elevation status.

The only auth gate is the **msgbus tier**, controlled by `SafeElevatedRun.json` (runtime config loaded via `IServConfig.dll`). If the config permits `trusted_client_path` or `same_sign` tier access, any client at a trusted path can write/delete SYSTEM registry values.

## Vulnerability Detail

### Method Dispatch (FUN_18000e4d0)

The SafeElevatedRun dispatcher routes IPC messages by method name:

| Method | Handler | Auth Check |
|--------|---------|------------|
| `run_elevated` | FUN_18000c290 | **IsInFolder + IsTrusted (WinVerifyTrust)** |
| `run_elevated_async` | FUN_18000c290 (async) | **IsInFolder + IsTrusted** |
| `run_service_elevated` | FUN_18000d310 | **NONE** |
| `run_service_elevated_async` | FUN_18000d310 (async) | **NONE** |
| `save_regicy_value` | FUN_18000af50 | **NONE** |
| `save_regicy_value_async` | FUN_18000af50 (async) | **NONE** |
| `delete_registry_value` | FUN_18000b8f0 | **NONE** |
| `delete_registry_value_async` | FUN_18000b8f0 (async) | **NONE** |

Note: `save_regicy_value` — the typo isin the binary (missing 't' in registry).

### Evidence: Zero Auth in `_SaveRegValue` (FUN_18000af50)

Static analysis of the 432-line decompiled function:

1. **Line 104**: Reads `registry_structure` from IPC message param
2. **Line 189**: Parses GUID `f788e6ba-a651-4c45-ab83-158b70972fad` from the structure
3. **Line 193**: Looks up registry operation object via vtable
4. **Line 270**: Calls the operation object method — **no auth check before this call**

Searched for auth strings: `IsInFolder`, `IsTrusted`, `WinVerifyTrust`, `trusted`, `verify`, `hash`, `sign`, `cert`, `folder`, `path.*check` → **zero matches**.

### Evidence: Zero Auth in `_DeleteRegValue` (FUN_18000b8f0)

Same analysis pattern. **Zero auth-related strings** in the entire handler function.

### Contrast: `_RunElevated` (FUN_18000c290) HAS Auth

The `_RunElevated` handler calls:
- `FUN_18000e980` (ExePath::IsTrusted) — verifies digital signature via WinVerifyTrust
- `FUN_18000f5d0` (ExePath::IsInFolder) — verifies executable is in BD install folder

These checks are **absent** from registry handlers and `run_service_elevated`.

### Msgbus Auth Tier System

The msgbus security framework (FUN_18003fd10 in msgbus.dll) defines 6 security rule types:

1. `trusted_client_path` — client exe must be in trusted folder
2. `trusted_client_process` — client process hash must match config
3. `same_sign` — client must have same digital signature as BD
4. `admin_client` — client must run as admin (processed by `process_elevated_checker`)
5. `admin_write_client_folder` — admin with write access to client folder
6. `trusted_parent_process` — parent process trust chain

The enforcement point is `gateway_observer::is_allowed` (FUN_180024ef0) in msgbus.dll. Rules are loaded from `SafeElevatedRun.json` via `IServConfig.dll`.

**Critical unknown**: What auth tier does SafeElevatedRun.json assign to `save_regicy_value`, `delete_registry_value`, and `run_service_elevated`? If any of these use `trusted_client_path` or `same_sign`, a standard user at a trusted path (or a BD-signed binary) can invoke them.

## Attack Chain

### Chain A: SaveRegValue + Service Persistence (SYSTEM LPE)

```
Standard user → msgbus pipe → save_regicy_value
  → Write HKLM\SYSTEM\CurrentControlSet\Services\<evil_svc> 
    → ImagePath = attacker binary
  → run_service_elevated → StartServiceW(<evil_svc>)
  → SYSTEM code execution
```

Both methods have ZERO auth. If msgbus permits the call, full SYSTEM LPE.

### Chain B: SaveRegValue → IFEO Debugging (SYSTEM LPE)

```
Standard user → msgbus pipe → save_regicy_value
  → Write HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>\Debugger = <attacker_cmd>
  → When target process launches, attacker code runs as that user context (or SYSTEM if target is SYSTEM service)
```

## Affected Code

| File | Function | Line | Description |
|------|----------|------|-------------|
| safeelevatedrun.dll | FUN_18000af50 (_SaveRegValue) | decompiled.c:~104 | No auth check before registry write |
| safeelevatedrun.dll | FUN_18000b8f0 (_DeleteRegValue) | decompiled.c:~1 | No auth check before registry delete |
| safeelevatedrun.dll | FUN_18000d310 (_RunServiceElevated) | decompiled.c:~1 | No auth check before StartServiceW |
| safeelevatedrun.dll | FUN_18000e4d0 (Dispatch) | decompiled.c:10442 | Routes to handlers; no auth layer |
| msgbus.dll | FUN_18003fd10 (security_rule_keys_builder) | - | 6 auth rule types parsed from config |
| msgbus.dll | FUN_180024ef0 (is_allowed) | - | Auth enforcement gate; default = deny if no rule |

## Remediation

1. **Add method-level auth to all ElevatedOperations handlers** mirroring `_RunElevated`'s `IsInFolder` + `IsTrusted` checks
2. **Add allowlist to `_SaveRegValue`** — restrict which registry keys can be modified
3. **Add allowlist to `_DeleteRegValue`** — restrict which registry keys can be deleted
4. **Harden msgbus config** — ensure ElevatedOperations methods use at minimum `same_sign` or `admin_client` tier
5. **Add telemetry logging** for registry operations performed via ElevatedOperations

## Confidence

- **Code analysis**: HIGH — confirmed by exhaustive string search of decompiled handlers
- **Exploitability**: MEDIUM — depends on msgbus auth tier configuration (SafeElevatedRun.json)
- **Impact**: HIGH — SYSTEM registry write + unrestricted service start = full SYSTEM LPE

## Blocking

- **SafeElevatedRun.json extraction** — need to confirm auth tier for registry and service methods
- **Live VM validation** — need to verify msgbus connection from standard user context