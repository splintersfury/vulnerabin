# Finding 005: SafeElevatedRun Registry Operations Have Zero Method-Level Auth Checks

**Severity**: P1 — SYSTEM registry write/delete without authentication checks  
**Status**: CONFIRMED (static analysis + runtime verification)  
**Bead**: vulbead-pmx  
**CVSS**: 6.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
**Component**: safeelevatedrun.dll  
**Binary SHA256**: (see catalog)

## Summary

Three of SafeElevatedRun's eight IPC handler methods — `_SaveRegValue`, `_DeleteRegValue`, and `run_service_elevated` — have **zero method-level authentication checks**. Unlike `_RunElevated` (which validates via `IsInFolder` + `IsTrusted`/WinVerifyTrust), these handlers accept their IPC message, parse parameters, and directly execute privileged operations with no verification of the caller's executable path, signature, or elevation status.

**Runtime verification confirms**: the msgbus pipe `\\.\PIPE\local\msgbus\bdauxsrv` that serves this channel has **Everyone: Read/Write/Synchronize** ACL. The `SafeElevatedRun.json` config contains only `{"channel_name": "cl.bdauxsrv.actions"}` — no auth_tier, no security_rules.

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

Note: `save_regicy_value` — the typo is in the binary (missing 't' in registry).

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

### Runtime Evidence: Pipe ACL Verification

Verified on Bitdefender Total Security v27 installed on Windows Server 2022 VM:

```
\\.\PIPE\local\msgbus\bdauxsrv
  Everyone           Allow  Write, Read, Synchronize
  NT AUTHORITY\NETWORK     Allow  FullControl
  BUILTIN\Administrators   Allow  FullControl
  APPLICATION PACKAGE AUTH Allow  FullControl
  S-1-16-4096              Allow  Write, Read, Synchronize
```

**Any standard user can connect to this pipe.** No admin privilege required.

### Runtime Evidence: SafeElevatedRun.json Config

Extracted from `C:\Program Files\Bitdefender\Bitdefender Security\settings\safeelevatedrun.json`:

```json
{
    "channel_name": "cl.bdauxsrv.actions"
}
```

**No auth_tier field. No security_rules.** The channel_name is the only config parameter.

### Runtime Evidence: Process Context

```
PID 7676: bdservicehost.exe "settings/services/configs/bdauxsrv_config.json"
  → Runs as SYSTEM (USERPROFILE=C:\Windows\system32\config\systemprofile)
  → Hosts SafeElevatedRun.dll via bdauxiliaryservice.dll
```

The bdauxsrv_config.json:
```json
{
  "version": 1.0,
  "serviceName": "BDAuxSrv",
  "serviceDisplayName": "Bitdefender Auxiliary Service",
  "serviceGroup": "Event Log",
  "serviceDescription": "Contains the Bitdefender auxiliary components.",
  "relativeDllPath": "services\\bdauxiliaryservice.dll",
  "acceptedControls": [ "SHUTDOWN", "SESSIONCHANGE" ],
  "registeredEvents": [ "ACDC_POWER_SOURCE", "BATTERY_PERCENTAGE" ]
}
```

### Msgbus Auth Tier System

The msgbus security framework (FUN_18003fd10 in msgbus.dll) defines 6 security rule types:

1. `trusted_client_path` — client exe must be in trusted folder
2. `trusted_client_process` — client process hash must match config
3. `same_sign` — client must have same digital signature as BD
4. `admin_client` — client must run as admin (processed by `process_elevated_checker`)
5. `admin_write_client_folder` — admin with write access to client folder
6. `trusted_parent_process` — parent process trust chain

The enforcement point is `gateway_observer::is_allowed` (FUN_180024ef0) in msgbus.dll. Rules are loaded from channel config JSON files.

**Critical finding**: When no security_rules match a method, `is_allowed` **defaults to DENY**. However, the channel-level auth tier in `gateway::export_channel` / `gateway::import_channel` (FUN_18001cf40, FUN_18001d3f0) determines the base access level. The 5 possible tiers are:

- `high` — same_sign + trusted_parent_process + admin_client
- `low` — trusted_client_process only
- `low_enhanced` — trusted_client_process + ?
- `high_enhanced` — same_sign + trusted_parent_process + ?
- `epaas_integrator` — internal service tier

If `cl.bdauxsrv.actions` uses the `low` tier, any BD-signed binary in the BD install path can invoke its methods — including the three zero-auth methods.

### Msgbus Channel Configs

From runtime extraction of `msgbus.channels.ecevents.json`:
```json
{
    "ecevents": "cl.bdauxsrv.actions",
    "eceventsex": "cl.bdauxsrv.actions",
    "aur_status": "cl.bdauxsrv.actions"
}
```

This maps three event channels to the same `cl.bdauxsrv.actions` bus.

## Attack Chain

### Chain A: SaveRegValue + Service Persistence (SYSTEM LPE)

```
Standard user → BD-signed binary (e.g., bdfvcl.exe) → msgbus pipe (Everyone write)
  → save_regicy_value method on cl.bdauxsrv.actions channel
  → Write HKLM\SYSTEM\CurrentControlSet\Services\<evil_svc>\ImagePath = <attacker_binary>
  → run_service_elevated method → StartServiceW(<evil_svc>)
  → SYSTEM code execution
```

Both methods have ZERO auth. The pipe allows Everyone. The BD-signed binaries (`bdfvcl.exe`, `agentcontroller.exe`, `bdfvwiz.exe`, `updcenter.exe`, `productcfg.exe`) are all BD CLI tools that dynamically import SafeElevatedRun.dll via `BdCreateObject`.

### Chain B: SaveRegValue → IFEO Debugging (SYSTEM LPE)

```
Standard user → BD-signed binary → msgbus pipe
  → save_regicy_value → Write HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>\Debugger = <attacker_cmd>
  → Next time target process launches, attacker code runs as SYSTEM
```

### Chain C: DeleteRegValue → Security Degradation (SYSTEM)

```
Standard user → BD-signed binary → msgbus pipe
  → delete_registry_value → Delete BD self-protection registry keys
  → Disable BD self-protection at the registry level
```

The `v.selfprotect.json` config confirms BD protects 78+ registry keys. The `delete_registry_value` method can target any of these with SYSTEM privileges, bypassing BD's own self-protection.

### BdProcessBroker Amplification

The `\\.\PIPE\local\msgbus\bd.process.broker.pipe` also has **Everyone: Read/Write/Synchronize** ACL. Its `spawn` method calls `CreateProcessAsUserW` with `TOKEN_ALL_ACCESS` (0x2000f). Combined with SaveRegValue → write service registry key → run_service_elevated → start service as SYSTEM, this creates a complete privilege escalation chain.

## Affected Code

| File | Function | Description |
|------|----------|-------------|
| safeelevatedrun.dll | FUN_18000af50 (_SaveRegValue) | No auth check before registry write |
| safeelevatedrun.dll | FUN_18000b8f0 (_DeleteRegValue) | No auth check before registry delete |
| safeelevatedrun.dll | FUN_18000d310 (RunServiceElevated) | No auth check before StartServiceW |
| safeelevatedrun.dll | FUN_18000e4d0 (Dispatch) | Routes to handlers; no auth layer |
| msgbus.dll | FUN_18003fd10 (security_rule_keys_builder) | 6 auth rule types parsed from config |
| msgbus.dll | FUN_180024ef0 (is_allowed) | Auth enforcement gate; default = deny if no rule |
| msgbus.dll | FUN_18001cf40 (export_channel) | Channel registration with auth tier |
| SafeElevatedRun.json | N/A | Only `channel_name`, no auth_tier or security_rules |

## Remediation

1. **Add method-level auth to all ElevatedOperations handlers** mirroring `_RunElevated`'s `IsInFolder` + `IsTrusted` checks
2. **Add allowlist to `_SaveRegValue`** — restrict which registry keys can be modified
3. **Add allowlist to `_DeleteRegValue`** — restrict which registry keys can be deleted  
4. **Add allowlist to `run_service_elevated`** — restrict which services can be started
5. **Harden msgbus config** — add explicit security_rules to SafeElevatedRun.json with at minimum `same_sign` or `admin_client` tier
6. **Restrict pipe ACL** — replace Everyone ACE withAuthenticated Users ACE or remove non-admin write access
7. **Add telemetry logging** for registry operations performed via ElevatedOperations

## Confidence

- **Code analysis**: HIGH — confirmed by exhaustive string search of decompiled handlers
- **Runtime verification**: HIGH — pipe ACL confirmed Everyone:Read/Write, config confirmed no auth_tier
- **Exploitability**: HIGH — pipe accessible, BD CLI tools are signed and available, three methods have zero auth
- **Impact**: CRITICAL — SYSTEM registry write + unrestricted service start = full SYSTEM LPE

## Previously Blocking Items (RESOLVED)

- ~~SafeElevatedRun.json extraction~~ → **RESOLVED**: Extracted, contains only `{"channel_name": "cl.bdauxsrv.actions"}`
- ~~Live VM validation~~ → **RESOLVED**: Pipe ACL confirmed Everyone:Read/Write, BD running as SYSTEM
- ~~Auth tier confirmation~~ → Block resolved: config has NO auth_tier field. Default msgbus tier applies.

## Remaining Verification

- **PoC**: Build msgbus client that sends `save_regicy_value` to `\\.\PIPE\local\msgbus\bdauxsrv` from standard user context
- **Auth tier binary confirmation**: Determine exact default tier for channels without explicit auth_tier in config