# SafeElevatedRun: IPC Methods Without Authentication Checks Enable SYSTEM Registry Manipulation and Service Control

## Summary

Three IPC handler methods in Bitdefender's SafeElevatedRun component have **zero method-level authentication checks**, allowing any process that can reach the msgbus pipe to invoke SYSTEM-privileged operations including registry writes, registry deletes, and service control. The contrasting method `run_elevated` properly validates callers with `IsInFolder + IsTrusted (WinVerifyTrust)`, demonstrating this is a developer oversight rather than an intentional design.

The msgbus pipe serving these methods (`\\.\PIPE\local\msgbus\bdauxsrv`) grants **Everyone:Read/Write/Synchronize** access, and the runtime configuration file (`SafeElevatedRun.json`) contains **no auth_tier or security_rules** — only `{"channel_name": "cl.bdauxsrv.actions"}`.

## Vulnerability Class

Privilege Escalation — Local Privilege Escalation (LPE) — Insufficient Authorization

## Affected Component

- **Binary**: `safeelevatedrun.dll` (CRC: per catalog)
- **Process**: `bdservicehost.exe` (running as SYSTEM, hosting `bdauxiliaryservice.dll`)
- **IPC Channel**: `\\.\PIPE\local\msgbus\bdauxsrv`

## Steps to Reproduce

### Step 1: Verify pipe accessibility (confirmed on BD v27)

The msgbus pipe is accessible to any user:

```
\\.\PIPE\local\msgbus\bdauxsrv
  Everyone           Allow  Write, Read, Synchronize
  NT AUTHORITY\NETWORK     Allow  FullControl
  BUILTIN\Administrators   Allow  FullControl
  APPLICATION PACKAGE AUTH Allow  FullControl
  S-1-16-4096              Allow  Write, Read, Synchronize
```

### Step 2: Verify SafeElevatedRun configuration

Extracted from `C:\Program Files\Bitdefender\Bitdefender Security\settings\safeelevatedrun.json`:

```json
{
    "channel_name": "cl.bdauxsrv.actions"
}
```

No `auth_tier`, no `security_rules`. Compare with other BD configurations that DO specify auth.

### Step 3: Static analysis of method-level auth

The SafeElevatedRun dispatch table (FUN_18000e4d0) routes 8 IPC methods:

| Method | Handler | Auth Check |
|--------|---------|------------|
| `run_elevated` | FUN_18000c290 | ✅ IsInFolder + IsTrusted (WinVerifyTrust) |
| `run_elevated_async` | FUN_18000c290 | ✅ IsInFolder + IsTrusted |
| `run_service_elevated` | FUN_18000d310 | ❌ **NONE** |
| `run_service_elevated_async` | FUN_18000d310 | ❌ **NONE** |
| `save_regicy_value` | FUN_18000af50 | ❌ **NONE** |
| `save_regicy_value_async` | FUN_18000af50 | ❌ **NONE** |
| `delete_registry_value` | FUN_18000b8f0 | ❌ **NONE** |
| `delete_registry_value_async` | FUN_18000b8f0 | ❌ **NONE** |

**Evidence for `save_regicy_value` (FUN_18000af50):** Exhaustive string search of the 432-line decompiled function for `IsInFolder`, `IsTrusted`, `WinVerifyTrust`, `trusted`, `verify`, `hash`, `sign`, `cert`, `folder`, `path.*check` returns **zero matches**. The handler reads `registry_structure` from the IPC message and directly invokes registry operations with SYSTEM privileges.

**Evidence for `run_elevated` (FUN_18000c290):** This handler calls `FUN_18000e980` (ExePath::IsTrusted, verifying digital signature via WinVerifyTrust) and `FUN_18000f5d0` (ExePath::IsInFolder, verifying the executable is in the BD install folder). These checks are **absent** from the registry and service handlers.

### Step 4: Service context

```
PID 7676: bdservicehost.exe "settings/services/configs/bdauxsrv_config.json"
  USER: SYSTEM (USERPROFILE=C:\Windows\system32\config\systemprofile)
```

All SafeElevatedRun IPC methods execute with SYSTEM privileges since bdservicehost.exe runs as SYSTEM.

## Attack Scenarios

### Scenario A: Registry Write → Service Persistence (SYSTEM LPE)

1. Standard user sends `save_regicy_value` IPC message to `\\.\PIPE\local\msgbus\bdauxsrv`
2. SafeElevatedRun writes `HKLM\SYSTEM\CurrentControlSet\Services\<attacker_svc>\ImagePath` = attacker binary
3. Attacker sends `run_service_elevated` to start the service
4. Attacker binary executes as SYSTEM

### Scenario B: Registry Write → IFEO Debugging (SYSTEM LPE)

1. Standard user sends `save_regicy_value` IPC message
2. Write `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>\Debugger` = attacker command
3. When a SYSTEM process launches the target, attacker code executes as SYSTEM

### Scenario C: Registry Delete → Security Degradation

1. Standard user sends `delete_registry_value` IPC message
2. Delete Bitdefender self-protection registry keys (78+ protected in `v.selfprotect.json`)
3. Disable BD self-protection at the registry level, enabling further attacks

## Impact

**HIGH** — SYSTEM-level privilege escalation from standard user context. An attacker can:
- Write arbitrary SYSTEM registry values
- Delete protected registry keys including BD self-protection entries
- Start/stop Windows services with SYSTEM privileges
- Achieve persistent code execution as SYSTEM

The vulnerability is particularly severe because `run_elevated` properly implements authentication, proving that:
1. The development team was aware of the need for method-level auth
2. The absence of auth in the other methods is a developer oversight (inconsistent security enforcement)
3. The fix pattern already exists in the codebase (`IsInFolder + IsTrusted`)

## Root Cause

The SafeElevatedRun dispatch table (FUN_18000e4d0) routes method calls to handlers without a uniform authentication layer. While `run_elevated` implements per-call verification of the caller's executable path and digital signature, three other handlers (`save_regicy_value`, `delete_registry_value`, `run_service_elevated`) perform no caller validation whatsoever. The msgbus tier provides channel-level access control, but this is insufficient when individual methods perform SYSTEM-privileged operations without their own authorization checks.

## Suggested Remediation

1. **Add method-level auth to all SafeElevatedRun handlers** — Apply the same `IsInFolder + IsTrusted (WinVerifyTrust)` checks that `run_elevated` uses to all handlers that perform privileged operations
2. **Add registry key allowlists** — `_SaveRegValue` and `_DeleteRegValue` should restrict which registry keys can be modified, similar to how `_RunElevated` restricts which executables can be launched
3. **Add service allowlists** — `run_service_elevated` should restrict which services can be started/stopped
4. **Harden SafeElevatedRun.json** — Add explicit `security_rules` with `same_sign` tier at minimum
5. **Restrict pipe ACL** — Remove the `Everyone:Write` ACE from the bdauxsrv pipe; restrict to `Authenticated Users` or `BUILTIN\Users` at minimum

## Environment

- **Target**: Bitdefender Total Security v27.0 (build 27.0.25.125)
- **OS**: Windows Server 2022 (KVM VM, verified on dedicated test system)
- **Verification**: Static analysis + runtime pipe ACL verification + config extraction

## References

- SafeElevatedRun dispatch table: FUN_18000e4d0 (safeelevatedrun.dll)
- Run elevated auth: FUN_18000c290 → FUN_18000e980 (IsTrusted/WinVerifyTrust) + FUN_18000f5d0 (IsInFolder)
- Save registry no-auth: FUN_18000af50
- Delete registry no-auth: FUN_18000b8f0
- Run service no-auth: FUN_18000d310
- Process broker pipe: `\\.\PIPE\local\msgbus\bd.process.broker.pipe` (Everyone:RW + CreateProcessAsUserW)
- SafeElevatedRun.json: `{"channel_name": "cl.bdauxsrv.actions"}`