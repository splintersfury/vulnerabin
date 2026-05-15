# Finding 001: msgbus Security Gate — trusted_client_process Path-Hash Bypass (Prerequisite Research)

## Status
UNCERTAIN — requires VM verification of trusted process list

## Summary
The Bitdefender msgbus IPC system uses a named pipe accessible to all users (Everyone ACL), relying entirely on application-layer security to gate privileged operations. The weakest security tier ("low") only checks `trusted_client_process` — an FNV-1a-derived hash of the connecting process's image path. If any process executable in a user-writable or user-accessible location appears in the trusted hash map, a standard user can connect and invoke all "low"-tier endpoints (which include the process broker's `spawn` command and potentially the ElevatedOperations registry methods).

## ACID Assessment

### A — Attacker-Controlled
The pipe is accessible to any process on the machine (ACL grants WinWorldSid GENERIC_READ|GENERIC_WRITE). The attacker controls:
- Which process they launch (and therefore its image path)
- The message body sent over the pipe

The `trusted_client_process` check (FUN_1800212c0 in msgbus.dll) computes a hash of the process image path using a custom FNV-1a–based algorithm that normalizes `/` and `\` as equivalent. If the attacker can run a binary from a trusted path, the hash will match.

### C — Chain-Complete
```
Attacker process at trusted path
    → connects to \\.\PIPE\local\msgbus\bd.process.broker.pipe  (WinWorldSid ACL)
    → msgbus checks trusted_client_process (FNV-1a hash of image path)
    → if hash matches: security level "low" satisfied
    → calls process_broker::spawn or ElevatedOperations::SaveRegValue
    → SYSTEM-privileged operation executes
```

The chain is complete IF a trusted process path is user-accessible. The break point is the trusted process hash map content (unknown without VM inspection).

### I — Impact
**If trusted path found:**
- **Process broker spawn**: Can invoke any pre-registered task from `process_broker.json` with a specified session token. Impact: code execution as any logged-in user (not SYSTEM elevation per se — impersonates caller).
- **ElevatedOperations _SaveRegValue**: Arbitrary registry write as SYSTEM (security level TBD). If confirmed "low" tier: arbitrary SYSTEM registry writes → persistence, LPE via autorun/service hijack.
- **ElevatedOperations _SafeElevatedRun**: Execute any Authenticode-signed binary in another session as that session's user.

### D — Defenses
1. **trusted_client_process hash map**: Only pre-approved process paths can pass. Hash is 64-bit, collision attack infeasible.
2. **same_sign check**: For "high"/"high_enhanced" tiers, the connecting process must be Bitdefender-signed. Not applicable to "low" tier.
3. **admin_client check**: Some operations additionally require TokenElevation. Standard user without UAC elevation fails this.
4. **trusted_client_path check**: Additional check that process is in a trusted system directory (system32, Program Files, etc.). Low tier doesn't require this.

## Evidence

### Pipe ACL — Everyone
`decomp-msgbus/functions/FUN_18003c220.c`:
```c
FUN_18003bd80(local_60, WinWorldSid);  // Creates ACE for Everyone
local_230 = 0xc0000000;  // GENERIC_READ | GENERIC_WRITE
```

### Trusted Process Hash Function
`decomp-msgbus/functions/FUN_1800212c0.c` — custom hash of wide-string process path, normalizing `\` and `/`.

### Security Level Enum
`decomp-msgbus/functions/FUN_18001cf40.c`:
- 0 = "high" (`same_sign & trusted_client_process & (trusted_client_path | admin_client)`)
- 1 = "low" (`trusted_client_process` only)
- 2 = "low_enhanced" (`trusted_client_process & (trusted_client_path | admin_client)`)
- 3 = "high_enhanced"
- 4 = "epaas_integrator"

### Security Rules (from msgbus.dll strings)
```json
{
  "security_rules": {
    "low": "trusted_client_process",
    "low_enhanced": "trusted_client_process & (trusted_client_path | admin_client)",
    "high": "same_sign & trusted_client_process & (trusted_client_path | admin_client)"
  }
}
```

## Required VM Verification

On Windows VM with Bitdefender installed:

1. **Enumerate trusted process hashes**:
   ```powershell
   # Attach debugger to msgbus service, breakpoint FUN_1800212c0
   # Record which process paths produce matching hash values
   # Alternatively: enumerate msgbus config JSONs
   Get-ChildItem "C:\Program Files\Bitdefender\*" -Recurse -Filter "*.json" | 
       Select-String "trusted_client_process"
   ```

2. **Check ElevatedOperations security level**:
   ```powershell
   # Look for SafeElevatedRun.json, process_broker.json in Bitdefender install dir
   Get-Content "C:\Program Files\Bitdefender\Total Security\*\settings\SafeElevatedRun.json"
   ```

3. **Attempt connection from untrusted process**:
   ```python
   # Simple pipe client
   import win32file, win32pipe
   pipe = win32file.CreateFile(
       r'\\.\PIPE\local\msgbus\bd.process.broker.pipe',
       win32file.GENERIC_READ | win32file.GENERIC_WRITE,
       0, None, win32file.OPEN_EXISTING, 0, None)
   # Send msgbus message: {"module":"process_broker","method":"spawn","task":"..."}
   ```

## Verdict
UNCERTAIN — LOW confidence without VM inspection of trusted process list.

If any Bitdefender-installed component is placed in a user-writable location AND its path appears in the trusted_client_process hash map, this becomes a CONFIRMED LPE chain. Most likely the trusted paths are all in write-protected Program Files directories — but this must be verified.

## Suggested Fix (if confirmed)
- Implement pipe ACL that restricts connection to SYSTEM + Administrators + BD service accounts
- Remove "low" security tier or require at minimum `trusted_client_path` check (restricts to system dirs)
- Add session isolation for pipe (currently session-local pipe allows same-session standard users)
