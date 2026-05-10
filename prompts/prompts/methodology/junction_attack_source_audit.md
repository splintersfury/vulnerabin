# Methodology: junction-attack source enumeration for Windows desktop and Electron

This is the systematic source-enumeration playbook for the junction-attack-on-missing-path class. It is the "find every candidate" arm of the methodology; the existing `/junction-hunt` skill is the "exploit a known candidate" arm. Use this when you want to be **thorough** on one binary or one product, not when you want to drill on a single suspect.

## Why a separate methodology

`/junction-hunt` assumes the target profile already matches and walks you through ProcMon → ACL check → exploit-build. That works because junction-attacks are mechanical once you've identified one missing-path candidate. The hard part is **finding the candidate**: the binary touches dozens of file paths at runtime; only a few have an attacker-controllable parent. Without an enumeration pass, you're trusting ProcMon noise filters to surface the gold. ProcMon is great for verification but it's a poor enumerator: you only see paths the binary touches during the run, and you only see them if you filter correctly.

The two paid-out findings (Bitdefender ProductAgentService P3/$1,000 and Dell SupportAssistInstaller P2) both came from spotting a **specific path** that the binary touches in a privileged context whose **parent doesn't exist** on a fresh install AND whose **next-up existing ancestor** (`C:\ProgramData`, `%WINDIR%\Temp`, `%LOCALAPPDATA%\Temp`) grants `BUILTIN\Users` create-folder permission. Source-by-discovery missed dozens of similar candidates per binary; source-by-enumeration would have surfaced them in one pass.

## The six-signal model

Every junction-attack candidate path has these six properties. Enumerators tag every path with all six; the catalog stores them; chains rate exploitable when the right combination holds.

| Signal | Values | Why it matters |
|--------|--------|----------------|
| `path_template` | A path string, possibly with `%ENVVAR%` or template substitutions (e.g., `%LOCALAPPDATA%\Vendor\Cache\<random>`, `C:\ProgramData\Vendor\<vendor>.json`) | The bug exists at a specific path. Enumeration lists every distinct template. |
| `principal` | `SYSTEM`, `Admin`, `LocalService`, `NetworkService`, `loggedInUser`, `installer-elevated` | Determines the privilege gain. Junction-attack only matters when principal is more privileged than the user setting up the junction. |
| `operation` | `read`, `write`, `create_directory`, `create_file`, `set_acl`, `delete`, `query_attributes` | `write`/`create_*` is the classic Dell pattern (write-as-SYSTEM into attacker-controlled location). `read` is the Bitdefender PAS pattern (read attacker-controlled config that influences SYSTEM behavior). |
| `parent_must_exist` | `yes`, `no_will_create`, `unknown` | The killer signal. If the binary writes to the path and the parent directory does not exist, it likely calls `CreateDirectory`/`SHCreateDirectoryEx`/`Directory.CreateDirectory` to make it. The first call creates an inheritable ACL; that ACL is the next victim. |
| `parent_acl_inherited_from` | The deepest existing ancestor's path. Almost always one of: `C:\ProgramData`, `%WINDIR%\Temp`, `%LOCALAPPDATA%\Temp`, `C:\Users\Public`, `%TEMP%` | Default Windows ACLs on these grant `BUILTIN\Users:(CI)(WD,AD,WEA,WA)` — meaning any user can pre-create a subdirectory there. If `parent_must_exist=no_will_create` AND `parent_acl_inherited_from` is one of the magic three, the candidate is almost always exploitable. |
| `trigger` | `process_start`, `scheduled_task`, `service_start`, `ipc_invocation`, `file_system_event`, `com_activation`, `installer_run`, `update_check` | Determines whether the attacker can fire the chain on demand or has to wait. Triggers under attacker control (IPC, COM, filesystem watcher events) are highest-value. |

## What "exploitable" looks like

A chain is exploitable when:

```
operation in {write, create_file, create_directory, set_acl}
AND principal in {SYSTEM, Admin, LocalService, installer-elevated, loggedInUser_with_higher_caps}
AND parent_must_exist == no_will_create
AND parent_acl_inherited_from in {ProgramData, WINDIR\Temp, LOCALAPPDATA\Temp}  # for low-priv attacker
AND no_canonicalization_check  # binary doesn't IsJunctionPoint(parent) before write
AND attacker_can_trigger
```

Or for the read-flavor (config-injection):

```
operation == read
AND principal in {SYSTEM, Admin, LocalService}
AND path is under a parent that low-priv attacker can pre-create as junction
AND read result influences SYSTEM-context behavior (config, log path, exec path, library load path)
AND attacker_can_trigger the read
```

## Per-binary-type enumeration recipes

### Windows native binaries (PE EXE/DLL/SYS)

**Static signals to extract from decompilation:**

1. **Path-construction calls**: trace every site that builds a path string. The common builders are:
   - `SHGetFolderPath`, `SHGetKnownFolderPath`, `SHGetSpecialFolderLocation` — known folder lookups (CSIDL/KFID — the special-folder constants like FOLDERID_LocalAppData = `%LOCALAPPDATA%`)
   - `GetEnvironmentVariableW` with names: `LOCALAPPDATA`, `APPDATA`, `PROGRAMDATA`, `WINDIR`, `TEMP`, `TMP`, `USERPROFILE`, `PUBLIC`
   - `ExpandEnvironmentStringsW`
   - `PathCombineW`, `PathAppendW`, `PathCchAppend`, `swprintf` with format strings ending in path components
   - hardcoded wide strings starting with `C:\`, `\\?\C:\`, `\Device\HarddiskVolume`, etc.

2. **Path-touching calls**: `CreateFileW`, `CreateDirectoryW`, `SHCreateDirectoryExW`, `MoveFileExW`, `WriteFile`, `ReadFile`, `OpenFileMappingW`, `LoadLibraryExW`, `CryptUIWizDigitalSign`, `CreateProcessW`, `_wfopen`, `_wopen`, the wide-flavor of every fs API.

3. **Parent-existence patterns**: cross-reference the path-construction site with the path-touching site. If the binary calls `CreateDirectoryW(parent)` *only if* `GetFileAttributesW(parent) == INVALID_FILE_ATTRIBUTES`, that's `parent_must_exist=no_will_create`. If it just calls `CreateFileW(child)` and lets it fail when the parent is missing, it'll fail safely. The danger pattern: `CreateDirectoryW(parent_no_check); CreateFileW(child)`.

4. **Junction-check absence**: grep for `FILE_ATTRIBUTE_REPARSE_POINT`, `IsReparseTagDirectory`, `OBJECT_ATTRIBUTES.Attributes & OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT`. The presence of these around path-touching code is a defense; the absence is the gap.

5. **Token impersonation**: search for `OpenThreadToken`, `ImpersonateLoggedOnUser`, `RevertToSelf` around path-touching code. SYSTEM services that impersonate the calling user before touching a path are typically safe; ones that don't are the high-yield targets.

**Dynamic signals (when running ProcMon under representative use):**

ProcMon filter for junction-attack enumeration:
- Operation: `CreateFile`, `WriteFile`, `CreateDirectory`, `QueryAttributesFile`
- User: pick the principal you suspect (`NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, `LOCAL SERVICE`)
- Path begins with: `C:\ProgramData\<vendor>`, `C:\Windows\Temp`, `C:\Users\<admin>\AppData\Local\Temp\<vendor>`, `C:\ProgramFiles*\<vendor>` (writes to install dir from non-installer context = trust assumption)
- Result: `NAME NOT FOUND`, `PATH NOT FOUND` — the gold mine. Every one of these is a path the SYSTEM process tried to access but doesn't exist, meaning a junction can be pre-created.

### Windows .NET binaries (managed)

dnSpy or ILSpy (`ilspycmd <binary> -o <out>`) recovers source-equivalent C#. Greps that map cleanly:

- `Path.Combine(...)` — every site is a path-construction candidate.
- `Environment.GetFolderPath(Environment.SpecialFolder.X)` — same KNOWNFOLDERID semantics.
- `Environment.ExpandEnvironmentVariables`.
- `Directory.CreateDirectory(path, security)` — the exact API the Dell SupportAssistInstaller bug hinges on. It applies the protected DACL to the **leaf** path, NOT to pre-existing ancestors. The .NET `DirectoryInfo.Create(security)` is the same shape.
- `File.Open` / `File.Create` / `FileStream` constructor.
- `WindowsIdentity.GetCurrent()` followed by impersonation patterns — same defensive-or-missing tell as native.

The Dell-pattern signature in C# is roughly:

```csharp
string extractRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Dell", "SupportAssistInstaller");
if (!Directory.Exists(extractRoot)) {
    Directory.CreateDirectory(extractRoot, securedAcl);  // applies the protected ACL only here
}
string randomSubdir = Path.Combine(extractRoot, Guid.NewGuid().ToString());
Directory.CreateDirectory(randomSubdir);  // inherits parent's ACL — wide-open if extractRoot ancestor was user-writable
```

The pattern Dell got bit by: when `Path.GetTempPath()` returns `%LOCALAPPDATA%\Temp` for a UAC-S4U scheduled task running as Administrator, that path is the LIMITED user's profile — pre-creatable.

### Electron apps

Electron junction-attack surface is different from native: the Electron main process runs as the user (no privilege ladder *within* Electron usually), but Electron apps frequently ship a SYSTEM-context auto-update service or ship via an MSI installer that runs as admin. The interesting paths are:

1. **Auto-update extraction directories**:
   - `electron-updater` writes to `app.getPath('userData')`, `app.getPath('temp')`, `%LOCALAPPDATA%\<app>-updater\pending\`. Check whether the parent is auto-created and whether the updater impersonates.
   - Squirrel.Windows: `%LOCALAPPDATA%\<app>\packages\` and `%LOCALAPPDATA%\<app>\app-<version>\`. Squirrel's Update.exe runs in user context normally but in elevated context for some MSIs.
   - The user has paid out on Notion's update mechanism (filed elsewhere) — same pattern surfaces.

2. **Custom protocol handlers** that take attacker-controllable arguments and translate them to file paths:
   - `app.setAsDefaultProtocolClient('myapp')` then a `myapp://...` URL fragment is parsed in `app.on('open-url', ...)` or `process.argv` parsing inside `second-instance` handler. If the URL is parsed into a path that's then opened/written, that's a source-to-write chain triggered by browser navigation.

3. **IPC channels that touch the filesystem**:
   - `ipcMain.on('save-file', async (event, path, content) => fs.writeFile(path, content))` — if the renderer is compromised or `nodeIntegration: true`, the renderer-supplied path becomes attacker-controlled.
   - `ipcMain.handle('open-file', async (e, path) => fs.readFile(path))` — same shape for reads.
   - These aren't junction-attacks per se but they're the parallel structural source-enumeration class for Electron.

4. **`webPreferences.preload` script paths** loaded relative to the app root — DLL-search-order-equivalent for Electron.

5. **File associations and crash-dump locations** — `app.setPath('crashDumps', ...)` writes attacker-readable crash dumps if the path is misconfigured.

For the Electron junction-attack flavor specifically, the high-yield place is the **auto-updater**, because:
- It's the rare component that runs with elevation (or that prompts UAC and inherits Admin token)
- It writes large blobs to predictable paths
- It often does NOT canonicalize before writing
- The `pending`/`tmp`/`download` subdirectories are frequently auto-created if missing, with default ACLs

## What the enumerators emit

Every enumerator pass produces one structured record per distinct path the binary touches:

```json
{
  "binary": "ProductAgentService.exe",
  "version": "27.x",
  "candidates": [
    {
      "id": "PATH-001",
      "path_template": "C:\\ProgramData\\Bitdefender\\com.bitdefender.superapp\\config_files\\<configname>.json",
      "construction_site": "FUN_140053a20 line 187 (Path.Combine equivalent)",
      "touch_sites": [
        {"function": "FUN_140084100", "operation": "read", "line": 412}
      ],
      "principal": "SYSTEM",
      "parent_must_exist": "no_will_create",
      "parent_acl_inherited_from": "C:\\ProgramData",
      "trigger": "service_start",
      "junction_check_seen": false,
      "impersonation_seen": false,
      "exploitability": "high",
      "exploitability_reason": "SYSTEM-context read of a path under ProgramData where the parent is auto-created with default ACL; classic config-injection junction target.",
      "evidence_excerpts": [
        "ExpandEnvironmentStringsW(L\"%PROGRAMDATA%\\\\Bitdefender\\\\com.bitdefender.superapp\\\\config_files\", buf, MAX_PATH);",
        "GetFileAttributesW(parent) == INVALID_FILE_ATTRIBUTES then SHCreateDirectoryEx(parent)"
      ]
    }
  ]
}
```

The orchestrator merges per-binary outputs into `engagements/<eng>/source_enumeration.json`. The catalog seeder consumes that to populate `catalog/binaries/<name>.yml` `sources[]` entries.

## Calibration: known cases the enumerator must catch

Use these as oracle tests when validating the worker prompts and orchestrator. Each is a real, paid-out or vendor-confirmed case:

1. **Bitdefender ProductAgentService config injection** (paid 2026-03, $1,000):
   - Path: `C:\ProgramData\Bitdefender\com.bitdefender.superapp\config_files\<n>.json`
   - Principal: SYSTEM (ProductAgentService.exe)
   - Operation: read
   - Parent must exist: no_will_create
   - Parent ACL inherited from: C:\ProgramData
   - Junction check: absent
   - Trigger: service_start

2. **Bitdefender ProductAgentService log junction** (same finding, second leg):
   - Path: `C:\ProgramData\BdLogging\<sub>\<file>.log`
   - Principal: SYSTEM
   - Operation: write
   - Parent must exist: no_will_create
   - Junction check: absent
   - Trigger: service runtime logging (pings every few seconds)

3. **Dell SupportAssistInstaller extract directory** (P2 Triaged, 2026-04-25):
   - Path: `%LOCALAPPDATA%\Temp\<random>\` for the UAC-S4U scheduled-task elevation case
   - Principal: installer-elevated (Admin via UAC)
   - Operation: write (extracts payload here, then runs payload)
   - Parent must exist: no_will_create (`Directory.CreateDirectory(path, security)` applies ACL to leaf only)
   - Parent ACL inherited from: `%LOCALAPPDATA%\Temp` (the LIMITED user's, when UAC-S4U)
   - Junction check: absent (this is the variant of CVE-2024-38305 — original CVE checked the leaf, this finding shows the parent is unprotected)
   - Trigger: installer_run

4. **BDTS 005 safeelevatedrun** (submitted 2026-05-09):
   - This is NOT a junction-attack source — it's a path-traversal trust-check bypass. Source is the msgbus IPC, not the filesystem. The enumerator should mark this binary's filesystem sources as `none_in_scope_for_junction_class` since no SYSTEM-context fs-touching paths with inherited ACL exist.

A worker that runs against `bitdefender-total-security-2026-04-11/decomp-productagt/` and FAILS to surface candidates 1 and 2 above is broken. Use it as the regression test.

## Anti-patterns

- ❌ Enumerating only paths in scope of an active hunt. The catalog value comes from cataloguing every candidate, including ones marked `low_exploitability`. Future engagements may revisit.
- ❌ Conflating the junction-attack source class with general filesystem source classes. Junction-attack candidates are a narrow subset; a binary that reads `C:\Windows\System32\kernel32.dll` is not a junction candidate (kernel32.dll's parent has admin-only ACL inheritance).
- ❌ Relying on ProcMon alone. ProcMon shows runtime-touched paths; static enumeration finds paths touched only on certain code branches (error paths, update paths, recovery paths) that ProcMon never exercises.
- ❌ Skipping impersonation analysis. A SYSTEM service that calls `ImpersonateLoggedOnUser` before every fs touch is largely safe from this class. Marking it as `principal=SYSTEM` without checking is misleading.
