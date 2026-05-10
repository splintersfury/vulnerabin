# RE journal — ProductAgentService.exe

Long-form, dated. The structured fields in `productagentservice_exe.yml::reverse_engineering` are the index; this file is the story.

---

## 2026-03 — initial RE pass (engagement: bitdefender-2026-03)

**Goal**: Bitdefender Total Security has a SYSTEM-context process named `ProductAgentService.exe`. Find the input surface.

**Step 1 — services.msc / Get-CimInstance Win32_Service**

```
Name        : ProductAgentService
PathName    : "C:\Program Files\Bitdefender Agent\27.1.1.28_0\ProductAgentService.exe"
StartName   : LocalSystem
StartMode   : Auto
State       : Running
```

Confirmed SYSTEM-context, auto-start. Worth reversing.

**Step 2 — strings + Ghidra import**

Notable strings dump:
- `ProductAgentService` (service name)
- `ProductAgent.dll` (pulled in as static import — no surprise, the .exe is a thin host)
- `BDLogging` (logging library)
- `msgbus.dll` (Bitdefender's IPC bus)
- `udel.dll` (update / delivery)
- `com.bitdefender.superapp` ← **interesting**, looks like a config namespace
- `config_files\\%s.json` ← **very interesting**, suggests config-file discovery by name pattern
- `%s\\Bitdefender Agent\\Logs` ← log path template

**Step 3 — entrypoint**

`wWinMain @ 0x140001a30` → registers SCM dispatch for "ProductAgentService" → `ServiceMain @ 0x140012a0`.

`ServiceMain` does the standard Win32 service dance (RegisterServiceCtrlHandlerExW, SetServiceStatus), then calls into ProductAgent.dll's exported `Init` function. All real logic lives in the DLL.

**Step 4 — the config loader (ProductAgent.dll @ 0x140043b0)**

Found by xref to the `"config_files\\%s.json"` format string. Pseudocode:

```c
void config_loader(void)
{
    wchar_t base_path[MAX_PATH];
    SHGetKnownFolderPath(FOLDERID_ProgramData, ..., &base_path);
    PathAppendW(base_path, L"Bitdefender\\com.bitdefender.superapp\\config_files");
    // Enumerate *.json in that dir
    HANDLE h = FindFirstFileW(L"*.json", &fd);
    do {
        wchar_t full[MAX_PATH];
        PathCombineW(full, base_path, fd.cFileName);
        load_one_config(full);  // <-- INP-001
    } while (FindNextFileW(h, &fd));
}
```

**The bug-shape spot**: this is a per-file-name read, not a single fixed file. Every `.json` in the dir gets parsed. So if the **directory** is attacker-controlled, every config the attacker drops gets ingested.

**Step 5 — checking if the path exists on a fresh install**

ProcMon trace, fresh install of BDTS, Operation = `CreateFile`, User = `SYSTEM`, Path begins with `C:\ProgramData\Bitdefender\com.bitdefender.superapp`, Result = `NAME NOT FOUND`:

```
ProductAgentService.exe  CreateFile  C:\ProgramData\Bitdefender\com.bitdefender.superapp\config_files\*.json   NAME NOT FOUND
```

**Hit.** The config_files directory does NOT exist after install. Walk up to find the deepest existing ancestor:

```
Test-Path C:\ProgramData\Bitdefender\com.bitdefender.superapp\config_files   -> False
Test-Path C:\ProgramData\Bitdefender\com.bitdefender.superapp                -> False
Test-Path C:\ProgramData\Bitdefender                                         -> True
```

So `C:\ProgramData\Bitdefender\com.bitdefender.superapp` is the missing parent. ACL on `C:\ProgramData`:

```
BUILTIN\Users  Allow  CreateDirectories
```

Standard user can create `com.bitdefender.superapp` as anything they want — including a junction.

**Step 6 — the second leg (BDLogging)**

The config JSON has a `log_dir` field. BDLogging.dll opens log files via `CreateFileW(<log_dir>\<file>, GENERIC_WRITE, ..., OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)` — no `FILE_FLAG_OPEN_REPARSE_POINT`. So if `log_dir` resolves through a junction, the SYSTEM-context CreateFile follows the junction.

That's the chain end-to-end:
1. Standard user pre-creates `C:\ProgramData\Bitdefender\com.bitdefender.superapp` as junction → attacker dir
2. Drops crafted `config_files\evil.json` with `"log_dir": "C:\\junction\\to\\System32"`
3. Restarts service (or waits for boot)
4. Service reads `evil.json`, writes log to junction-redirected target → SYSTEM-owned file in `System32`

**Step 7 — checking bdprivmon**

BdPrivMon.sys maintains a list of "protected processes" that can't be modified by Admin. Found via reading the registered allowlist at runtime. PAS is **NOT** in the list. So injection-based variants from Admin context also work — relevant for variant findings.

**Outcome**: Bugcrowd `791bd4d8-8a22-4bf3-9ad5-14438c4e9d76`, P3, $1,000 paid.

---

## 2026-04-11 — re-engagement (BDTS engagement)

Re-checked on BDTS 27.x — chain still works. No `IsJunctionPoint` defense added on the parent dir, no DACL hardening on `com.bitdefender.superapp`. Vendor patched the **specific** finding (probably) but the architectural pattern is intact for variants.

Logged INP-001 + INP-002 here, derived_from-linked SRC-001 + SRC-002 to them. The structured form makes it possible to answer "what other binaries share INP-002?" — the BDLogging surface is shared with WatchDog.exe, bdntwrk.exe, DiscoverySrv.exe (auto-detected by `enumerate_sources.py` on 2026-05-09).

---

## Open questions / follow-ups

- Does `udel.dll` parse anything from disk that could be redirected the same way? Not yet inspected.
- The msgbus IPC peer dispatch table — is there a path where a compromised BD-signed peer can push attacker bytes through to PAS? Not yet inspected; T-006 same_sign means anything BD-signed is trusted by default.
- Other binaries in BDTS that consume `com.bitdefender.superapp\config_files\*.json` — same junction primitive likely lands a hit there too.
