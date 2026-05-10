# Windows Logic-Chain LPE Methodology

Privilege escalation on Windows that uses **no memory corruption**. Instead, you chain
together legitimate Windows features so a SYSTEM-level service does work-on-behalf-of you
that it shouldn't. Recent payouts: BlueHammer (CVE-2026-33825), RedSun, PhantomRPC,
Forshaw's 9-vuln Administrator Protection bypass series. Research time-to-finding is much
shorter than memory-corruption work because there's no exploit-dev or mitigation-bypass
burden — but the bug must be discovered through *system reasoning*, not Ghidra alone.

For deep reference (researcher catalog, CVE list, sources): `~/Documents/research-windows-logic-chain-lpe.md`.

## The mindset

Memory-corruption hunting asks "where is the validation flawed in this function?".
Logic-chain hunting asks "**what does this privileged service trust about the world that I
can lie about?**". The bug is not in any single function — it's in the gap between two
trust domains.

Every logic-chain LPE follows this template:

```
SYSTEM-process P does operation O on resource R, expecting R to have property X.
Low-priv user U manipulates the world so that R no longer has property X
        between the time P checks it and the time P acts on it,
                                or between two consecutive uses by P.
Result: P does O on attacker's chosen resource, with SYSTEM rights.
```

X is usually one of: **path identity, file content, lock-holding, security descriptor,
RPC peer identity, COM class registration, scheduled-task target, registry key target.**

## The chain audit (the only six questions you need)

When inspecting a privileged operation, ask:

1. **Who runs as SYSTEM/admin and touches user-writable state?** (services, scheduled tasks,
   COM autoElevate, Defender remediation, Update workflows, MSI rollback, Spooler, WSearch,
   cloud-files reparse handlers).
2. **What user-writable input does that privileged code consume?** Path strings, file
   contents, registry values, named pipes, RPC arguments, environment variables, oplock
   acknowledgements, file system reparse data.
3. **Is the input *re-read* after a check, or used through a name that resolves dynamically?**
   (Path → file content. Handle → object. RegKey → value.) Anywhere the privileged side
   resolves a name twice or reads a file after a check, the link can be redirected.
4. **What primitive (junction, hardlink, oplock, symlink, COM TreatAs, RPC channel, ...)
   lets me change the resolution between the two reads?** If you can name the primitive,
   the bug is real.
5. **What is the privileged write or read sink?** ArbitraryFileWrite, ArbitraryFileRead,
   ArbitraryDelete, RegistryHandleDuplication, TokenDuplication, ScheduledTaskCreate,
   ServiceConfigChange. Each chains differently into SYSTEM.
6. **What is the smallest end-to-end repro?** If a 50-line PoC plus standard tools
   (`junction.exe`, `mklink /J`, `OleViewDotNet`, `RpcView`) can demonstrate the chain,
   it's probably real. If you need a heroic memory-corruption exploit-dev step, you've
   misclassified the bug.

## The 20 reusable primitives (memorize these)

Logic chains are not invented from scratch — they're recombinations of these. If a target
operation uses one of these as a hidden trust assumption, you have a candidate.

| # | Primitive | What it lies about | Tool |
|---|-----------|--------------------|------|
| 1 | NTFS junction (mount-point reparse) | Path → directory identity | `mklink /J`, `CreateMountPoint` |
| 2 | NTFS hardlink | Path → file content (low-priv user can repoint to non-writable file) | `mklink /H`, `CreateHardLink` |
| 3 | NTFS object-manager symlink | NT-namespace name → object | `NtCreateSymbolicLinkObject` |
| 4 | Opportunistic lock (oplock) | Pauses privileged file I/O so attacker can swap target mid-flow | Forshaw `SymbolicLinkTestingTools` |
| 5 | Volume Shadow Copy (VSS) snapshot | Past file state visible as a "previous version" filesystem | `vssadmin`, `wmic shadowcopy` |
| 6 | Cloud Files placeholder (cldflt.sys) | Sparse file traps reads back into user-mode provider | CldApi, `CfRegisterSyncRoot` |
| 7 | Filter manager / minifilter altitude | Order-of-callback assumptions | `fltmc`, custom WDK filter |
| 8 | CLFS / TxF transactional FS | Atomicity assumed where there is none | `clfs.sys` log files, `KTM` transactions |
| 9 | DLL search-order / planting | Loader trusts CWD/PATH for non-fully-qualified library names | DLLSpy, ProcMon |
| 10 | COM TreatAs / InProcServer32 | CLSID → DLL is per-user override of HKLM | `OleViewDotNet`, registry CLSID hijack |
| 11 | COM autoElevate elevation moniker | "Admin Approval Mode" trusted CLSID list | `CoCreateInstanceAsAdmin`, ICMLuaUtil |
| 12 | RPC interface trust | Server trusts client identity / endpoint / channel binding | `RpcView`, `NdrClientCall` |
| 13 | Scheduled task / service trigger | Path/argument fields rewritable per-user | `schtasks.exe`, `sc.exe` |
| 14 | SeImpersonate token coercion | Service-side accept of unauthenticated callbacks | `PrintSpoofer`, RoguePotato, GodPotato |
| 15 | Driver IOCTL logic (not memory) | Privileged driver duplicates a handle / opens a file under SYSTEM token | `DeviceIoControl` to vulnerable signed drivers |
| 16 | Registry symlink (REG_LINK) | Key path → key contents | `NtCreateKey` REG_OPTION_CREATE_LINK |
| 17 | WIL / Velocity feature flag override | Registry override of compiled feature gate | `HKLM\System\…\FeatureManagement\Overrides` |
| 18 | Update / repair / rollback worker | SYSTEM service revisits attacker-staged content | MSI rollback, Defender remediation, WU |
| 19 | MSI / installer custom action | InstallShield/MSI revert path running with elevated context | Mandiant repair-mode research |
| 20 | LOLBin / signed-binary side effects | Trusted binary writes/copies/loads with attacker args | LOLBAS project catalog |

## Common chain templates (re-usable shapes)

Most published logic-chain LPEs reduce to one of these four shapes. When auditing, try
each shape against your candidate operation:

### Shape A — "Junction-on-write"
1. SYSTEM service writes/copies/deletes a file at a user-controlled or
   user-influenceable path.
2. Attacker turns the parent dir (or one of its components) into a junction
   pointing at a privileged location (e.g. `C:\Windows\System32`).
3. The SYSTEM operation lands in the privileged location.
4. Output primitive: `ArbitraryFileWrite` or `ArbitraryFileDelete` as SYSTEM.
5. From there, drop a DLL into a default-loaded path or overwrite a service binary →
   SYSTEM code execution.

Examples: 80% of OEM "uninstaller" LPEs (Dell, Razer, ASUS, NVIDIA), Defender
remediation (BlueHammer), WU rollback (CVE-2025-21204).

### Shape B — "Oplock-on-check"
1. SYSTEM service performs a "check then act" on an attacker-controlled file
   (signature verify, hash, copy-with-permissions).
2. Attacker places an oplock on the file. The check passes.
3. Oplock break callback fires; attacker swaps the file (rename, hardlink retarget,
   junction redirect) before SYSTEM acts.
4. The "act" step uses attacker's swapped file.
5. Output primitive: arbitrary signed-binary execution, arbitrary file content delivered
   to a privileged consumer.

Examples: cldflt.sys TOCTOUs (CVE-2025-55680), AsIO3.sys (CVE-2025-3464), Forshaw's
SymbolicLink primitives.

### Shape C — "Trust-the-caller RPC / COM"
1. RPC interface or COM CLSID is registered with `CallerAuthenticationLevel = NONE`
   or registered for autoElevate, OR the server checks caller PID/path string instead
   of token integrity.
2. Attacker invokes the interface from low-priv context, possibly impersonating a
   trusted name through hardlinking / process hollowing / parent-PID spoofing.
3. SYSTEM-side handler does the requested operation under its own token.
4. Output primitive: any of ArbitraryFileWrite, RegistryWrite, ServiceCreate,
   TokenDuplicate (depending on the interface).

Examples: PhantomRPC, ICMLuaUtil COM elevation, Forshaw's UAC-bypass family.

### Shape D — "Update / maintenance worker abuse"
1. Periodic or on-demand SYSTEM worker scans a user-writable directory for
   "things to clean up", "definitions to update", or "rollback artifacts".
2. Attacker stages content there that hijacks the worker's operation
   (replace expected file with junction; place a DLL where the worker calls
   non-fully-qualified LoadLibrary; drop a `.cab` whose installer runs custom action).
3. Output primitive: arbitrary code as SYSTEM at next worker tick.

Examples: BlueHammer (Defender remediation queue), CVE-2025-21204 (WU stack), RedSun
(Defender SYSTEM-write).

## Where to look first — the privileged-worker inventory

When picking a target on a fresh Windows install, enumerate these in order:

1. **Defender platform** (`C:\ProgramData\Microsoft\Windows Defender\Platform\<ver>\`) —
   MsMpEng.exe, MpCmdRun.exe, NisSrv.exe. Updates monthly out-of-band giving fresh
   diff targets. Remediation queue is at
   `C:\ProgramData\Microsoft\Windows Defender\Quarantine\` and `\Scans\`.
2. **Windows Update / TrustedInstaller** — `services.exe` children, CBS handlers,
   pending.xml replays.
3. **Cloud Files filter** — `cldflt.sys` + sync-root reparse points; placeholder files
   trigger SYSTEM round-trips to user-mode providers.
4. **Spooler** post-PrintNightmare — `spoolsv.exe` still loads driver DLLs, processes
   custom-color profile files.
5. **MSI / installer cache** — `C:\Windows\Installer\*.msi`, repair mode, rollback log.
6. **Search indexer (`searchindexer.exe` / `Microsoft.Search.SqliteService`)** — has
   produced multiple LPEs through the index file format.
7. **Scheduled tasks owned by SYSTEM with user-writable arguments** — enumerate via
   `Get-ScheduledTask | ? Principal -match SYSTEM`.
8. **COM CLSIDs marked autoElevate** (HKCR `Elevation\Enabled`) — finite list, audit each.
9. **RPC servers exposed on `\\.\pipe\*` or ALPC** — RpcView dump, then Ghidra each
   handler.
10. **Third-party signed kernel drivers shipped with consumer hardware** — vulnerable
    drivers project, LOLDrivers catalog. IOCTL logic bugs (Shape C variant).

## Tools

- **NtObjectManager** (Forshaw, PowerShell module) — junction/symlink/oplock/RPC
  enumeration and exploitation. The single most important tool.
- **OleViewDotNet** — COM CLSID inventory, autoElevate flag visibility, IID method
  mapping.
- **RpcView** — live RPC server enumeration with full IDL recovery.
- **Sysinternals ProcMon** — observe what privileged workers actually touch (run as
  Admin, filter by `Result is not SUCCESS` to find ENV/path-injection candidates).
- **SymbolicLinkTestingTools** (Forshaw) — `CreateSymlink`, `CreateMountPoint`,
  `SetOpLock`, `OplockBreakOnAccess`.
- **junction.exe** (Sysinternals) — quick junction setup.
- **AccessChk / AccessEnum** — find user-writable paths in privileged workflows.
- **fltmc** — list filter-manager altitudes / minifilters; understand which file ops
  touch which filters in which order.
- **Process Hacker / System Informer** — token + handle inspection; spot impersonation.
- **ETW + WPR** — capture privileged worker traces; many "what does Defender actually
  do" questions answer themselves through the `Microsoft-Windows-Windows Defender` ETW
  provider.

## Worked example — BlueHammer (CVE-2026-33825)

**Trust assumption (X):** Defender remediation engine, when restoring a file from
quarantine, trusts that the path it's writing to is a normal NTFS directory under the
user profile.

**Primitive used:** Cloud Files placeholder + oplock + VSS previous-version surface.

**Chain:**
1. Attacker submits a benign-looking file Defender will quarantine.
2. Defender quarantines it; remediation queue holds the metadata.
3. Attacker creates a Cloud Files sync root over the destination directory; sync root
   is a placeholder (sparse).
4. Attacker requests Defender to restore (or waits for periodic cleanup).
5. Defender writes restored bytes to the destination; cldflt.sys traps the write to
   the user-mode sync provider; provider re-encodes the path through a VSS shadow
   copy that points at a SYSTEM-owned location.
6. Restored bytes land in `C:\Windows\System32\<dll>` as SYSTEM.
7. Trigger DLL load via any service-launch event → SYSTEM.

**Why it took six features to chain:** each individual feature has reasonable defenses;
the bug is the *combination* — Cloud Files trusts that its sync provider is benign,
Defender trusts that the destination is a normal directory, VSS trusts that the
shadow path is read-only.

**The audit that finds this kind of bug:** ProcMon trace of Defender remediation,
filter for paths Defender writes to that pass through cldflt.sys, look for any
attacker-influenceable component in the path resolution.

## Assessment checklist

Apply these to any candidate before committing to a deep dive.

1. [ ] Is there a SYSTEM-or-admin process that operates on a path or handle the
       low-priv attacker can influence? (Source identified.)
2. [ ] Does the privileged side resolve the path/handle MORE THAN ONCE, OR resolve a
       name (path/CLSID/RPC endpoint) into the actual object only at use time?
3. [ ] Is there a window between resolutions where the attacker can swap the target?
4. [ ] Can I name the redirection primitive (junction, hardlink, oplock, symlink,
       COM TreatAs, registry symlink, RPC channel rebind)?
5. [ ] What's the resulting privileged primitive (FileWrite / FileRead / FileDelete /
       RegistryWrite / TokenDup / ServiceConfigChange)?
6. [ ] Is the primitive concretely chainable to SYSTEM code execution? (Default DLL
       load path, service binary, Defender ASR allow-listed location, etc.)
7. [ ] Does the chain require ANY user interaction beyond logon? (No → publishable.
       Yes → typically rejected.)
8. [ ] Does any feature flag, GP setting, or `HKLM` config defang the chain in default
       deployment? (Required: confirm in default Win11 24H2 Pro.)

## Common mistakes when hunting logic chains

- **Treating it like a function-level audit.** Decompiling the SYSTEM service in
  Ghidra finds nothing. The bug is in the world-model, not the code. Use ProcMon and
  RpcView and watch the live system.
- **Assuming "the path is sanitized" without testing.** Privileged code routinely
  passes user-influenceable paths through `Path*` APIs that don't resolve junctions
  before access. Test it.
- **Stopping at "the file is signed".** Signature checks are usually performed on the
  path, not the bytes loaded. Hardlink/oplock breaks the assumption (see
  toctou_assumption.md).
- **Trying to break a single check.** As with TOCTOU, don't try to forge the check —
  ask what the check assumes.
- **Forgetting the feature gate.** Microsoft increasingly ships fixes behind WIL
  feature flags with stage 3 (AlwaysEnabled). The PRE binary still contains the
  vulnerable path as dead code; reaching it requires admin-override (defeats LPE).
  Confirm stage of any new flag before claiming a variant.
- **Mismatching attacker model.** Logic-chain LPE assumes a low-priv local user with
  ability to write to their own profile / `%TEMP%` / `\Users\Public\` and run code.
  If your chain needs admin to set up, you've already lost.
- **Not validating in default config.** A logic chain that needs Cloud Files enabled,
  or Defender disabled, or a non-default GP, is often unreportable. Test in a stock
  Win11 24H2 Pro VM.

## Recent reference CVEs (2025–2026) — read all of these

- **CVE-2026-33825 — BlueHammer** (Defender + VSS + Cloud Files + oplocks). [Picus](https://www.picussecurity.com/resource/blog/bluehammer-redsun-windows-defender-cve-2026-33825-zero-day-vulnerability-explained)
- **RedSun** — Defender SYSTEM write, unpatched. [nefariousplan](https://nefariousplan.com/posts/redsun-windows-defender-system-write)
- **PhantomRPC** — RPC interface-trust, MS declined. [Securelist](https://securelist.com/phantomrpc-rpc-vulnerability/119428/)
- **Forshaw — Bypassing Windows Administrator Protection (9 vulns)**. [Project Zero](https://projectzero.google/2026/26/windows-administrator-protection.html)
- **CVE-2025-55680 — cldflt.sys TOCTOU**. [Exodus Intelligence](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- **CVE-2025-21204 — Windows Update Stack abuse**. [cyberdom](https://cyberdom.blog/abusing-the-windows-update-stack-to-gain-system-access-cve-2025-21204/)
- **CVE-2025-3464 — AsIO3.sys hash-vs-content TOCTOU**. (See `toctou_assumption.md`)
- **Mandiant — Privileges via Third-Party Windows Installers**. [Mandiant](https://www.mandiant.com/resources/blog/privileges-third-party-windows-installers)
- **decoder.cloud — RoguePotato** (canonical SeImpersonate chain). [decoder.cloud](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- **ZDI — Breaking Barriers (Pt. 2)**. [ZDI](https://www.thezdi.com/blog/2024/7/30/breaking-barriers-and-assumptions-techniques-for-privilege-escalation-on-windows-part-2)
- **itm4n / Clément Labro** — service-side LPE patterns. [itm4n](https://itm4n.github.io/)

## Cross-references in this taxonomy

- `toctou_assumption.md` — sub-class methodology; logic chains are ultimately TOCTOU
  on system state.
- `primitive_escalation.md` — what to do once you have a privileged primitive
  (FileWrite/FileRead/etc.) to convert into SYSTEM exec.
- `taxonomy/binary/assumption_attacks.json` — programmatic catalog of trust-assumption
  patterns (extend with logic-chain primitives).
