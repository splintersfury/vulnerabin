# Comprehensive source taxonomy for Windows desktop, Electron, and adjacent attack surfaces

This is the canonical source-class reference for vulnerabin engagements. Every catalog entry, every triage decision, every finding's source declaration should map to one or more class IDs defined here.

**Phase B, 2026-05-09.** Builds on Phase A audit (`engagements/_audit/audit_phase_a.md`), which classified 101 findings across 35 engagements under the v2 taxonomy at `engagements/_audit/draft_taxonomy_v2.md`. Phase B adds: detection signals, defense patterns, bypass patterns, and CVE exemplars per class.

## Reading this document

Each class follows the same structure:

- **Definition** — one paragraph
- **Trust boundary** — who's the attacker, what privilege transition the bug crosses
- **Detection signals** — static patterns, dynamic instrumentation, structural shapes
- **Defense pattern** — what makes a binary safe
- **Bypass pattern** — common misimplementations / where defenses fail
- **CVE exemplars** — 1-3 CVEs per class, each tagged with **training-recall confidence (HIGH | MEDIUM | LOW)**. No web search was used in writing this; HIGH means I'm very confident the CVE exists with the description given, MEDIUM means I recall something like this but may mis-attribute details, LOW means I'm fishing from memory and the user should verify against MITRE before citing externally.
- **Our engagement coverage** — which of our 35 engagements exercised this class
- **Phase B notes** — open questions / refinements / followups

Depth varies by Phase A engagement volume. High-volume classes (K-001, F-001, I-002, N-001, N-003) get the deepest research; zero-coverage classes get a shorter scaffold ready to expand on first engagement contact.

## Table of contents

- [F — Filesystem trust-boundary](#f--filesystem-trust-boundary)
- [I — Local IPC](#i--local-ipc)
- [N — Network](#n--network)
- [K — Kernel / Driver](#k--kernel--driver)
- [U — User-input / process surface](#u--user-input--process-surface)
- [T — Trust assumption](#t--trust-assumption)
- [UP — Update / install / package](#up--update--install--package)
- [C — Configuration / persistence](#c--configuration--persistence)
- [E — Electron-specific](#e--electron-specific)
- [W — Web (auth/session)](#w--web-authsession)
- [CR — Cryptographic primitive misuse](#cr--cryptographic-primitive-misuse)

---

# F — Filesystem trust-boundary

## F-001 — NTFS-junction-write-by-elevated-process

**Definition.** An elevated principal (SYSTEM service, Admin installer, scheduled task running with elevated token) writes to a path whose **parent directory** is auto-created on demand. A standard user pre-creates that parent as an NTFS junction pointing at any filesystem location. The elevated process's write follows the reparse point and lands at the attacker-chosen target. Result: arbitrary file write as the elevated principal.

**Trust boundary.** Standard user → SYSTEM (or → Admin). The crossing is the filesystem; the kernel I/O manager honors the reparse point unless `FILE_OPEN_REPARSE_POINT` / `OBJ_DONT_REPARSE` is set on the handle.

**Detection signals.**
- *Static (Windows native)*: `CreateDirectoryW`, `SHCreateDirectoryExW`, `_wmkdir` calls. Path-construction with `SHGetKnownFolderPath` / `ExpandEnvironmentStringsW` resolving to `%PROGRAMDATA%`, `%WINDIR%\Temp`, `%LOCALAPPDATA%\Temp`, `C:\Users\Public`. The danger pattern is `if (GetFileAttributesW(parent) == INVALID_FILE_ATTRIBUTES) SHCreateDirectoryExW(NULL, parent, NULL); CreateFileW(child, GENERIC_WRITE, ...)` with no junction check.
- *Static (.NET)*: `Directory.CreateDirectory(path)` or `Directory.CreateDirectory(path, security)` followed by writes to children. The Dell SupportAssistInstaller pattern is exactly this: protected ACL applied to leaf, parent inherits user-writable ACL.
- *Static (Electron / Node)*: `fs.mkdirSync(path, { recursive: true })` followed by `fs.writeFileSync(path.join(parent, 'x'))`. `recursive: true` is the smoking gun.
- *Dynamic*: ProcMon filtered to `Operation=CreateFile,WriteFile,CreateDirectory; User=NT AUTHORITY\SYSTEM; Path begins with C:\ProgramData\<vendor>; Result=NAME NOT FOUND or PATH NOT FOUND`. Every `NAME NOT FOUND` against a SYSTEM process touching a vendor path is a candidate.
- *Structural*: any service binary registered as `LocalSystem` whose install footprint has paths under `C:\ProgramData\<vendor>` that don't exist on a fresh install.

**Defense pattern.**
1. Apply protected DACL to **every ancestor** the binary creates, not just the leaf. `SetSecurityInfo(parent, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, ...)` after `CreateDirectoryW(parent, NULL)`.
2. Open paths with `FILE_OPEN_REPARSE_POINT` / `OBJ_DONT_REPARSE` and refuse if `FILE_ATTRIBUTE_REPARSE_POINT` is set on any walked component.
3. Impersonate the calling user before the write (`ImpersonateLoggedOnUser` / `ImpersonateNamedPipeClient`) so the write happens with the user's token, not SYSTEM's.
4. Write to a path whose every ancestor is in a SYSTEM-only-write-DACL location (`C:\Windows\System32\<vendor>`, `C:\Program Files\<vendor>`).

**Bypass pattern.**
- Vendor adds `IsJunctionPoint(leaf_path)` after a CVE → attacker creates junction one level UP from leaf → check passes. **This is the patch-bypass class** that pays consistently (Dell SAI variant of CVE-2024-38305 was this exact shape).
- Vendor uses `Directory.CreateDirectory(path, security)` thinking it secures the whole tree → it only secures the LEAF; ancestors created in the same call inherit the upstream ACL.
- Vendor checks `!Directory.Exists(parent)` then creates → race: attacker creates junction between the check and the create.
- Vendor sets DACL via `CreateDirectoryW(path, &sa)` for one path only → the next subdirectory inherits.

**CVE exemplars.**
- **CVE-2024-38305** — Dell SupportAssistInstaller — junction in installer extract directory; the original CVE checked one level, our paid finding is a variant that exploits one level higher up. (Confidence: HIGH — the user filed a variant on this.)
- **CVE-2020-1170** — Microsoft Defender — junction in scan path lets standard user redirect Defender's scan-write to arbitrary location. (Confidence: MEDIUM — I recall this CVE class on Defender but the exact ID may be off.)
- **CVE-2020-1054** / Win32k filesystem-junction class. (Confidence: LOW — multiple Win32k CVEs in this period; I'm not certain the right one.)
- **CVE-2023-23397** — Outlook MAPI universal NTLM-relay; not a junction-write per se but the CVE-class-adjacent file-handler-trust shape. (Confidence: HIGH — well-publicized.)

**Our engagement coverage** (15 findings across 8 engagements):
- `bitdefender-total-security-2026-04-11` — multiple findings (BDLogging junction in WatchDog enumeration)
- `acronis-2026-05-07/findings/001-junction-bootstrapper-syswrite.md` — confirmed primitive
- `acronis-2026-05-07/findings/002-rce-via-dll-extraction.md` — F-001 + UP-005 chain
- `logitech-2026-05-07/findings/001-junction-defense-analysis.md` — defense analyzed; verdict turned negative
- `lenovo-vantage-2026-04-29/findings/001-junction-candidates.md` — defense analyzed; verdict turned negative
- `hp-support-assistant-2026-04-29/findings/001-...` — verdict turned negative
- `intel-dsa-2026-04-30/findings/001-...` — FALSE_POSITIVE per junction-hunt skill exit
- `nvidia-app-2026-04-30/findings/002-arbitrary-dir-file-create-as-SYSTEM.md` — confirmed
- `malwarebytes-2026-04-29/findings/005-mbupdatr-toctou-mbuns.md` — F-001 + UP-001 chain
- (paid) Bitdefender ProductAgentService config-injection + log junction (March 2026, $1,000) — F-001 + F-002

**Phase B notes.** This class accounts for 15% of our engagement effort but only 1 publicly-submitted finding. The defense-vs-bypass dialectic determines yield: when defenses are correctly implemented (Logitech, Lenovo, HP, Intel DSA), the engagement closes negative. The two paid cases (Bitdefender PAS, Dell SAI) won because they exploited a defense gap (one-level-up, leaf-only-ACL). Future hunts should focus on **patch-bypass after a vendor's first CVE**, not on greenfield F-001 hunts on hardened products.

---

## F-002 — NTFS-junction-read-by-elevated-process (config injection)

**Definition.** An elevated principal reads configuration / log path / lookup data from a path whose parent the low-priv user pre-creates as a junction. The redirected read returns attacker-supplied data, which then influences the elevated process's behavior (log path, library path, exec path, policy values).

**Trust boundary.** Same as F-001, but the data flows from attacker to victim (read), not victim to attacker (write).

**Detection signals.**
- *Static*: read-flavor of F-001 patterns: `CreateFileW(GENERIC_READ)`, `_wfopen(path, L"r")`, `RegLoadAppKey` against a path under `%PROGRAMDATA%\<vendor>\config*\`. Look for places the binary parses JSON/INI/XML/YAML config files from non-installer locations.
- *Dynamic*: ProcMon `Operation=ReadFile, CreateFile(GENERIC_READ); User=NT AUTHORITY\SYSTEM; Path begins with C:\ProgramData\<vendor>; Result=NAME NOT FOUND` — same as F-001 but for read operations.
- *Structural*: services that read settings or log-config from `%PROGRAMDATA%` rather than `%PROGRAMFILES%` (which has admin-only DACL).

**Defense pattern.** Same as F-001 (canonicalize, OBJ_DONT_REPARSE, impersonate). Additionally: **sign or HMAC the config file** so even if the read succeeds, the content is rejected.

**Bypass pattern.** Same as F-001. Plus: vendor adds path canonicalization but parses config content unsafely (e.g., trusts a `log_dir` field in the config to write logs to attacker-chosen path → second-stage F-001).

**CVE exemplars.**
- The user's own paid Bitdefender PAS finding is the canonical exemplar (read of `C:\ProgramData\Bitdefender\com.bitdefender.superapp\config_files\<n>.json` → log_dir field controls where SYSTEM-context logs are written → second-stage junction-write). (Confidence: HIGH — the user worked it.)
- **CVE-2021-21551** — Dell DBUtil — different mechanism (kernel IOCTL) but illustrative of "vendor reads attacker-influenced data and acts on it". (Confidence: HIGH — canonical Dell driver CVE.)
- (No external CVE I'm confident of for clean F-002 read-junction class — most public exemplars are F-001-flavor.)

**Our engagement coverage.** 0 directly tagged in Phase A (the BD-PAS calibration case lives in a prior-engagement folder we didn't process). Phase A's `audit_phase_a.md` documents this gap.

**Phase B notes.** Recommend re-running the seeder against the prior PAS-engagement folder to capture this case in `sources_observed.jsonl`.

---

## F-003 — NTFS-hardlink-substitution

**Definition.** A privileged process opens a file expected to be under its control (e.g., its own log file, its own config). An attacker pre-creates a hardlink at that path pointing at a SYSTEM-protected target. The privileged process opens via the path; the kernel resolves to the protected target; the privileged write/truncate/delete operates on the protected target.

**Trust boundary.** Standard user → SYSTEM. The crossing is the filesystem object identity (hardlinks share the same inode/MFT entry).

**Detection signals.**
- *Static*: `CreateFileW(GENERIC_WRITE)` / `CreateFileW(... TRUNCATE_EXISTING ...)` / `_wfopen(... "w")` on a path whose parent is user-writable. Specifically, look for log files written under `%PROGRAMDATA%`, temp paths, or any per-user data dir.
- *Dynamic*: hardlink-detection requires `lstat`-equivalent which Windows doesn't expose directly; the standard check is `GetFileInformationByHandle` then comparing `nNumberOfLinks` against 1.

**Defense pattern.**
- Open the path with `FILE_FLAG_OPEN_REPARSE_POINT` AND verify `nNumberOfLinks == 1`.
- Use a SYSTEM-only-DACL parent for sensitive writes.
- Use the modern Windows `FILE_DISPOSITION_POSIX_SEMANTICS` family which respects DELETE-pending semantics.

**Bypass pattern.**
- Service truncates a log file by opening with TRUNCATE_EXISTING → hardlink redirects to `C:\Windows\System32\config\SAM` (or similar) → service truncates SAM (BSOD on next boot, or worse).
- Service appends to a log → hardlink to `\\.\PhysicalDrive0` writes attacker-controlled bytes to disk header.

**CVE exemplars.**
- **CVE-2023-32016** — Windows hardlink CVE class. (Confidence: MEDIUM — I recall a CVE in this period but the exact ID may be wrong.)
- **CVE-2024-21320** — recent Windows hardlink LPE. (Confidence: LOW — verify before citing externally.)
- **CVE-2020-0668** — Windows servicing-stack hardlink. (Confidence: LOW.)

**Our engagement coverage** (2 findings):
- `backblaze-2026-04-08/findings/001-...` — Backblaze v10 hardlink LPE. Submitted 2026-04-09 to Bugcrowd; closed Duplicate.
- `teamviewer-2026-03-31/findings/005-...` — TeamViewer hardlink class.

**Phase B notes.** Hardlink-class is hardening on modern Windows: `FILE_RENAME_INFORMATION_EX` defaults stricter, kernel I/O manager has gradual hardening. Pure F-003 is harder to land in 2026 than 2018.

---

## F-004 — Symlink-by-low-priv-into-protected-target (Linux flavor)

**Definition.** Linux equivalent of F-003: privileged process opens path; symlink redirects. Less common on Linux because mode-bit semantics catch many cases; still happens on root-owned files in `/tmp`, log directories, lock files.

**Trust boundary.** Standard UID → root.

**Detection signals.**
- *Static*: `open(path, O_WRONLY|O_CREAT)` without `O_NOFOLLOW`. `fopen(path, "w")`. `unlink(path)` followed by `creat(path)`.
- *Dynamic*: `strace -f -e trace=file <binary>` filtered to root-uid file accesses in `/tmp`.

**Defense pattern.** `O_NOFOLLOW`, `openat()` with `AT_SYMLINK_NOFOLLOW`, `mkstemp` for temp files instead of predictable paths.

**Bypass pattern.** Race the symlink creation with the open call; on systems without `O_NOFOLLOW` the kernel follows.

**CVE exemplars.**
- **CVE-2017-2616** — Linux su / setuid + symlink. (Confidence: MEDIUM — I recall a CVE-2017 in this class.)
- **CVE-2019-3462** — apt symlink. (Confidence: MEDIUM.)

**Our engagement coverage.** 0 directly tagged.

**Phase B notes.** RustDesk findings (F-005) have adjacent Linux-symlink potential not yet investigated.

---

## F-005 — World-writable IPC socket

**Definition.** A privileged daemon creates a Unix socket / named pipe with permissive mode (0777, NULL DACL, or `BUILTIN\Users:GA`). Any local process can connect and drive the daemon. Exploit gain depends on what commands the daemon accepts.

**Trust boundary.** Local UID 1000+ → root (Linux) or standard user → SYSTEM (Windows).

**Detection signals.**
- *Static (Linux)*: `set_permissions(socket_path, mode 0o0777)`, `chmod 0o777`, `umask 0` followed by socket bind, `setsockopt(SO_PASSCRED)` absence (no peer-credential check).
- *Static (Windows)*: `CreateNamedPipe(... PIPE_ACCESS_DUPLEX, ..., NULL_for_security_descriptor, ...)`, `CreateFileMappingW(... NULL, ...)` with NULL SD. `InitializeSecurityDescriptor` followed by `SetSecurityDescriptorDacl(sd, TRUE, NULL, FALSE)` (NULL DACL = everyone allowed).
- *Dynamic*: `ls -la /tmp/<vendor>` for Linux; `accesschk.exe -a \\.\pipe\<name>` for Windows.

**Defense pattern.** Set socket permissions to 0700 / per-user; use SO_PEERCRED to verify caller UID; on Windows set explicit DACL granting only the owning service account.

**Bypass pattern.** Daemon sets DACL on socket but the parent directory is world-writable → attacker pre-creates socket as a real socket of their own → daemon bind() fails or follows attacker's socket. (Hybrid F-005 + F-001.)

**CVE exemplars.**
- **CVE-2017-2616** — Linux su (cited above; symlink-class but related). (Confidence: MEDIUM.)
- **CVE-2020-7461** — FreeBSD dhclient world-writable socket. (Confidence: LOW — verify.)
- The user's RustDesk uinput finding is the canonical recent example. (Confidence: HIGH — they worked it.)

**Our engagement coverage** (1 finding):
- `local-host-svc-hunt-2026-05-09/findings/001-rustdesk-uinput-lpe.md` — `/tmp/RustDesk/ipc_uinput_*` mode 0777 owned by root.

**Phase B notes.** This class is high-yield in the IoT-adjacent / Linux-server space.

---

## F-006 — World-writable / user-readable config / log file

**Definition.** Variant of F-002. A privileged process writes a file (log, config, state) to a path whose parent has permissive ACL, allowing low-priv read or substitution. Often a vector for information disclosure (read sensitive logs) or precondition for a chain (substitute config).

**Trust boundary.** Same as F-001/F-002 but data direction varies.

**Detection signals.** Same as F-001/F-002.

**Defense pattern.** Apply protected DACL on file creation; rotate logs to admin-only directories.

**Bypass pattern.** Logs include sensitive data (creds, IPC tokens, sessions) and are written to user-readable locations.

**CVE exemplars.**
- **CVE-2023-2745** — WordPress credential exposure via log. (Confidence: LOW — different platform, similar shape.)
- **CVE-2022-24521** — Windows CLFS LPE — different mechanism but shows logs being a target. (Confidence: HIGH.)

**Our engagement coverage** (2 findings):
- `bitdefender-total-security-2026-04-11/findings/001-bdch-dll-plant.md` — F-006 + UP-005-adjacent shape
- `teamviewer-2026-03-31/findings/004-...` — log readable by low-priv

---

## F-007 — File-association / drag-drop trust handler

**Definition.** Application registers a file extension or drag-drop handler. An attacker delivers a crafted file (via web download, email, removable media) which the handler trusts in unsafe ways: parses content, executes content, dereferences relative paths.

**Trust boundary.** Cross-trust user (browser-delivered file) → desktop user. Sometimes elevation via UAC-attached file-handler.

**Detection signals.** `IShellExtInit::Initialize`, `RegisterDragDrop`, `OleInitialize`, `IPersistFile::Load` callbacks, registered shell extensions in `HKCR\<.ext>\shell\open\command`.

**Defense pattern.** Treat file content as untrusted; sanitize path components; drop privileges before parsing.

**Bypass pattern.** Handler trusts the file extension to determine parser, then parser is buggy.

**CVE exemplars.**
- **CVE-2017-11882** — Office Equation Editor file-format parser. (Confidence: HIGH — canonical.)
- **CVE-2023-21716** — Office RTF font heap overflow. (Confidence: HIGH.)
- **CVE-2024-21412** — Windows SmartScreen .url file bypass. (Confidence: HIGH.)

**Our engagement coverage.** 0 directly tagged.

**Phase B notes.** High-yield class for desktop-app variant analysis (PDF readers, image viewers, IDE file-handlers).

---

# I — Local IPC

## I-001 — Named-pipe-unauthenticated-read

**Definition.** Service creates a named pipe whose DACL grants `Everyone` or `Authenticated Users` GENERIC_READ. Any local process can connect and read messages emitted by the service. Information disclosure surface depending on what the service publishes (events, status, secrets).

**Trust boundary.** Standard user → privilege of the publishing service.

**Detection signals.**
- *Static*: `CreateNamedPipe` with `PIPE_ACCESS_DUPLEX` or `PIPE_ACCESS_OUTBOUND`, `lpSecurityAttributes` set to NULL OR pointing at an SD whose DACL is `(A;;FR;;;AU)` or `(A;;FR;;;WD)`.
- *Static (modern .NET)*: `NamedPipeServerStream(name, PipeDirection.InOut, ..., PipeOptions.None, ..., null)` — null security.
- *Dynamic*: `accesschk.exe -accepteula -a \\.\pipe\<name>` or NtObjectManager `Get-NtPipeFile`.

**Defense pattern.** Explicit SDDL grant only to the owning service principal: `(A;;FA;;;LS)` for LocalService, etc. Authenticate caller via `GetNamedPipeClientProcessId` + token check, or `ImpersonateNamedPipeClient` then ACL-check the resource.

**Bypass pattern.** Service uses default DACL (which is permissive on `\\.\pipe\<name>` for non-PIPE_REJECT_REMOTE_CLIENTS).

**CVE exemplars.**
- **CVE-2018-1000007** — Plex Media Server named pipe info disclosure. (Confidence: MEDIUM — recall something like this.)
- **CVE-2023-20106** — Cisco named pipe info disclosure. (Confidence: LOW.)
- The user's Sophos EventStore finding is the canonical recent exemplar. (Confidence: HIGH.)

**Our engagement coverage** (3 findings):
- `sophos-endpoint-ipc-2026-05-05/findings/001-eventstore-unauth-read.md` — submitted P3
- `sophos-2026-04-29/findings/001-...` — earlier Sophos pipe surface
- `dropbox-2026-04-30/findings/001-dbxsvc-signature-validation-bypass.md` — co-tagged I-001 + T-001

**Phase B notes.** Yield is medium: vendors triage as P3-P4 unless the leaked data is sensitive (creds, sessions). Sophos eventstore was P3 because threat-detection metadata is sensitive.

---

## I-002 — Named-pipe-unauthenticated-write

**Definition.** Service creates a named pipe whose DACL grants `Everyone` / `Authenticated Users` write. Any local process connects and sends commands. Exploit potential is **anything the service does on receipt**: file write, process spawn, IOCTL, COM activation, registry edit.

**Trust boundary.** Standard user → privilege of the listening service (typically SYSTEM).

**Detection signals.**
- *Static*: same `CreateNamedPipe` pattern as I-001 but with `PIPE_ACCESS_INBOUND` or `PIPE_ACCESS_DUPLEX`. `ReadFile` on the pipe handle is the entry point of the message-handling state machine.
- *Static*: presence of a request-dispatcher function that switches on a message type or command code without first authenticating the caller.
- *Dynamic*: `accesschk.exe -w \\.\pipe\<name>` to confirm low-priv has write access.

**Defense pattern.** Same as I-001 plus: authenticate the caller. Two patterns work: (a) `ImpersonateNamedPipeClient` + `OpenThreadToken` + check group membership against an admin SID; (b) `GetNamedPipeClientProcessId` + open process + check image path against a trusted-list.

**Bypass pattern.**
- Service authenticates by checking caller's image path → attacker uses process-hollowing of a trusted binary (T-001). This is the BD msgbus same_sign attack class.
- Service authenticates by checking caller's parent process → attacker spawns the legitimate parent under controlled args (T-006 variant).
- Service uses `ImpersonateNamedPipeClient` but performs the privileged action AFTER `RevertToSelf` on a path derived from the impersonated user's input (TOCTOU).

**CVE exemplars.**
- **CVE-2020-7368** — Cisco AnyConnect VPN service named pipe LPE. (Confidence: HIGH — well-publicized.)
- **CVE-2021-31380** — Citrix Workspace named pipe. (Confidence: MEDIUM.)
- **CVE-2024-30090** — Office named pipe class. (Confidence: LOW — uncertain.)
- **CVE-2022-24521** — CLFS / named pipe / kernel IPC class. (Confidence: HIGH but spans multiple Bug shapes.)

**Our engagement coverage** (11 findings, our most-shipped class):
- `bitdefender-total-security-2026-04-11/findings/005-safeelevatedrun-path-traversal.md` — I-002 + T-005 + T-006 (submitted)
- `bitdefender-total-security-2026-04-11/findings/006-seccenter-safeelevatedrun-relay-lpe.md` — I-002 + T-006
- `bitdefender-2026-05-02/findings/001-msgbus-trusted-process-bypass.md` — I-002 + T-004
- `bitdefender-2026-05-02/findings/002-safeelevatedrun-wvt-toctou.md` — I-002 + T-001
- `bitdefender-2026-05-02/findings/003-safeelevatedrun-ipc-unauth-memcpy.md`
- `cisco-secure-client-2026-03-30/findings/001-...` — submitted; the FP variant
- `teamviewer-2026-03-31/...` (multiple, reclassified to I-009 in v2 since TeamViewer uses TCP not pipes)
- `malwarebytes-2026-04-29/findings/006-ipc-attack-surface.md` — I-001 + I-002 cotagged

**Phase B notes.** This is our **highest-yield submission shape**. 5 of 21 submitted findings are I-002. Pattern: combine with a trust-assumption class (T-001/T-004/T-005/T-006) for full chain.

---

## I-003 — D-Bus method caller-uid trust

**Definition.** A D-Bus daemon (running as root or as a privileged uid) exposes a method that takes the caller's uid as a method argument rather than reading it from the message bus. The daemon trusts the argument. Any local user spoofs another user's uid (commonly 0) and operates with that user's privileges.

**Trust boundary.** Local UID → root or another user.

**Detection signals.**
- *Static*: D-Bus method signature has `uint32 uid` (or `int32`) as a parameter. The handler reads it via `g_variant_get_uint32` rather than `g_dbus_method_invocation_get_sender` + `dbus_bus_get_unix_user`.
- *Bus policy*: `<allow send_destination="<service>"/>` without `<allow send_interface="..." send_member="..."/>` per-method scoping.

**Defense pattern.** Always read the caller's uid from `g_dbus_method_invocation_get_sender(invocation)` then `bus.get_unix_user(sender)`. Discard any uid argument or use it only as a hint cross-checked against the bus uid.

**Bypass pattern.** Method takes a uid argument "for backward compatibility" but daemon never deprecates the bypass.

**CVE exemplars.**
- **CVE-2021-3560** — polkit pkexec — uid trust in polkit. (Confidence: HIGH — canonical.)
- **CVE-2018-19788** — polkit uid-related. (Confidence: HIGH.)
- The user's ProtonVPN finding. (Confidence: HIGH.)

**Our engagement coverage** (1 finding):
- `protonvpn-linux-2026-05-08/findings/001-dbus-uid-spoof-setconfig.md` — submitted to security@proton.me 2026-05-08.

---

## I-004 — COM elevation moniker / IElevator interface

**Definition.** Application registers a COM class with `LaunchPermission` that allows non-admin instantiation, but the class itself runs elevated (via the Elevation: moniker, AppID with RunAs="Interactive User", or class registered as a COM+ application). The class's methods, when invoked, perform privileged operations. If the methods don't authenticate the caller within COM, any standard user instantiates and calls them with elevated effect.

**Trust boundary.** Standard user → SYSTEM or Administrator.

**Detection signals.**
- *Static*: registry hive `HKCR\AppID\{...}` with `RunAs` value `"Interactive User"` or `"NT AUTHORITY\\SYSTEM"`. `HKCR\CLSID\{...}\Elevation\Enabled = 1`. `LaunchPermission` SD that includes `Authenticated Users`.
- *Static*: classes derived from `IDispatch` or vendor-specific elevator interfaces (`IElevator`, `IElevationManager`, `IElevatorEdge`).
- *Dynamic*: `oleview.exe` or NtObjectManager's `Get-ComProcess` to enumerate COM classes with elevation; `CoCreateInstanceEx(CLSCTX_LOCAL_SERVER | CLSCTX_ELEVATION_AWARE)` from a low-priv process.

**Defense pattern.** Restrict `LaunchPermission` to admin-only SIDs. Authenticate the caller in every method (via `CoImpersonateClient` + `OpenThreadToken` + token check). Use `IUnknown::QueryInterface` filtering to refuse non-trusted callers.

**Bypass pattern.**
- Vendor uses Elevation moniker with `LaunchPermission=Authenticated Users` (broken default) → standard user instantiates, calls method, action runs as SYSTEM.
- Vendor authenticates by checking caller's COM authentication info → attacker uses a different COM interface that bypasses the check.

**CVE exemplars.**
- **CVE-2021-31980** — Windows MSDT COM elevation. (Confidence: MEDIUM.)
- **CVE-2024-26229** — Windows CSC COM. (Confidence: LOW.)
- **CVE-2025-21333** (Edge IElevatorEdge missing caller validation) — the user filed VULN-175971 case 108804 on this; closed Duplicate. (Confidence: HIGH — they filed it.)
- **CVE-2024-29045** / Dropbox IElevator. (Confidence: MEDIUM — the user filed Dropbox 004 separately.)

**Our engagement coverage** (3 findings):
- `dropbox-2026-04-30/findings/004-ielevator-submission.md` — submitted
- `dropbox-2026-04-30/findings/004-ielevator-clean.md` — same class, cleaner version
- `ms-com-elevators-2026-05-03/findings/001-...` — Edge / Microsoft COM elevators sweep

**Phase B notes.** This class has been mining the Microsoft COM elevator surface for at least two years (TheWover and others have published widely). Phase B: cross-reference James Forshaw's research on this.

---

## I-005 — WM_COPYDATA / window message

**Definition.** Privileged GUI process registers a window class and processes WM_COPYDATA / custom WM_USER messages from any process that can find the window. Attacker `FindWindow` + `SendMessage` reaches the privileged WndProc with attacker-controlled COPYDATASTRUCT.

**Trust boundary.** Standard user → privilege of the window-owning process. Same-session-only by default.

**Detection signals.** `RegisterClass`/`RegisterClassEx`, WndProc handling `WM_COPYDATA`, `WM_USER+N`, `WM_DROPFILES`. Look for processing that does not validate `cbData` / `lpData` rigorously.

**Defense pattern.** `ChangeWindowMessageFilter`/`ChangeWindowMessageFilterEx` to block specific messages from non-elevated. UAC's UIPI is the default protection (lower-IL processes can't send WM_COPYDATA to higher-IL by default in modern Windows).

**Bypass pattern.** `User Interface Privilege Isolation` (UIPI) bypass via `AllowSetForegroundWindow` then `ChangeWindowMessageFilter` — published research from Adam Chester / James Forshaw.

**CVE exemplars.**
- **CVE-2014-4076** — IE memory corruption via WM_COPYDATA. (Confidence: LOW.)
- **CVE-2019-1132** — Win32k UIPI bypass. (Confidence: MEDIUM.)

**Our engagement coverage.** 0 directly tagged.

---

## I-006 — ALPC port (kernel)

**Definition.** Kernel-mode component creates an ALPC port (the modern LPC). Cross-trust connection without proper auth callback enables unprivileged → privileged calls.

**Trust boundary.** User-mode → kernel-mode (or cross-session user-mode → privileged user-mode service).

**Detection signals.** Static (kernel decomp): `IoCreateAlpcPort`, `NtAlpcCreatePort`, `NtAlpcSendWaitReceivePort` server stubs. ETW Microsoft-Windows-Kernel-Process for ALPC events at runtime.

**Defense pattern.** Implement an ALPC connection callback that validates caller via `AlpcGetMessageAttribute` and `PsLookupProcessByProcessId` checks.

**Bypass pattern.** James Forshaw's `taskhostw` ALPC research; multiple Windows ALPC LPE classes.

**CVE exemplars.**
- **CVE-2018-8440** — Task Scheduler ALPC LPE (the SandboxEscaper bug). (Confidence: HIGH — canonical.)
- **CVE-2020-1423** — ALPC. (Confidence: MEDIUM.)

**Our engagement coverage.** 0 directly tagged.

**Phase B notes.** Hard surface to enumerate without a kernel debugger workflow we haven't set up.

---

## I-007 — Mailslot

**Definition.** Service listens on `\\.\mailslot\<name>` for connectionless datagrams from any local user. Less common in modern Windows; legacy service-management surface.

**Detection signals.** `CreateMailslotW`, `GetMailslotInfo`, `ReadFile` on a mailslot handle.

**Defense pattern.** Set DACL via `lpSecurityAttributes`. Authenticate sender via `GetMailslotClientPID` (no such API exists — limitation: mailslots don't expose peer creds well).

**CVE exemplars.**
- **CVE-2014-1814** — Microsoft Server mailslot. (Confidence: LOW.)

**Our engagement coverage.** 0.

---

## I-008 — Shared section / cross-process memory

**Definition.** Privileged process creates a section (`NtCreateSection` / `CreateFileMappingW`) accessible by other principals. Section name in `\BaseNamedObjects\` is reachable by any local user with view permission. Attacker maps the section, mutates contents, racing/poisoning the privileged process's view.

**Detection signals.** `CreateFileMappingW(... NULL_or_permissive_SD)`, `NtCreateSection` with permissive `DesiredAccess`, `PAGE_READWRITE` access on shared regions. `ZwOpenSection` from low-priv to confirm reachability.

**Defense pattern.** Per-session local namespace (`\Sessions\<sid>\BaseNamedObjects\`), explicit DACL.

**CVE exemplars.**
- **CVE-2020-1054** — win32k.sys section abuse. (Confidence: LOW.)
- Multiple SMBGhost-adjacent CVEs use shared sections.

**Our engagement coverage.** 0.

---

## I-009 — Localhost TCP IPC (port-bound)

**Definition.** Service binds to `127.0.0.1:N` (or `0.0.0.0:N` with firewall rule) for IPC. Any local process connects to the port without OS-level peer authentication; the service's application-level auth determines safety. Differs from named pipes: ACL is replaced by port-binding semantics; SO_PEERCRED is unavailable on TCP.

**Trust boundary.** Standard user → privilege of listener.

**Detection signals.**
- *Static*: `socket(AF_INET, SOCK_STREAM, 0)` followed by `bind` to `INADDR_LOOPBACK` or `0.0.0.0`.
- *Dynamic*: `netstat -ano | findstr LISTENING` → identify processes binding low ports; `Get-NetTCPConnection -LocalAddress 127.0.0.1` (PowerShell). Cross-reference with the owning process's privilege.

**Defense pattern.** Application-level auth: TLS-with-mutual-cert, HMAC over messages, OAuth-style tokens. The IPC layer offers no protection on its own.

**Bypass pattern.** Service authenticates by checking peer's source port range or by IP source (always 127.0.0.1 on localhost) — useless.

**CVE exemplars.**
- **CVE-2016-1577** — Cisco AnyConnect localhost LPE. (Confidence: MEDIUM.)
- **CVE-2019-15999** — Cisco Webex localhost. (Confidence: LOW.)
- The user's TeamViewer findings are the canonical recent exemplars. (Confidence: HIGH.)

**Our engagement coverage** (3 findings, reclassified from I-002 in v2):
- `teamviewer-2026-03-31/findings/001-...`
- `teamviewer-2026-03-31/findings/002-...`
- `teamviewer-2026-03-31/findings/008-...`

**Phase B notes.** TeamViewer's localhost IPC was submitted to psirt@teamviewer.com 2026-04-29; awaiting reply. The class is large; many vendors do localhost-TCP IPC as a workaround for cross-platform compatibility.

---

# N — Network

## N-001 — DNS wire-format parser

**Definition.** Resolver, authoritative server, or DNS-over-HTTPS endpoint parses untrusted DNS packets. Wire format has compression pointers, RDATA sections of varying lengths, EDNS extensions. Bugs are often integer overflows in length fields, off-by-ones in compression-pointer chasing, type confusion when DNS_TYPE switching.

**Trust boundary.** Network attacker (anyone who can spoof a DNS response, or send a query if pre-auth) → server's privilege.

**Detection signals.**
- *Static*: parsers for RR types (A/AAAA/MX/TXT/SOA/RRSIG/NSEC3/SVCB/HTTPS/etc.). Library functions like `dns_name_fromwire`, `dns_message_parse`, `dnsdb_iterator`. Length-field arithmetic on RDATA.
- *Dynamic*: fuzzing with AFL++ + DNS-aware grammar (named-fuzz, Knot DNS fuzz harnesses).

**Defense pattern.** Strict bounds checking on every length field; compression-pointer cycle detection; explicit max-iterations on RR-list traversal; ASAN on debug builds.

**Bypass pattern.** Parser does length check on parent record but not nested records; integer-overflow bug class is endemic.

**CVE exemplars.**
- **CVE-2020-1350** — Windows DNS Server (SIGRed) — RR record integer overflow. (Confidence: HIGH — canonical.)
- **CVE-2023-50387** — KeyTrap DNSSEC. (Confidence: HIGH.)
- **CVE-2025-40780**, **CVE-2025-40778** — recent BIND CVEs. (Confidence: MEDIUM.)
- **CVE-2022-3094** — BIND named DoS. (Confidence: HIGH.)

**Our engagement coverage** (11 findings, all bind9):
- bind9-2026-04-06 has 11 findings auditing BIND parsers (rdata heap, TSIG, TKEY, HTTP/2 DoH, QNAME minimization, etc.)

**Phase B notes.** Bind9 audit was thorough; no submissions yet because none of the 11 findings reached confirmable PoC at server-RCE level. Pattern: DNS-server audits produce many "candidate" findings, few "ship" findings.

---

## N-002 — HTTP listener (HTTP.sys / IIS / custom)

**Definition.** Server-side HTTP request parser. URL parsing, header parsing, body parsing, multipart/form-data, chunked transfer encoding. Each is a CWE-rich surface (HTTP request smuggling, header injection, path traversal).

**Detection signals.** `HttpAddUrlToUrlGroup`, `HttpReceiveHttpRequest`, custom URL routers, request parsers.

**Defense pattern.** Use battle-tested HTTP libraries; strict RFC compliance; explicit length checks.

**CVE exemplars.**
- **CVE-2021-31207** — Windows HTTP.sys ProxyShell adjacent. (Confidence: MEDIUM.)
- **CVE-2022-21907** — HTTP Protocol Stack RCE. (Confidence: HIGH.)
- **CVE-2024-21762** — Fortinet FortiOS HTTPD. (Confidence: HIGH.)

**Our engagement coverage** (1 finding):
- `bind9-2026-04-06/findings/008-http2-null-deref-empty-sstreams.md` (the BIND DoH endpoint).

---

## N-003 — TLS / network protocol parser (transport-level)

**Definition.** Protocol parser running over TLS. The TLS layer protects integrity/confidentiality; the application layer trusts the server (or vice-versa) and parses payload. Bugs typically: malicious server (compromised vendor backend, MITM with cert validation bypass, BGP hijack of CDN) sending crafted responses to a client, or vice versa.

**Trust boundary.** Cross-network. Specifically the "malicious server" attacker model: a server vendor would typically operate trusts; if compromised or under-attacker-control, the response payload becomes attacker-controlled to clients. Combined with weak TLS validation, this opens to MITM.

**Detection signals.** `SSL_read` / `BIO_read` / Schannel `InitializeSecurityContext` followed by an application protocol parser. Custom binary protocols (Protocol Buffers, MsgPack, custom TLV).

**Defense pattern.** Cert pinning; HMAC over payloads; protocol parser fuzzing.

**Bypass pattern.** Cert validation skips hostname check; pinning omitted; "downgrade to plaintext on retry" fallback.

**CVE exemplars.**
- **CVE-2014-0160** — Heartbleed (TLS extension parsing). (Confidence: HIGH — canonical.)
- **CVE-2014-3566** — POODLE (CBC padding). (Confidence: HIGH.)
- **CVE-2023-46604** — ActiveMQ OpenWire deserialization. (Confidence: HIGH.)
- **CVE-2024-30078** — Wi-Fi protocol parser. (Confidence: HIGH.)

**Our engagement coverage** (8 findings):
- `protonvpn-local-agent-rce-2026-05-08/findings/001-malicious-server-dos-cluster.md` — submitted
- `telegram-desktop-2026-03-29/findings/001-mtpphoto-oob-read.md` — N-003 + N-004
- `nextcloud-desktop-2026-04-06/findings/001/002/004-...` — multiple
- `keeper-security-2026-04-09/findings/001-mitm-rce-cert-bypass.md` — N-003 + UP-003
- `backblaze-2026-04-08/findings/...` — restore protocol parser

**Phase B notes.** N-003 + UP-003 chain (MITM update feed) is high-yield: Keeper class has 1 in-flight submission.

---

## N-004 — Custom application protocol (payload-level)

**Definition.** Vendor-specific binary or text protocol parsed inside an established channel (TLS, named pipe, plain TCP). Bugs at the parser level: integer overflows in length fields, type confusion, deserialization of unsafe types.

**Detection signals.** Custom message-type dispatchers, hand-rolled TLV/TLE parsers.

**CVE exemplars.**
- **CVE-2025-7775** — Citrix Netscaler protocol bug. (Confidence: HIGH — referenced in our citrix engagement.)
- **CVE-2025-32756** — Fortinet protocol bug. (Confidence: HIGH — referenced in our fortinet engagement.)
- **CVE-2023-46805** — Ivanti protocol parser. (Confidence: HIGH.)

**Our engagement coverage** (2 findings):
- `telegram-desktop-2026-03-29/findings/001/002/...` — MTProto / Lottie payload

---

## N-005 — SSRF

**Definition.** Server-side fetcher takes a user-supplied URL and dereferences it. Internal network (cloud metadata service, internal admin services), file:// scheme, gopher://, alternate protocols, DNS rebinding for IP filter bypass.

**Detection signals.** `HttpClient.Get`, `WebClient.DownloadString`, `curl_easy_perform`, `requests.get` taking user-controlled URL strings.

**Defense pattern.** URL allowlist; DNS resolution before fetch + filter against internal IP ranges; disable redirects; disable file:// / gopher://.

**Bypass pattern.** DNS rebinding, IPv6 (allow IPv4 internal but allow all IPv6), URL parser confusion (`http://[::1]/`, `http://localhost%23.evil.com/`), 30x redirect to internal.

**CVE exemplars.**
- **CVE-2021-26855** — Exchange ProxyLogon SSRF. (Confidence: HIGH — canonical.)
- **CVE-2022-22965** — Spring4Shell adjacent. (Confidence: HIGH.)
- **CVE-2019-11580** — Atlassian Crowd. (Confidence: HIGH.)

**Our engagement coverage** (2 findings):
- `easyship-2026-04-15/findings/001-ssrf-webhook-dns-bypass.md` — submitted YWH
- `nextcloud-desktop-2026-04-06/findings/002-ssrf-direct-download-url.md`

---

## N-006 — WebSocket

**Definition.** Server accepts WebSocket connections; per-message processing without auth/origin/length checks.

**Detection signals.** `WebSocketAcceptUpgrade`, `OnMessage` handlers, `wss://` endpoints in JS configs.

**CVE exemplars.**
- **CVE-2022-26133** — Atlassian SAML WebSocket. (Confidence: LOW.)

**Our engagement coverage.** 0.

---

## N-007 — Multicast / mDNS / broadcast listener

**Definition.** UDP listener on multicast (224.0.0.0/4) or broadcast (255.255.255.255). Untrusted by definition; on-link attacker can craft packets.

**CVE exemplars.**
- **CVE-2017-15098** — Apple mDNSResponder. (Confidence: MEDIUM.)
- **CVE-2020-13988** — Multiple mDNS implementations. (Confidence: LOW.)

**Our engagement coverage.** 0.

---

# K — Kernel / Driver

## K-001 — IOCTL input buffer (IRP_MJ_DEVICE_CONTROL)

**Definition.** User-mode `DeviceIoControl(handle, ioctl, in_buf, in_len, out_buf, out_len, ...)` reaches the driver's `IRP_MJ_DEVICE_CONTROL` dispatch. The IRP_STACK_LOCATION's `Parameters.DeviceIoControl.IoControlCode` is the function selector; `Type3InputBuffer` / `SystemBuffer` is the input data. Method (METHOD_BUFFERED / IN_DIRECT / OUT_DIRECT / NEITHER) determines who owns the memory and what bounds the kernel performs automatically.

**Trust boundary.** Standard user → kernel. Specifically, any user with sufficient access to the device object (per its SDDL) can issue IOCTLs.

**Detection signals.**
- *Static*: `DriverEntry` sets `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]`. The handler walks the IRP stack: `IoGetCurrentIrpStackLocation(Irp)`, then a switch over `IoControlCode`. Each case is one IOCTL handler.
- *Static*: `IoControlCode` decode: bits encode (DeviceType<<16) | (Access<<14) | (Function<<2) | Method. `Method = IoControlCode & 3` gives 0=BUFFERED, 1=IN_DIRECT, 2=OUT_DIRECT, 3=NEITHER. NEITHER is dangerous: kernel does not validate user pointers; driver must call `ProbeForRead`/`ProbeForWrite`.
- *Static*: `IoCreateDevice` + `IoCreateSymbolicLink` with permissive Characteristics. `IoCreateDeviceSecure` with SDDL.
- *Static*: helpers like `SeAccessCheck` to authenticate the caller within the IOCTL handler.
- *Dynamic*: `WinObj.exe` from Sysinternals to enumerate `\Device\` and `\GLOBAL??\` for accessible names; `accesschk.exe -e \Device\<name>`.

**Defense pattern.**
1. SDDL on the device object excludes `Authenticated Users` write access (Microsoft uses `D:P(A;;GA;;;SY)(A;;GA;;;BA)` for SYSTEM-only).
2. Per-IOCTL ACL via `SeAccessCheck` against a privileged token.
3. METHOD_BUFFERED for any IOCTL that doesn't need zero-copy.
4. For METHOD_NEITHER: `ProbeForRead(buffer, length, alignment)` + `ProbeForWrite(buffer, length, alignment)` inside `__try`/`__except`.
5. Length checks on `InputBufferLength` / `OutputBufferLength` against fixed sizes.
6. Integer-overflow checks on user-supplied lengths used as buffer sizes (the canonical Cisco DBUtil bug).

**Bypass pattern.**
- Driver checks `InputBufferLength >= sizeof(SOMETHING)` but uses a length field WITHIN the buffer for subsequent allocation/copy → integer underflow.
- Driver `ProbeForRead`s user pointer A but operates on user pointer B copied from A — TOCTOU class.
- Driver issues `MmMapLockedPages` on user-supplied MDL → user-mode unmaps mid-execution.
- Driver double-fetches a length from user buffer (multi-fetch class — see K-006).
- Driver assumes a particular bit pattern is invariant after `ProbeForRead`.

**CVE exemplars.**
- **CVE-2021-21551** — Dell DBUtil — IOCTL with attacker-controlled physical memory access. (Confidence: HIGH — canonical "BYOVD" anchor.)
- **CVE-2022-22047** — Windows CSRSS LPE. (Confidence: HIGH.)
- **CVE-2020-17087** — Windows cng.sys. (Confidence: HIGH.)
- **CVE-2023-21768** — Windows AFD.sys IOCTL LPE. (Confidence: HIGH — used widely in exploits.)
- **CVE-2024-1086** — Linux nftables IOCTL-class. (Confidence: HIGH — different OS but illustrative.)
- **CVE-2024-21338** — Windows AppLocker driver IOCTL. (Confidence: HIGH.)

**Our engagement coverage** (16 findings, our largest class):
- `cisco-secure-client-2026-03-30/findings/001-integer-overflow-heap-overflow.md` — submitted; the FP variant
- `cisco-secure-client-2026-03-30/findings/002-method-neither-arbitrary-kernel-write.md`
- `cldflt-2026-04-28/findings/001-...`
- `clfs-sys-2026-04-28/findings/001-AddNewClient-uninit-vtable-call.md` (variant analysis)
- `vhdmp/vid/storvsp/vkrnlintvsp/vmusrv/storvsc` — Hyper-V class
- `bitdefender-2026-05-02` — bddci4 etc.
- `tdx-sys-2026-04-28/findings/...`
- `afd-sys-2026-04-28/findings/...`
- `ms-kernel-ioctl-2026-05-04/findings/...`

**Phase B notes.** This is our broadest class but submission-yield is moderate (3 of 21 submitted). The hard part is reaching impact: an out-of-bounds read in a kernel driver is hard to convert to LPE without an arbitrary-write primitive. Variant analysis on Microsoft kernel drivers (vhdmp, vid, storvsp) has been productive — the user filed VULN-186170 on vhdmp.

---

## K-002 — FSCTL / minifilter port operation

**Definition.** Minifilter driver registers a communication port via `FltCreateCommunicationPort`. User-mode connects with `FilterConnectCommunicationPort` and sends messages via `FilterSendMessage`. Different from K-001 because the protocol is the FltMgr communication port, not direct IRP_MJ_DEVICE_CONTROL.

**Detection signals.** `FltRegisterFilter`, `FltCreateCommunicationPort`, message handlers registered in `Operations[]`. Per-operation PRE/POST callbacks.

**Defense pattern.** SDDL on the port; per-message authentication; bounds-check input/output sizes.

**CVE exemplars.**
- **CVE-2023-36802** — Windows MSKSSRV.SYS — kernel callback class. (Confidence: HIGH.)
- **CVE-2025-21333** — Windows Bind Filter Driver. (Confidence: MEDIUM.)
- **CVE-2024-26229** — Windows CSC. (Confidence: MEDIUM.)

**Our engagement coverage** (1 finding):
- `bitdefender-total-security-2026-04-11/findings/004-trufos-kernel-infoleak.md` — Trufos `\TRFCOMMPORT` port leaks pool address via `FilterSendMessage`. Submitted to Bugcrowd as `c100b59d`; closed P3 Not Applicable.

---

## K-003 — WMI provider input

**Definition.** Kernel-mode driver registers a WMI provider via `IoWMIRegistrationControl`. WMI clients (`Get-WmiObject`, `wbemtest.exe`) call methods that reach the driver. Less common; specialized targets.

**Detection signals.** `IoWMIRegistrationControl`, `WMILIB_CONTEXT`, GUID registrations in driver's MofResource.

**CVE exemplars.**
- **CVE-2022-44698** — Windows WMI provider class. (Confidence: LOW.)

**Our engagement coverage.** 0.

---

## K-004 — Object/process/image-load/registry callback

**Definition.** Kernel callback registered by an EDR/AV driver to mediate user-mode operations. Sometimes the source of bugs (callback itself parses unsafe data); usually the defense.

**Detection signals.** `ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `CmRegisterCallbackEx`, `PsSetCreateThreadNotifyRoutine`.

**CVE exemplars.**
- **CVE-2024-26229** — Windows CSC callback. (Confidence: MEDIUM.)

**Our engagement coverage.** 0 (defensive surface mostly).

---

## K-005 — Non-IOCTL IRP (read/write/create)

**Definition.** Driver registers `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_CREATE` handlers without proper auth. User-mode reaches via `ReadFile`/`WriteFile` on the device. Some filesystem and storage drivers expose surface here.

**CVE exemplars.**
- **CVE-2022-44698** — adjacent Windows kernel class. (Confidence: LOW.)

**Our engagement coverage.** 0 directly tagged (variant of K-001 in practice).

---

## K-006 — Kernel-resident user-mapped buffer (multi-fetch / Cc-mapped)

**Definition.** Kernel driver maps a user-mode-influenced buffer into kernel address space (via `MmMapLockedPages`, `MmGetSystemAddressForMdlSafe`, `CcMapData`, file-backed sections), then reads multiple times during processing. User-mode flips the contents between reads → kernel sees inconsistent data → use-after-validate bug.

**Trust boundary.** User-mode → kernel; specifically the trust assumption that "after `ProbeForRead`, the user buffer is safe to dereference" is FALSE because user-mode can race.

**Detection signals.**
- *Static*: same field accessed multiple times within one IOCTL handler. Pattern: `if (buf->len < MAX) { ... use buf->len ... }` where `len` is read twice.
- *Static*: `CcMapData`, `MmMapLockedPages`, `RtlCopyMemory` with size from a dereferenced user-controlled pointer.
- *Tooling*: `scripts/multifetch_scan.py` (the user wrote this for the CVE-2026-3006 class).

**Defense pattern.** Kernel-pool snapshot before validate-and-use: copy the user buffer to a kernel-allocated buffer first, then validate-and-operate on the kernel copy.

**Bypass pattern.** Vendor adds snapshot for Method-Buffered IOCTLs but missed Method-Neither paths; or snapshot for one syscall but not the IOCTL that reaches the same code.

**CVE exemplars.**
- **CVE-2026-3006** — WinFSP family multi-fetch into ExAllocatePool. (Confidence: HIGH — the user worked this; recent.)
- **CVE-2023-21674** — Windows ALPC double-fetch. (Confidence: MEDIUM.)
- **CVE-2018-8453** — Win32k double-fetch. (Confidence: MEDIUM.)

**Our engagement coverage** (2 findings):
- `clfs-sys-2026-04-28/findings/004-UpdateCachedOwnerPage-cache-race-multifetch.md` — false positive (FILE_SHARE_NONE blocks)
- `clfs-sys-2026-04-28/findings/003-CreateImage-multifetch-candidate.md` — candidate

**Phase B notes.** This class is well-tooled (multifetch_scan.py). The user has the recipe; defense recognizers are mature.

---

# U — User-input / process surface

## U-001 — Elevated process argv parsing

**Definition.** A privileged process is launched with attacker-controllable command-line arguments. Common channels: scheduled tasks (the user can set the trigger), services with permissive `lpServiceArgVectors`, helper binaries called by elevation prompts.

**CVE exemplars.**
- **CVE-2022-26904** — Windows User Profile Service argv. (Confidence: MEDIUM.)
- Various MSI custom-action argv bugs.

**Our engagement coverage.** 0 directly tagged.

---

## U-002 — Environment variable trust

**Definition.** Privileged process reads an environment variable that the calling user controls. Common in services started by `runas` or scheduled tasks where the user's environment is inherited.

**CVE exemplars.**
- **CVE-2017-1000367** — sudo TTY env var. (Confidence: HIGH — canonical.)
- **CVE-2019-7619** — pkexec env. (Confidence: MEDIUM.)

**Our engagement coverage.** 0.

---

## U-003 — Custom-protocol-handler URL routing

**Definition.** OS routes `myapp://...` URL to a registered handler. The URL becomes argv[1] (Windows) or `process.argv` in Electron. Application parses the URL fragment into commands; if parsing is unsafe, attacker-controlled URLs become attacker-controlled commands.

**Detection signals.** `app.setAsDefaultProtocolClient` (Electron). `HKCR\<scheme>\shell\open\command` (Windows). `app.on('second-instance', argv => ...)`.

**CVE exemplars.**
- **CVE-2018-8174** — IE / Edge URL handler. (Confidence: MEDIUM.)
- **CVE-2024-21412** — Windows SmartScreen URL bypass. (Confidence: HIGH.)
- **CVE-2024-1597** — Discord protocol handler. (Confidence: LOW.)

**Our engagement coverage** (1 finding):
- `telegram-desktop-2026-03-29/findings/003-bg-typo-protocol-handler.md`

---

## U-004 — Clipboard / drag-drop content

**Definition.** Privileged paste handler trusts content (RTF, HTML clipboard format, file-list drop).

**CVE exemplars.**
- **CVE-2017-11882** — Office Equation (clipboard not strictly but file-handler class). (Confidence: HIGH.)

**Our engagement coverage.** 0.

---

## U-005 — Window-message input

**Definition.** Privileged WndProc accepts user input messages. Distinct from I-005 (WM_COPYDATA): this covers WM_KEYDOWN, WM_LBUTTONDOWN, etc. used to drive privileged-app state transitions.

**Our engagement coverage.** 0.

---

# T — Trust assumption

## T-001 — WinVerifyTrust on file path (process-hollowing)

**Definition.** Privileged peer in an IPC handshake authenticates the caller by reading the caller's image file via `GetNamedPipeClientProcessId` → `OpenProcess(PROCESS_QUERY_INFORMATION)` → `QueryFullProcessImageNameW` → `WinVerifyTrust(image_path)`. The check trusts the FILE on disk, not the running CODE in memory. Attacker process-hollows: spawns from a signed binary (suspended), unmaps original image, writes attacker code, resumes. The kernel-stored ImageFileName remains the signed file's path; WinVerifyTrust passes; running code is fully attacker-controlled.

**Trust boundary.** Standard user → privilege of the IPC peer.

**Detection signals.**
- *Static*: trust check chain: `GetNamedPipeClientProcessId` → `QueryFullProcessImageNameW` → `WinVerifyTrust`. No attempt to verify in-memory code (e.g., no `ZwQueryVirtualMemory` of caller's image base + hash compare).
- *Dynamic*: process-hollowing PoC against the trusting service.

**Defense pattern.** Verify in-memory code: hash the caller's image base via `ZwReadVirtualMemory`, compare against an expected hash. Or use Protected Process Light (PPL) for the trusting service so it can't have its memory probed by user-mode for the sibling check, BUT the trusting service itself is now PPL — usually too costly.

**Bypass pattern.** The CVE-class itself.

**CVE exemplars.**
- **CVE-2013-3900** — original WinVerifyTrust signature-validation issue. (Confidence: HIGH.)
- **CVE-2022-34689** — Windows CryptoAPI signature spoof. (Confidence: HIGH.)

**Our engagement coverage** (2 findings):
- `dropbox-2026-04-30/findings/001-dbxsvc-signature-validation-bypass.md`
- `bitdefender-2026-05-02/findings/002-safeelevatedrun-wvt-toctou.md`

---

## T-002 — PEB.ImagePathName trust

**Definition.** Server-side check reads `NtQueryInformationProcess(ProcessBasicInformation)` then walks PEB to ImagePathName. PEB is in user-writable memory of the calling process; attacker pre-writes a fake path. Different from T-004: T-002 is PEB-based, T-004 is kernel-image-path-based (NtQueryInformationProcess(ProcessImageFileName) which sources from EPROCESS->SectionObject and is NOT user-writable).

**CVE exemplars.**
- General process-spoofing research, multiple security blogs. (Confidence: LOW for specific CVE-IDs.)

**Our engagement coverage.** 0 confirmed; hypothesised in BDTS msgbus reversing.

---

## T-003 — Token / SID / membership check spoofable

**Definition.** Privileged check uses `CheckTokenMembership(NULL, AdminSid, ...)` or `GetTokenInformation(token, TokenGroups)` and trusts. Various SID-shadowing or restricted-token bypasses can confuse these checks.

**CVE exemplars.**
- **CVE-2017-0175** — Windows AppContainer token. (Confidence: LOW.)

**Our engagement coverage.** 0.

---

## T-004 — Caller-process-image-path trust without impersonation

**Definition.** Server takes the peer's process ID and queries the kernel for the image path (via `NtQueryInformationProcess(ProcessImageFileName)`). The kernel image path IS authoritative (sourced from EPROCESS->SectionObject), so process-hollowing doesn't bypass T-004. But: attacker can still match the trust check by injecting code into a binary that LEGITIMATELY has the trusted path.

**Detection signals.** `NtQueryInformationProcess` with `ProcessImageFileName` class (29) on a peer pid; comparison against a trusted-path string.

**Defense pattern.** No defense at the trust-check level; this IS the strongest static-trust signal Windows offers. The right defense is: don't have IPC at all, OR require fresh authentication beyond image-path identity.

**Bypass pattern.** Inject code into a process that legitimately has the trusted path. On systems with no PPL or no protection on the trusted image, dll-injection or process-injection (when the injecting principal is also user-mode) defeats it.

**CVE exemplars.**
- The user's BDTS msgbus `trusted_client_process` reversing in `notes_msgbus_auth_reversing.md` is the canonical exemplar in our engagement coverage. (Confidence: HIGH.)

**Our engagement coverage** (1 finding):
- `bitdefender-2026-05-02/findings/001-msgbus-trusted-process-bypass.md`

---

## T-005 — Path-traversal / canonicalization in trust check

**Definition.** Trust check uses string-comparison (`wcsncmp`, `strncmp`, `StringCchCompare`) on a user-influenced path against an allow-list, but the path is not canonicalized. `..` segments slip through; the resolved file is outside the allow-list.

**Detection signals.**
- *Static*: `wcsncmp(user_path, expected_prefix, len)` with `len = wcslen(expected_prefix)`. Absent canonicalization: no `GetFullPathNameW`, `PathCanonicalize`, `RtlGetFullPathName_U`.
- *Static*: path normalizer that lowercases / replaces slashes / strips quotes but does NOT call any canonicalization API.

**Defense pattern.** Canonicalize before compare: `GetFullPathNameW(path, MAX_PATH, canonical, NULL)` then `wcsncmp(canonical, expected_prefix, ...)`. Or use `PathIsPrefix` from shlwapi on canonicalized inputs.

**Bypass pattern.**
- `..\` segments resolving outside the allow-list.
- 8.3 short-name aliasing (`PROGRA~1` for `Program Files`).
- UNC vs DOS path equivalences.
- Symlink/junction in the path components.

**CVE exemplars.**
- **CVE-2024-7344** — Howyar Reloader Authenticode bypass. (Confidence: HIGH.)
- The user's BDTS 005 finding. (Confidence: HIGH.)

**Our engagement coverage** (2 findings):
- `bitdefender-total-security-2026-04-11/findings/005-safeelevatedrun-path-traversal.md` — submitted P3
- `teamviewer-2026-03-31/findings/003-driver-install-validation-analysis.md`

---

## T-006 — Same-sign / co-signing assumption

**Definition.** Server requires the peer to be signed by the same publisher as the server. Bypassable when the publisher has any signed binary that loads attacker-controllable code (DLL search-order, IPC marshalling, command-line argv).

**CVE exemplars.**
- General research on co-signing assumptions; multiple AV product writeups.

**Our engagement coverage** (2 findings):
- `bitdefender-total-security-2026-04-11/findings/005,006` — co-tagged with T-005 / I-002.

---

## T-007 — Internal-component-as-untrusted-source (coalition / threshold)

**Definition.** Multi-party protocol assumes integrity if M-of-N components are honest. If the threat model includes coalition-of-K compromised components (K < M), aggregator components running with full data become untrusted sources to the rest of the system.

**CVE exemplars.**
- Threshold cryptography literature (Scytl / Swiss Post audits).
- **CVE-2021-43528** — Mozilla Firefox isolation related. (Confidence: LOW.)

**Our engagement coverage** (1 finding):
- `swiss-post-evoting-2026-04-06/findings/003-untrusted-server-aggregates-threshold-shares.md`

---

# UP — Update / install / package

## UP-001 — Auto-updater unsigned-binary execution

**Definition.** Updater fetches and executes a payload without verifying a vendor signature. Any MITM (network), DNS hijack, or CDN compromise serves attacker-controlled binary.

**Detection signals.** `Process.Start(downloaded_path, ...)` with no `WinVerifyTrust(downloaded_path)` between download and exec.

**CVE exemplars.**
- **CVE-2020-15889** — JetBrains TeamCity auto-update unsigned. (Confidence: MEDIUM.)
- **CVE-2022-23748** — Audinate Dante installer. (Confidence: MEDIUM.)

**Our engagement coverage** (2 findings):
- `backblaze-2026-04-08/findings/002-unsigned-update-execution-lpe.md`
- `malwarebytes-2026-04-29/findings/005-mbupdatr-toctou-mbuns.md`

---

## UP-002 — Squirrel.Windows update channel

**Definition.** Squirrel.Windows' Update.exe runs as the user but invokes elevated MSI install steps. Manipulation of the feed URL (`%LOCALAPPDATA%\<app>\packages\.config`) or the update package can substitute a malicious Update.exe.

**Detection signals.** `Update.exe --update <url>`, `%LOCALAPPDATA%\<app>\packages\` writability checks.

**CVE exemplars.**
- **CVE-2018-1000136** — Electron Squirrel-related. (Confidence: LOW.)

**Our engagement coverage.** 0.

---

## UP-003 — electron-updater / update-feed manipulation

**Definition.** electron-updater fetches a `latest.yml` (or app-update.yml) from a feed URL. If the feed is HTTP (not HTTPS), or if cert validation is lax, MITM serves a manipulated YAML pointing at attacker-supplied installer path.

**Detection signals.** `electron-updater` package usage, feed URLs in `package.json`/`build.appUpdater`. HTTPS-required check.

**Defense pattern.** Cert pinning, signature on `latest.yml`, code-sign on the downloaded package.

**Bypass pattern.** Feed URL is HTTP; vendor disabled signature requirement for "small fast iterations".

**CVE exemplars.**
- **CVE-2023-25809** — electron-updater path traversal. (Confidence: MEDIUM.)
- **CVE-2024-29024** — Logitech Sync update. (Confidence: LOW.)

**Our engagement coverage** (3 findings):
- `nextcloud-desktop-2026-04-06/findings/001/004-...`
- `keeper-security-2026-04-09/findings/001-mitm-rce-cert-bypass.md`

---

## UP-004 — MSI custom-action argv

**Definition.** MSI custom action (DLL or VBScript) takes properties from the MSI invocation. If `msiexec /i` is invoked with attacker-controllable properties (via UAC consent + standard-user MSI install), custom action receives attacker input as argv.

**CVE exemplars.**
- **CVE-2024-38014** — Windows Installer Standard User Elevation. (Confidence: HIGH.)

**Our engagement coverage.** 0 directly tagged (Dell SAI is closer to UP-005).

---

## UP-005 — Installer extract-then-execute

**Definition.** Installer extracts a payload (DLL, EXE, ZIP) to a path, then runs/loads it. If the extract path is attacker-influenceable (junction, race, path-traversal), the executed binary is attacker-controlled.

**Detection signals.** `_wfopen(path, "wb")` followed by `LoadLibrary(path)` or `CreateProcess(path)`. `Path.GetTempPath()` + `Path.Combine` + `File.WriteAllBytes` + `Process.Start` (.NET).

**CVE exemplars.**
- **CVE-2024-38305** — Dell SupportAssistInstaller. (Confidence: HIGH — the user filed a variant.)
- **CVE-2022-26904** — Windows User Profile Service. (Confidence: MEDIUM.)

**Our engagement coverage** (2 findings):
- `acronis-2026-05-07/findings/002-rce-via-dll-extraction.md`
- `malwarebytes-2026-04-29/findings/005-mbupdatr-toctou-mbuns.md` (also UP-001)

---

# C — Configuration / persistence

## C-001 — Registry value with permissive DACL trusted by elevated process

**Definition.** Privileged process reads a registry value whose subkey's DACL grants write to a lower-privilege principal. Hive (HKCU/HKLM/HKU) is irrelevant; the DACL is the source-class membership.

**Detection signals.**
- *Static*: `RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\<vendor>\\<sub>", ...)` followed by `RegQueryValueExW` of values used in privileged decisions.
- *DACL inspection*: `accesschk.exe -k <key>` to see who can write.

**Defense pattern.** SDDL on the subkey: admin-write only.

**Bypass pattern.** Vendor inherits parent ACL by default; some vendors use HKLM\SOFTWARE\<vendor>\Settings with default ACL (which is admin-write but Authenticated Users read) — fine for read trust but breaks if vendor relaxes for "settings sync".

**CVE exemplars.**
- **CVE-2024-21351** — Windows SmartScreen registry. (Confidence: LOW.)
- Multiple vendor-specific registry-trust LPEs.

**Our engagement coverage** (2 findings):
- `dropbox-2026-04-30/findings/002-bypass-validation-registry-flag.md`
- `dropbox-2026-04-30/findings/003-uninstall-cmd-substring-bypass.md`

---

## C-002 — Config file in user-writable location

Variant of F-002/F-006. See those.

---

## C-003 — GPO / policy preference

**Definition.** Group Policy preferences (registry blobs in `\\<domain>\SYSVOL\<domain>\Policies\<gpo>\Machine\Preferences\Groups\Groups.xml`) historically contained encrypted credentials with a known key. Modern variants: enterprise software trusts policy values writable by lower-tier admins.

**CVE exemplars.**
- **CVE-2014-1812** — Windows Group Policy Preferences cpassword. (Confidence: HIGH — historical canonical.)

**Our engagement coverage.** 0.

---

## C-004 — Service start parameters

**Definition.** Service config arguments (`lpServiceArgVectors` in `StartServiceW`) can be set by users with `SERVICE_START` access on the service. If the service binary parses argv, those args become attacker-controlled.

**Our engagement coverage.** 0.

---

# E — Electron-specific

## E-001 — ipcMain.on/handle channel

**Definition.** Electron main process registers `ipcMain.on('channel', handler)` or `ipcMain.handle('channel', handler)`. Renderer-supplied arguments reach the main process, which has Node.js access (fs, child_process, registry, etc.). If the renderer is compromised (XSS in a page loaded by the app, or the app is `nodeIntegration:true`), or if a third-party page can reach the same channel, the renderer-supplied args become attacker-controlled.

**Detection signals.** Static walk of the asar-extracted source for `ipcMain.on(`/`ipcMain.handle(` calls; map channel names to handler signatures.

**Defense pattern.** `contextIsolation: true` (default modern). Validate every handler argument. Don't pass user input to `child_process.exec`, `fs.writeFile`, `eval`.

**Bypass pattern.** Handler trusts a `path` argument and calls `fs.writeFile` with no path validation; renderer XSS supplies attacker path.

**CVE exemplars.**
- **CVE-2018-1000136** — Electron contextIsolation related. (Confidence: MEDIUM.)
- **CVE-2024-1597** — Discord. (Confidence: LOW.)

**Our engagement coverage** (2 findings):
- `keeper-security-2026-04-09/findings/002-...`, `003-...`

---

## E-002 — Custom protocol handler URL routing (Electron)

**Definition.** `app.setAsDefaultProtocolClient('myapp')` + `app.on('second-instance', (e, argv) => ...)` parses the URL fragment. Browser-delivered URL becomes argv.

**Detection signals.** `setAsDefaultProtocolClient`, `protocol.handle`, `protocol.registerSchemesAsPrivileged`.

**CVE exemplars.**
- **CVE-2018-1000006** — Electron protocol handler RCE. (Confidence: HIGH — canonical.)

**Our engagement coverage.** 0 cleanly tagged (U-003 captures one related case).

---

## E-003 — webPreferences.nodeIntegration:true

**Definition.** BrowserWindow configured with `nodeIntegration: true`. The renderer can call Node APIs directly. Any XSS in the renderer becomes RCE.

**Detection signals.** Search asar for `nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false`.

**Defense pattern.** Default modern Electron has `contextIsolation: true` and `nodeIntegration: false`. Use `contextBridge.exposeInMainWorld` for explicit API surface.

**CVE exemplars.**
- **CVE-2018-15685** — Electron nodeIntegration in iframe. (Confidence: HIGH.)
- **CVE-2024-29017** — vm2 sandbox-escape (related class). (Confidence: HIGH.)

**Our engagement coverage** (1 finding):
- `mongodb-compass-2026-05-07/findings/001-...`

---

## E-004 — protocol.registerFileProtocol unvalidated

**Definition.** `protocol.registerFileProtocol('myapp', (request, callback) => callback({ path: ... }))` resolves attacker URL fragments to filesystem paths.

**CVE exemplars.**
- **CVE-2023-44402** — Electron registerFileProtocol path traversal. (Confidence: MEDIUM.)

**Our engagement coverage.** 0.

---

## E-005 — BrowserWindow.loadURL with attacker URL

**Definition.** Main process `loadURL` with a URL derived from user input (deep link, IPC, file association). If `webSecurity: false` or untrusted page loaded, RCE potential.

**Our engagement coverage.** 0.

---

## E-006 — Renderer XSS in trusted origin

**Definition.** XSS in a page loaded by Electron, especially in pages with `contextBridge.exposeInMainWorld` exposing privileged APIs.

**CVE exemplars.**
- **CVE-2020-15174** — Electron content-handling. (Confidence: LOW.)
- **CVE-2024-1597** — Discord XSS. (Confidence: LOW.)

**Our engagement coverage** (2 findings):
- `telegram-desktop-2026-03-29/findings/004-iv-srcdoc-url-injection.md`
- `notion-2026-05-08/findings/002-saveTransactions-xss-sweep.md`

---

## E-007 — Squirrel/electron-updater feed (overlap with UP-003)

See UP-003.

---

# W — Web (auth/session)

## W-001 — Authenticated user session as source

**Definition.** Authenticated cross-tenant or cross-user data access. The user is authenticated; the bug is in authorization scope (IDOR, missing tenant filter, predictable IDs).

**Detection signals.** API endpoints taking object IDs without tenant scoping.

**CVE exemplars.**
- **CVE-2023-23397** — Outlook IDOR-flavored. (Confidence: MEDIUM.)
- Many SaaS-vendor specific.

**Our engagement coverage** (7 findings): Easyship (the SSRF chains), Notion guidance compliance, Swiss Post auth-attempt counter, etc.

---

## W-002 — Cross-tenant authorization gap

**Definition.** Auth enforced but tenant scope missing. Specific subset of W-001.

**Our engagement coverage.** 0 directly tagged (Notion guidance documents this class but our findings haven't shipped one cleanly yet).

---

## W-003 — Pre-auth endpoint

**Definition.** Endpoint accepts requests with no authentication at all. Attack surface = the entire Internet.

**CVE exemplars.**
- **CVE-2021-26855** — Exchange (auth-bypass leading to SSRF). (Confidence: HIGH.)
- **CVE-2024-3400** — PAN-OS pre-auth RCE. (Confidence: HIGH.)

**Our engagement coverage** (1 finding):
- `swiss-post-evoting-2026-04-06/findings/002-auth-attempt-counter-race.md`

---

# CR — Cryptographic primitive misuse

## CR-001 — Constant-key / many-time-pad encryption of privileged data

**Definition.** Encryption uses a constant or predictable key (hardcoded byte string, derived deterministically from public values, reused across sessions). Stream-cipher reuse (XOR with same keystream twice) enables plaintext recovery from ciphertext pair. AES-CTR with same nonce twice is the same problem.

**Detection signals.** Constant byte arrays passed as keys; PRNG seeded with constants; nonce reset between encryption operations.

**Defense pattern.** `BCryptGenRandom` for keys; nonces from `BCryptGenRandom` per-message; AEAD modes (GCM/CCM) which fail catastrophically on nonce reuse (a feature to force fresh nonces).

**CVE exemplars.**
- **CVE-2017-1000119** — Joomla AES-ECB constant-key. (Confidence: LOW.)
- **CVE-2007-1071** — encrypted protocols with key-reuse. (Confidence: LOW.)
- **WhatsApp many-time-pad** — non-CVE published findings. (Confidence: HIGH for the existence of these reports.)

**Our engagement coverage** (1 finding):
- `malwarebytes-2026-04-29/findings/002-constant-xor-keystream.md` — the new class added in v2 taxonomy

---

## CR-002 — Reserved (signature/HMAC omitted by default)

Placeholder for Phase B expansion when engagement coverage warrants.

---

# How to use this taxonomy

1. **During triage**: classify each suspected source under the closest class ID. If multiple apply, list all (most chains are multi-class). If none fit, propose a new ID with `UNCLASSIFIED-<short-name>` and document in the engagement notes.
2. **During catalog entry**: every catalog source `via:` field should reference the class ID. The catalog YAML's `notes:` field can include the CVE exemplar for that class.
3. **During variant analysis**: find the class for the published CVE; check our `engagements/_audit/sources_observed.jsonl` for prior work on the same class; load `taxonomy/binary/sources_v2.json` to drive `build_chains.py` matching.
4. **During worker dispatch**: each worker prompt (`prompts/workers/*`) should reference the v2 class IDs in its output schema. Currently these workers use ad-hoc tagging; Phase B follow-up updates them.

# Cross-class patterns we've actually shipped

The Phase A audit surfaced **6 of our 21 submitted findings co-tag IPC + trust-assumption** classes:

| Engagement | Finding | Classes |
|---|---|---|
| BDTS 04-11 | 005-safeelevatedrun-path-traversal | I-002 + T-005 + T-006 |
| BDTS 04-11 | 006-seccenter-safeelevatedrun-relay-lpe | I-002 + T-006 |
| BDTS 05-02 | 001-msgbus-trusted-process-bypass | I-002 + T-004 |
| BDTS 05-02 | 002-safeelevatedrun-wvt-toctou | I-002 + T-001 |
| Dropbox | 001-dbxsvc-signature-validation-bypass | I-001 + T-001 |
| TeamViewer | 003-driver-install-validation-analysis | I-002 + T-005 |

This is a chain shape worth elevating: when we open a desktop-product engagement with a SYSTEM service exposing IPC, the highest-yield audit is to enumerate (a) every IPC entry point AND (b) every trust assumption that gates it. Pure I-002 alone (no auth bypass) is a low-yield finding; pure T-005 alone (path traversal in a non-IPC context) is rare. The pair is the kill chain.

# What's next (Phase C, future)

Phase C should:
1. Build per-class detection-tool scripts that run automatically: a "given this binary, is this class present?" check. Some classes have these (multifetch_scan.py for K-006, the source-enumerators for F-001/F-002). Most don't.
2. Update `taxonomy/binary/sources.json` to v2 schema (separate file from this one for tool consumption).
3. Update worker prompts (`prompts/workers/inspect_function*.md`, `enumerate_fs_sources_*.md`) to reference v2 class IDs.
4. Cross-reference each class with `taxonomy/binary/assumption_attacks.json` for the trust-assumption-violation patterns.
5. Build a `scripts/audit_sources.py` that reproduces the Phase A extraction on demand for new engagements.
