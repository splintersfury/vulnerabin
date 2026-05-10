# CWE-367: TOCTOU & Assumption Attack Methodology

## What It Is

A TOCTOU (Time-of-Check to Time-of-Use) vulnerability exists when a security check validates
a condition that can change between the check and the subsequent use of the checked value.
But TOCTOU is actually a specific instance of a broader class: **assumption attacks** — where
the attacker doesn't break the security check, but violates what the check *assumes* about
the world.

The key mindset shift: **Don't try to beat the check. Ask what the check takes for granted.**

## The Assumption Audit

When you encounter a security gate (hash check, access control, validation), ask these five
questions:

1. **What does this check actually verify?** (Not what it *intends* to verify — what does the
   code *literally* do?)
2. **What does it assume stays constant?** (File contents? Object identity? Memory values?
   Process state?)
3. **Can an attacker change the assumed-constant thing?** (Via race, hardlink, shared memory,
   handle recycling?)
4. **Is there a time gap between check and use?** (Even a few instructions can be enough with
   the right technique)
5. **Does the check verify the thing itself, or a proxy for the thing?** (Path vs loaded binary,
   handle vs object, name vs identity)

## Code Patterns to Look For

### File-Based TOCTOU (Hardlink/Symlink)

```c
// CHECK: reads file at process image path, computes hash
GetProcessImageFileName(hProcess, path, MAX_PATH);
hash = SHA256_HashFile(path);
if (memcmp(hash, trusted_hash, 32) != 0)
    return ACCESS_DENIED;

// USE: grants access based on the hash check
// ASSUMPTION: file at 'path' IS the code running in the process
// REALITY: attacker can swap the file between load and check via hardlink
```

**Trigger indicators:**
- `ZwQueryInformationProcess(ProcessImageFileNameWin32)`
- `GetModuleFileName` / `QueryFullProcessImageName`
- Any file hash/signature check on the calling process
- String comparison on executable path or name

**Attack primitive: NTFS hardlinks**
```
1. Create hardlink: exploit.exe -> run.exe (points to attacker code)
2. Execute run.exe (loads attacker code into memory)
3. Delete hardlink, recreate: run.exe -> trusted.exe
4. Open device handle — driver checks run.exe, reads trusted.exe, hash matches
```

Key constraint: Windows only allows hardlinks to files the user can write to.
Workaround: copy the trusted binary to a user-writable location first.

James Forshaw (Project Zero) references:
- Windows symlink testing tools
- Arbitrary DACL write via mount points and junctions
- Object directory symlinks for kernel object name confusion

### Shared Memory TOCTOU (Double-Fetch)

```c
// CHECK: validate field from shared memory
uint32_t idx = shared_buf->index;  // read 1
if (idx >= MAX_ENTRIES) return -EINVAL;

// USE: re-read from shared memory — VULNERABLE
memcpy(dst, &table[shared_buf->index], sizeof(entry));  // read 2, attacker changed it
```

See `prompts/vuln_patterns/double_fetch.md` for full details.

### Handle-Based TOCTOU

```c
// CHECK: validate handle type
status = ObReferenceObjectByHandle(hObject, ..., &pObject);
if (pObject->Type != ExpectedType)
    return STATUS_INVALID_PARAMETER;
ObDereferenceObject(pObject);

// ... gap where handle could be closed and recycled ...

// USE: use handle assuming it's still the same object
status = ObReferenceObjectByHandle(hObject, ..., &pObject);
// pObject may now be a completely different object type
```

### Name-Based Identity

```c
// CHECK: verify caller by executable name substring
GetProcessImageFileName(pid, path, sizeof(path));
if (strstr(path, "TrustedApp") == NULL)
    return ACCESS_DENIED;

// ASSUMPTION: only TrustedApp.exe has "TrustedApp" in its path
// REALITY: attacker creates C:\Users\Public\TrustedApp\evil.exe
```

## Example: AsIO3.sys (CVE-2025-3464) — Full Chain

**The Gate:**
- Driver calls `ZwQueryInformationProcess(ProcessImageFileNameWin32)` to get caller's EXE path
- Converts Win32 path to NT namespace
- SHA256-hashes the file at that path
- Compares against hardcoded hash of AsusCertService.exe
- Also does substring match for "AsusCertService" in path

**The Assumption:**
The file at the process image path IS the binary loaded in memory.

**The Bypass:**
1. Create hardlink `run.exe` -> `exploit.exe`, execute it
2. Pause execution (exploit waits for input)
3. Delete hardlink, recreate `run.exe` -> local copy of `AsusCertService.exe`
4. Resume, open `\\.\Asusgio3` — driver reads `AsusCertService.exe`, hash matches
5. Exploit code now has full IOCTL access to the driver

**What the researcher did differently:**
They didn't try to forge the SHA256 hash (impossible). They asked: "What does the check
*assume*?" — it assumes file path = running code. That's a filesystem-level TOCTOU.

## Assessment Checklist

1. [ ] Does the security check verify a file on disk (path, hash, signature)?
2. [ ] Can the file at that path be swapped between check and use (hardlink, symlink, rename)?
3. [ ] Does the check use substring matching on paths instead of full verified identity?
4. [ ] Does the check read from shared/user-writable memory more than once?
5. [ ] Is there a handle validated then used after a potential close/reopen window?
6. [ ] Is the check based on a *proxy* (name, path, handle number) rather than the *thing itself*?
7. [ ] Is the checked state protected by a lock during both check and use?
8. [ ] Can the attacker create filesystem objects (hardlinks, junctions) in relevant paths?

## Common Mistakes When Analyzing

- **Dismissing the check as "strong"** — SHA256 hash check IS cryptographically strong. The
  weakness isn't in the crypto, it's in what the check assumes about the filesystem.
- **Frontal assault** — trying to break the check directly instead of violating its assumptions.
- **Missing the time gap** — even a single instruction between check and use can be exploitable
  with userfaultfd, hardlinks, or racing threads.
- **Ignoring filesystem primitives** — hardlinks, symlinks, mount points, and junctions are
  standard exploitation tools on Windows and Linux.
