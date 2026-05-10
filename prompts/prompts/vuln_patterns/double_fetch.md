# CWE-367: TOCTOU Race Condition / Double Fetch

## What It Is

A double-fetch (Time-of-Check to Time-of-Use) vulnerability occurs when a privileged
component reads a value from shared memory, validates it, then reads the same value again
for use. Between the two reads, a less-privileged attacker can modify the value, bypassing
the validation. This is critical in kernel drivers, hypervisors, and any code that shares
memory with an untrusted party.

## Code Patterns to Look For

### Decompiled C / Kernel Drivers

**Classic double-fetch from userspace:**
```c
// First fetch: validation
if (copy_from_user(&hdr, user_buf, sizeof(hdr)))
    return -EFAULT;
if (hdr.length > MAX_SIZE)
    return -EINVAL;

// Second fetch: use — VULNERABLE, user may have changed hdr.length
if (copy_from_user(kbuf, user_buf, hdr.length))  // re-reads from user_buf
    return -EFAULT;
```

**Shared memory / ring buffer double-fetch:**
```c
// Ring buffer header is in shared memory (e.g., virtio, VMBUS, USB)
uint32_t msg_type = ring->header->type;     // fetch 1: check
if (msg_type != EXPECTED_TYPE)
    return -EINVAL;

uint32_t length = ring->header->length;     // fetch 2: use
// Attacker changed length between the two reads
memcpy(local_buf, ring->data, length);      // overflow
```

**ProbeForRead then direct access:**
```c
// Windows kernel driver pattern
ProbeForRead(UserBuffer, Length, 1);         // validates address range
// ... attacker remaps or modifies UserBuffer ...
value = UserBuffer->field;                   // direct access, no copy
```

In Ghidra/IDA, look for:
- Two `copy_from_user` calls on the same user pointer or overlapping regions.
- `ProbeForRead`/`ProbeForWrite` followed by direct pointer dereference (not `RtlCopyMemory`).
- Ring buffer or shared memory structures where a field is read, validated, then read again.
- IOCTL handlers that read a header, validate a size field, then read the body using
  the size from the header (re-read from user memory, not from a kernel copy).
- Hypervisor handlers reading from guest-physical memory (GPA) mapped into host VA space.

### JavaScript

Double-fetch patterns are rare in pure JS but relevant in:
```javascript
// Shared memory in workers (SharedArrayBuffer)
const view = new Int32Array(sharedBuffer);
const len = Atomics.load(view, 0);    // check
if (len > MAX) throw new Error();
// Another thread modifies view[0] here
const data = new Uint8Array(sharedBuffer, 4, Atomics.load(view, 0));  // use — re-read
```

Also relevant in native Node.js addons that access shared memory or user-mapped buffers.

## Example Vulnerable Code

### Linux Kernel IOCTL Handler

```c
// VULNERABLE: double-fetch from userspace in ioctl handler
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct my_header __user *uhdr = (void __user *)arg;
    struct my_header khdr;

    // First fetch: read header to validate
    if (copy_from_user(&khdr, uhdr, sizeof(khdr)))
        return -EFAULT;

    if (khdr.data_len > MAX_DATA_LEN)
        return -EINVAL;

    char *kbuf = kmalloc(khdr.data_len, GFP_KERNEL);

    // VULNERABLE: re-reads from userspace — attacker changed data_len
    // between the first and second copy_from_user
    struct my_header khdr2;
    if (copy_from_user(&khdr2, uhdr, sizeof(khdr2)))
        return -EFAULT;

    // Uses khdr2.data_len which may now be > MAX_DATA_LEN
    if (copy_from_user(kbuf, uhdr->data, khdr2.data_len))  // OVERFLOW
        return -EFAULT;

    process_data(kbuf, khdr2.data_len);
    kfree(kbuf);
    return 0;
}
```

### Hypervisor Shared Ring Buffer

```c
// VULNERABLE: vmswitch-style double-fetch from guest-writable ring buffer
void handle_packet(struct ring_buffer *ring) {
    // Fetch 1: validate section index
    uint32_t section_idx = ring->hdr->section_idx;
    if (section_idx >= MAX_SECTIONS)
        return;

    struct section *sec = &sections[section_idx];  // validated

    // ... some processing ...

    // Fetch 2: re-read from the SAME shared memory location
    uint32_t idx = ring->hdr->section_idx;  // guest changed it!
    // OOB access with attacker-controlled index
    memcpy(local_buf, &sections[idx], sizeof(struct section));
}
```

## Example Safe Code

### Kernel IOCTL (single copy, use the copy)

```c
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct my_header __user *uhdr = (void __user *)arg;
    struct my_header khdr;

    // Single copy of the header into kernel memory
    if (copy_from_user(&khdr, uhdr, sizeof(khdr)))
        return -EFAULT;

    if (khdr.data_len > MAX_DATA_LEN)
        return -EINVAL;

    char *kbuf = kmalloc(khdr.data_len, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    // Use the KERNEL copy of data_len, and read data from a different offset
    if (copy_from_user(kbuf, uhdr->data, khdr.data_len))  // uses khdr, not uhdr
        goto fail;

    process_data(kbuf, khdr.data_len);
    kfree(kbuf);
    return 0;
fail:
    kfree(kbuf);
    return -EFAULT;
}
```

### Hypervisor (snapshot shared memory)

```c
void handle_packet(struct ring_buffer *ring) {
    // Snapshot the entire header into local (non-shared) memory
    struct ring_header local_hdr;
    memcpy(&local_hdr, ring->hdr, sizeof(local_hdr));
    barrier();  // compiler barrier to prevent re-read optimization

    if (local_hdr.section_idx >= MAX_SECTIONS)
        return;

    // All subsequent accesses use local_hdr, never ring->hdr
    memcpy(local_buf, &sections[local_hdr.section_idx], sizeof(struct section));
}
```

## Common Bypasses

| Technique | Description |
|-----------|-------------|
| Race thread | Dedicated thread flipping the shared value between valid and malicious in a tight loop |
| mmap + mprotect | Map the ioctl buffer, fork a thread that continuously writes to it |
| userfaultfd | Stall the second copy_from_user on a page fault, modify the data, then release |
| FUSE filesystem | Serve the user buffer from a FUSE mount that returns different data on each read |
| Huge page flip | Use transparent huge pages to atomically swap the contents under the kernel |
| Compiler reload | Even without explicit double copy_from_user, the compiler may reload a value from user memory if it's accessed through a pointer (use `READ_ONCE` / `ACCESS_ONCE`) |
| CAS retry loop | If the kernel uses compare-and-swap on shared memory, the attacker can force retries until winning the race |

**Race window widening techniques:**
- CPU pinning: pin the kernel thread and the racing thread to maximize contention.
- Priority manipulation: lower the kernel thread's priority.
- Cache eviction: flush the cache line to increase memory access latency.
- userfaultfd: deterministically stall the kernel at the exact point between reads.
- Signal delivery: send a signal to the process during the syscall to context-switch.

## Assessment Checklist

1. [ ] Does the code read the same value from shared/user memory more than once?
2. [ ] Is the first read used for validation and the second read used for the actual operation?
3. [ ] Is the shared memory writable by a less-privileged entity (userspace, guest VM, other process)?
4. [ ] Does the code use `copy_from_user` only once and operate on the kernel copy thereafter?
5. [ ] Are `READ_ONCE` / `ACCESS_ONCE` / volatile used for shared memory reads?
6. [ ] Is there a compiler barrier preventing the optimizer from re-reading shared memory?
7. [ ] Can the attacker use userfaultfd, FUSE, or a racing thread to control the timing?

---

# Windows-kernel multi-fetch into ExAllocatePool — the CVE-2026-3006 / WinFSP class

(Added 2026-05-09 after empirical sweep of clfs.sys, storvsp.sys, vhdmp.sys, afd.sys, cldflt.sys, tdx.sys, vkrnlintvsp.sys, acsock64.sys.)

The most prolific Windows-kernel double-fetch shape is the **multi-fetch-into-`ExAllocatePool*`** pattern: a 16/32/64-bit field is dereferenced from user-mappable memory N times in a row, with at least one of those derefs being the size argument to a pool allocator and at least one other being a bound check or copy length. **CVE-2026-3006** (WinFSP, May 2026) is the canonical recent instance.

## Decompiled-C bug shape

```c
// FETCH #1 — bound check
if (MAX_LEN < *(uint *)(buf + 0x10)) goto err;

// FETCH #2 — alloc size, INDEPENDENT re-read
p = ExAllocatePoolWithTag(NonPagedPool, *(uint *)(buf + 0x10), 'tag1');

// FETCH #3 — copy length, ANOTHER re-read
RtlCopyMemory(p, *(void **)(buf + 8), *(uint *)(buf + 0x10));
```

If `buf` is in any user-mutable region, an attacker thread on a second core that flips the byte between fetches can make FETCH #2 and FETCH #3 disagree, undersizing the alloc and overflowing the copy. Bound checks against FETCH #1 are useless because they don't constrain the later fetches.

## The five racing-source classes

For Windows kernel drivers the racing source maps to one of these. Each has a distinct exploitability profile and a different verification checklist.

| Class | Static signature in decomp | User-mutable? | Verification path |
|---|---|---|---|
| **IRP user buffer** (METHOD_NEITHER) | `Irp->UserBuffer`, `IrpSp->Parameters.DeviceIoControl.Type3InputBuffer`, derived `param_X` arrives at the function | Yes — separate-process race trivial | Build user-mode racer, `DeviceIoControl` in tight loop, mutate buffer from another thread |
| **MDL-mapped user buffer** (METHOD_IN/OUT_DIRECT) | `MmGetSystemAddressForMdlSafe(Irp->MdlAddress, ...)` / `MmMapLockedPagesSpecifyCache` returns a kernel-VA pointer; `param_X` derives from it | Yes — the MDL only locks the *pages* but the **original user mapping in the calling process is still alive**, so the user can mutate via that mapping while the kernel reads via the MDL-mapped kernel VA. The scanner's chain-walk recogniser follows simple alias hops (`uVar1 = MmGet...; param_X = (T *)uVar1;`) | As above; only `ProbeForRead` + `RtlCopyMemory` to a fresh kernel-pool allocation closes the race |
| **Cc-mapped file cache page** | `MapCacheData` / `CcMapData` / `CcPinRead` / `CcPinMappedData` returns a pointer; derived `p_VarN` flows to the multi-fetch | **Maybe** — depends on whether the file is opened with `FILE_SHARE_WRITE` by the kernel driver | Pre-flight check (below); see `clfs.sys UpdateCachedOwnerPage` FP for an example where this defense closed it |
| **Guest-shared ring buffer** (Hyper-V VMBus, virtio) | `VmbChannelPacketGet*` / `VmbusChannelGetXxx` / a struct in `local_b8` from `MmMapLockedPagesSpecifyCache` over a guest GPA | Yes — guest-controlled | Guest-side racer via VMBus ring header writes; needs Hyper-V test bench |
| **Kernel-resident** (`this`, kernel global, `DAT_*`, parameter that traces to `ExAllocatePool`) | Source assignment in the same function reads from a kernel struct | No — not user-mutable from user mode | Mark FALSE_POSITIVE without further work |

## Recognised upstream defenses — score down before you build a racer

### Defense (A) — caller-side snapshot onto kernel stack

The textbook fix. The function that discovered the user buffer copies its size + pointer fields into kernel-stack locals **once** and forwards `&local_a` to the inner function. The inner function's "multi-fetch" then reads kernel stack memory, which user threads cannot mutate from another CPU.

```c
// Caller (CClfsLogFcbPhysical::Initialize @ clfs.sys 10.0.26100.8246)
if (param_6 != NULL) {
    local_60   = *(undefined8 *)param_6;          // snapshot field 0x00
    uStack_58  = *(undefined8 *)(param_6 + 8);    // snapshot field 0x08
    local_50   = *(undefined8 *)(param_6 + 0x10); // snapshot field 0x10
}
...
CClfsBaseFilePersisted::CreateImage(this, ..., (_CLFS_FILTER_CONTEXT *)&local_60, ...);
```

How to recognise this pattern when you scan a candidate:
- Look in the **same decomp tree** (every `decomp*/functions/*.c`) for any caller of the candidate function.
- Inside each caller, look for **2+ assignments** of the form `local_<X>  = *(<type> *)param_<Y>` or `local_<X>  = *(<type> *)(param_<Y> + <off>)`, each reading a different offset of the same source param.
- Also look for `&local_<X>` being passed as the relevant argument in the call to the candidate.
- If both are present, the multi-fetch is closed; mark FALSE_POSITIVE without booking kernel-debug time.

The repo's `scripts/multifetch_scan.py` performs this recogniser automatically and reports it in the `note:` field.

### Defense (B) — value-passed-to-kernel-pool at construction time

When the suspect dereference is `*(uint *)(param_X + <off>)` and `param_X` is a kernel-allocated struct constructed somewhere in the same driver, look for:

```c
// constructor function (typically named *Allocate*, e.g. AfdAllocateEndpoint)
_Dst = ExAllocatePool*(POOL_TYPE, SIZE, 'tag');         // or AfdReuseEndpoint, ExpInterlockedPopEntrySList, ...
...
*(uint *)(_Dst + <off>) = scalar_value_from_user_buffer;   // the snapshot
```

If `_Dst` is kernel-pool and the field at `+<off>` is set once via a `scalar_value` assignment, then any later multi-fetch on `*(... )(param_X + <off>)` reads kernel pool. The user buffer that the scalar was originally derived from can be remapped/freed/rewritten — the kernel-pool snapshot is immutable.

Real-world example: `afd.sys AfdAllocateEndpoint @ AfdAllocateEndpoint.c:163` does `*(uint *)(_Dst + 0xdc) = param_6;` where `param_6` was passed in by value from `AfdCreate`'s read of the user IRP buffer. Once stored, the AFD_ENDPOINT's `+0xdc` field is race-immune. This closes `AfdDelayedAcceptListen`'s otherwise-textbook multi-fetch shape — see `engagements/afd-sys-2026-04-28/findings/multifetch-001-AfdDelayedAcceptListen.md`.

`scripts/multifetch_scan.py` performs this recogniser automatically. Note the recogniser is a **fuzzy** match — it just looks for any `*(...)(<dest> + <off>) = ...;` in the engagement after `<dest> = <KernelAllocator>(...)`. Coincidental same-offset matches between unrelated kernel structs (e.g. IRP+0x10 vs MyStruct+0x10) can produce false defenses. The composable confidence model demotes-by-1 per fired recogniser rather than zeroing out, so a real candidate with one coincidental constructor match still appears at conf ≥ 1 and won't be hidden by the default `--min-confidence 2` filter unless multiple defenses agree.

### Defense (C) — file-share-exclusivity at the FS layer

When the racing source is a Cc-mapped file cache page, the file system driver typically opens its private metadata files with `FILE_SHARE_NONE`. **A second user-mode process cannot acquire a writable handle while the kernel driver is operating**, which means the cache pages, although coherent in theory, have no concurrent writer in practice.

Examples observed:
- `clfs.sys` `.blf` and `.bin` containers — `FILE_SHARE_NONE`.
- `eventlog` `.evtx` — same.
- Registry hives (`SYSTEM`, `SOFTWARE`, ...) — same.
- NTFS metadata files (`$Extend\$UsnJrnl`, `$Extend\$Quota`, etc.) — same.

This defense is **not detectable from the decomp alone** — you have to test the live file path. The 5-second pre-flight check below will save you from a half-day of futile kernel-debug repro.

### Composable confidence model (how the scanner ranks candidates)

```
base confidence by racing-source class:
  irp_user_buffer            → 3
  CcMapData_or_CcPinRead     → 2
  function_parameter         → 2
  unclassified               → 2
  kernel_object_field/global → 0  (decisive)

each defense detected demotes by 1 (floor 0):
  caller-snapshot (Defense A)
  constructor-store (Defense B)

default --min-confidence threshold is 2.
```

So:
- IRP user buffer with no defense fired → conf 3, must investigate.
- CcMap source with no defense fired → conf 2, run pre-flight FILE_SHARE check.
- Parameter source with constructor-store match → conf 1, likely FP but visible if you drop the threshold.
- Either kernel-resident OR (caller-snapshot AND constructor-store) → conf 0, hidden in default sweep.

This way coincidental same-offset matches don't silently hide real candidates — they push them down one level.

### Pre-flight verification (run before booking any kernel-debug repro)

For any candidate that the scanner rates **conf 2** with `racing source: CcMapData_or_CcPinRead`:

1. On the target VM, find the file path that backs the Cc-mapped buffer. Often this is the file the user is accessing (the .blf, the .evtx, the hive). When in doubt, run ProcMon while triggering the operation; look for `CreateFile` / `CreateSection` events from the suspect kernel driver.

2. With the kernel driver actively holding the file (i.e. while a long-running operation is in progress), from a low-priv user shell try:

```powershell
[System.IO.File]::Open('C:\path\to\file.blf', 'Open', 'ReadWrite', 'None')
```

3. If this throws `IOException: ... is being used by another process` (Win32 `ERROR_SHARING_VIOLATION` = 32), the kernel driver is holding it `FILE_SHARE_NONE`. The race is structurally impossible from a separate user process. **Mark FALSE_POSITIVE.**

4. If this succeeds, you have a writable handle on the file the kernel is reading via `CcMapData`. The race is exploitable in principle; build a racer.

For candidates that the scanner rates **conf 3** with `racing source: irp_user_buffer`, skip the pre-flight and build the racer directly — this is the CVE-2026-3006 class and the user owns the buffer by definition.

## Building a Windows-kernel racer

A minimal cross-compiled mingw racer looks like:

```c
/* clfs_racer.c — see engagements/clfs-sys-2026-04-28/_serve/clfs_racer.c */
HANDLE hLog = pCreateLogFile(L"log:" L"C:\\poc\\testlog.blf", ...);
pAddLogContainer(hLog, &cSize, contPath, NULL);
pCreateLogMarshallingArea(hLog, ..., &pMarshal);

CreateThread(NULL, 0, thread_api, &ctx, 0, NULL);    // hammer ReserveAndAppendLog/FreeReservedLog
CreateThread(NULL, 0, thread_race, contPath, 0, NULL); // race-write +6 of every 0x200-aligned chunk
SetThreadAffinityMask(tApi, 1ULL << 0);              // pin to different cores
SetThreadAffinityMask(tRace, 1ULL << 1);
```

Build: `x86_64-w64-mingw32-gcc -O2 -Wall -municode -o clfs_racer.exe clfs_racer.c -lkernel32`

Push to a kernel-debug VM (see `lab/SOP.md` for `vb-driver` setup), run for 60–300 seconds, watch for BSOD with bugcheck:
- `BAD_POOL_HEADER (0x19)` — pool overflow corruption
- `PFN_LIST_CORRUPT (0x4E)` — page-frame DB corruption from OOB write
- `KERNEL_SECURITY_CHECK_FAILURE (0x139)` — stack/heap corruption check fired
- `DRIVER_VERIFIER_DETECTED_VIOLATION (0xC4)` — Verifier with Special Pool caught it

Enable Driver Verifier with Special Pool on the suspect driver to make even tiny overflows fault immediately:

```cmd
verifier /standard /driver suspect.sys
verifier /flags 0x9bb /driver suspect.sys     # Special Pool + I/O Verification + Pool Tracking
shutdown /r /t 0
```

## Anchor CVEs / public references

- **CVE-2026-3006** — WinFSP (`winfsp.sys`), May 2026. Multi-fetch of size in `ExAllocatePool`, exploitable from Low Integrity. Maintainer Bill Zissimopoulos issued swift fix.
- **CVE-2024-21338** — `appid.sys` (AppLocker). IOCTL handler re-read size after `MmGetSystemAddressForMdlSafe`. Wormable kernel LPE.
- **CVE-2023-21768** — `afd.sys`. WinSock kernel driver — multi-fetch leading to type-confusion / arbitrary write.
- CLFS family: **CVE-2022-37969**, **CVE-2023-23376**, **CVE-2023-28252**, **CVE-2024-49138**, **CVE-2026-32070**, **CVE-2026-20820** — recurring CLFS log parser bugs (mostly logical, not multi-fetch — see `findings/004-UpdateCachedOwnerPage-cache-race-multifetch.md` for an FP that demonstrates why the share-exclusivity defense closes these).

## Tooling

- `scripts/multifetch_scan.py` — production scanner. Runs against an engagement, a directory, or a single file. Confidence-ranks candidates 0..3 with the racing-source classifier (incl. MDL chain-walk) and the three defense recognisers (caller-snapshot, constructor-store, kernel-resident hint) built in. JSON output via `--output`.
- `tests/test_multifetch_scan.py` — 33 tests including 5 integration anchors against real engagements. Run before/after edits to the scanner: `cd ~/vulnerabin && python3 -m pytest tests/test_multifetch_scan.py -v`.
- `engagements/clfs-sys-2026-04-28/_serve/clfs_racer.c` — reference racer for the CLFS-via-CcMapData flavor (FP example).
- Memory pointer: `reference_kernel_double_fetch_alloc_pattern.md` in your auto-memory tree.

## Common analyst trap — value vs. reference

When walking callers to determine if a multi-fetch is exploitable, the most common mistake (including by Explore agents — see auto-memory `feedback_value_vs_reference_in_caller_walks.md`) is conflating "the user buffer is never deep-copied" with "the user can race the value". They are different:

- If the caller passes `&user_struct` to the inner function and the user mapping stays alive, the inner's multi-fetch IS exploitable.
- If the caller reads `*(uint *)(user_buf + N)` once and passes that *value* (a uint) into the inner function as a parameter, the value was captured at the call site — it's already a deep-copy. The inner's multi-fetch reads its own kernel-stack parameter or a kernel-pool struct field, not the user buffer.

The textbook example is `afd.sys AfdAllocateEndpoint @ AfdAllocateEndpoint.c:163`:

```c
*(uint *)(_Dst + 0xdc) = param_6;     // param_6 was a `uint` value, not a pointer
```

The user IRP buffer that originally provided this `uint` can be remapped, freed, or rewritten — the AFD_ENDPOINT's `+0xdc` field is now a kernel-pool integer. Subsequent reads of `*(uint *)(endpoint + 0xdc)` in `AfdDelayedAcceptListen` are race-immune. This is exactly the **constructor-store defense** that the scanner detects automatically — see Defense (B) above.
