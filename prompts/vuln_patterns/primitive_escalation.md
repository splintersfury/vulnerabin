# Primitive-to-Exploitation: Turning Weak Primitives into Full Chains

## What It Is

A "primitive" is a basic capability an attacker gains from a vulnerability: write one byte,
decrement a value, free an object, leak an address. Most primitives look useless in isolation.
The skill is mapping a weak primitive to a high-value kernel target where that minimal
operation achieves maximum impact.

This is **primitive-first thinking**: "I have X capability. What single change to kernel
memory would be devastating?"

## The Primitive Catalog

### Decrement-by-One

**What you have:** Atomically subtract 1 from any kernel address.

**How it arises:**
- `ObfDereferenceObject(user_addr)` — decrements refcount at `(addr - 0x30)`
- Off-by-one in loop counter or array index
- Reference count underflow

**High-value targets:**
| Target | Offset | Effect |
|--------|--------|--------|
| KTHREAD.PreviousMode | +0x232 | 1 (User) -> 0 (Kernel) = god-mode read/write via Nt{Read,Write}VirtualMemory |
| EPROCESS.Token (low byte) | +0x4B8 | Corrupt token pointer, may redirect to controlled token |
| SEP_TOKEN_PRIVILEGES.Enabled | varies | Enable a disabled privilege (SeDebugPrivilege, etc.) |

**Canonical chain (PreviousMode):**
1. Leak KTHREAD address via `NtQuerySystemInformation(SystemHandleInformationEx)`
2. Calculate PreviousMode address: `KTHREAD + 0x232`
3. Trigger decrement: `ObfDereferenceObject(PreviousMode_addr + 0x30)` — value goes 1 -> 0
4. Call `NtReadVirtualMemory` / `NtWriteVirtualMemory` on kernel addresses (no access check)
5. Walk EPROCESS list, find SYSTEM (PID 4), steal token
6. Write SYSTEM token to your EPROCESS
7. **Restore PreviousMode to 1** before spawning shell (or BSOD on CreateProcess)

**Real world:** AsIO3.sys CVE-2025-1533 — IOCTL 0xA0402450 gives arbitrary decrement via
ObfDereferenceObject, chained to NT SYSTEM via PreviousMode flip.

**Constraints:**
- Windows 11 24H2+ blocks `NtQuerySystemInformation` kernel address leaks for non-admin
- Windows 23H2+ added PREVIOUS_MODE_MISMATCH (bugcheck 0x1F9)
- The 8-byte atomic decrement affects adjacent KTHREAD fields — need to handle side effects

### Increment-by-One

**What you have:** Add 1 to any kernel address.

**How it arises:**
- `ObfReferenceObject(user_addr)` — increments refcount at `(addr - 0x30)`
- Off-by-one in the other direction

**High-value targets:**
| Target | Effect |
|--------|--------|
| KTHREAD.PreviousMode | 0 -> 1 (restore after exploit, or 1 -> 2 = crash/unexpected behavior) |
| Refcount of target object | Prevent free, keep object alive for UAF prevention |
| Boolean flag fields | Flip 0 -> 1 (enable feature, bypass check) |

### Arbitrary Free

**What you have:** Free a kernel pool allocation at any address.

**How it arises:**
- `ExFreePool(user_addr)` or `ExFreePoolWithTag(user_addr, tag)` exposed via IOCTL
- Reference count underflow leading to premature free

**Exploitation pattern:**
1. Free a target object (e.g., a KPROCESS token, a pipe attribute)
2. Reclaim the freed memory with a controlled allocation of the same size (pool spray)
3. Controlled data now overlaps the "freed" object's fields
4. Original code still holds a pointer to the object — type confusion / arbitrary read-write

**Pool spray techniques:**
- Named pipes (`NtCreateNamedPipeFile` + `NtFsControlFile` for pipe attributes)
- Registry keys with controlled value data
- `NtCreateToken` for token objects
- I/O completion ports for specific pool sizes

### Single Byte Write

**What you have:** Write one attacker-controlled byte to any kernel address.

**High-value targets:**
| Target | Byte Value | Effect |
|--------|-----------|--------|
| KTHREAD.PreviousMode | 0x00 | KernelMode access |
| EPROCESS.Protection.Level | 0x00 | Remove process protection (PPL bypass) |
| EPROCESS.SignatureLevel | 0x00 | Disable code signing enforcement for process |
| TOKEN.Privileges.Enabled (specific bit) | varies | Enable SeDebugPrivilege |
| ACL.AceCount (set to 0) | 0x00 | Empty the ACL = no access checks |

### Arbitrary Read (Info Leak)

**What you have:** Read kernel memory from arbitrary address.

**How to escalate:**
1. Read EPROCESS.Token of SYSTEM process
2. Read your own EPROCESS.Token
3. Use a write primitive to copy SYSTEM token to your process
4. Or: read sensitive data directly (crypto keys, passwords, other process memory)

**Common info leak sources:**
- Uninitialized pool memory returned to userspace
- `NtQuerySystemInformation` with various info classes
- `/proc/kallsyms` on Linux (if readable)
- Side channels (page fault timing, cache timing)

### Relative Read/Write (bounded)

**What you have:** Read or write at a controlled offset from a known object.

**Exploitation pattern:**
1. Spray objects of known layout adjacent to the vulnerable object
2. Relative OOB read/write corrupts adjacent object's fields
3. Target: function pointer, object pointer, size field, or privilege field in adjacent object

## The Decision Framework

When you find a primitive, work through this decision tree:

```
1. Can I control the ADDRESS? (arbitrary vs relative)
   |
   +-- Arbitrary address:
   |   Can I control the VALUE?
   |   +-- Yes (arbitrary write) -> Direct token theft or callback overwrite
   |   +-- No (fixed operation like dec/inc/free):
   |       -> Target PreviousMode, token, protection, or refcount
   |
   +-- Relative offset only:
       What object type is adjacent?
       -> Pool spray to control neighbor, corrupt its fields
```

```
2. How many times can I trigger it?
   +-- Once only: must be precise (PreviousMode, single flag flip)
   +-- Unlimited: can build stronger primitives iteratively
       -> Dec-by-one * N = arbitrary value write (but slow and may corrupt neighbors)
```

```
3. What info do I need?
   +-- Kernel base address -> NtQuerySystemInformation or driver info leak
   +-- KTHREAD address -> handle leak via SystemHandleInformation
   +-- EPROCESS address -> KTHREAD.ApcState.Process or handle leak
   +-- Pool address -> spray pattern + relative offset
```

## Windows Kernel Structure Quick Reference

These offsets are for Windows 11 22H2 (Build 22621). Always verify for your target build.

### KTHREAD (key fields)
| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| +0x220 | ApcState.Process | 8 | Pointer to EPROCESS |
| +0x232 | PreviousMode | 1 | 0=Kernel, 1=User |
| +0x074 | BasePriority | 1 | Adjacent to fields affected by 8-byte dec |

### EPROCESS (key fields)
| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| +0x440 | UniqueProcessId | 8 | PID |
| +0x448 | ActiveProcessLinks | 16 | Doubly-linked list of all processes |
| +0x4B8 | Token | 8 | EX_FAST_REF to SEP_TOKEN |
| +0x87A | Protection | 1 | PS_PROTECTION (PPL level) |
| +0x878 | SignatureLevel | 1 | CI signature enforcement |

### SEP_TOKEN (key fields)
| Offset | Field | Notes |
|--------|-------|-------|
| +0x040 | Privileges | TOKEN_PRIVILEGES (Present, Enabled, EnabledByDefault) |
| +0x048 | Privileges.Enabled | Which privileges are active |
| +0x058 | UserAndGroupCount | For token manipulation |

## Assessment Checklist

1. [ ] What exact primitive does this vulnerability give? (read/write/free/inc/dec, how many bytes, how many times?)
2. [ ] Can the address be controlled? (arbitrary vs relative offset)
3. [ ] What information leaks are available to target the primitive? (KASLR bypass)
4. [ ] What is the minimum kernel structure change for maximum impact? (PreviousMode = 1 byte)
5. [ ] What are the side effects of the primitive? (8-byte dec corrupts adjacent fields)
6. [ ] What Windows build is the target? (offsets change, mitigations added per build)
7. [ ] Can the system be stabilized after exploitation? (restore PreviousMode, fix refcounts)

## Common Mistakes

- **Dismissing weak primitives** — "decrement by one is useless." It's one byte away from
  god-mode kernel access.
- **Targeting complex structures first** — PreviousMode is simpler and more reliable than
  overwriting function pointers or manipulating pool metadata.
- **Forgetting cleanup** — PreviousMode must be restored before spawning a child process,
  or the system bugchecks. Refcounts must be balanced.
- **Ignoring build-specific mitigations** — Windows 23H2 added PREVIOUS_MODE_MISMATCH check.
  Windows 24H2 blocks NtQuerySystemInformation kernel address leaks for non-admin.
- **Not checking if the primitive is repeatable** — a one-shot primitive needs precise targeting;
  a repeatable one can build up to arbitrary write through iteration.
