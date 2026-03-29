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
