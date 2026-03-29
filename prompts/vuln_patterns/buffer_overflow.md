# CWE-120/121/122: Buffer Overflow

## What It Is

A buffer overflow occurs when data is written beyond the bounds of an allocated memory
region. Stack-based overflows (CWE-121) overwrite return addresses and saved registers.
Heap-based overflows (CWE-122) corrupt adjacent heap metadata or objects. Both lead to
arbitrary code execution, denial of service, or information disclosure.

## Code Patterns to Look For

### Decompiled C / Native Binaries

**Stack overflow indicators:**
```c
char buf[64];
strcpy(buf, user_input);           // no length check
sprintf(buf, "Hello %s", name);    // unbounded format
gets(buf);                         // never safe, ever
recv(sock, buf, 1024, 0);         // buf is smaller than 1024
```

**Heap overflow indicators:**
```c
char *p = malloc(len);
memcpy(p, src, attacker_controlled_len);  // len != attacker_controlled_len
realloc() without updating size tracking
```

**Integer overflow in size calculation:**
```c
size_t total = count * element_size;  // wraps to small value on overflow
char *buf = malloc(total);            // tiny allocation
memcpy(buf, src, count * element_size); // copies way more than allocated
```

**Off-by-one:**
```c
char buf[256];
for (int i = 0; i <= 256; i++)  // should be < 256
    buf[i] = src[i];
// Or:
strncpy(buf, src, sizeof(buf));  // no null terminator if src >= 256
```

In Ghidra/IDA, look for:
- Local variables sized as `char [N]` followed by `strcpy`/`sprintf`/`memcpy` with no bounds.
- Functions that take a length parameter from the network and pass it to `memcpy`/`memmove`.
- Arithmetic on `uint32_t` size values before `malloc` (integer wrap).
- `alloca()` with attacker-controlled size (stack exhaustion / overflow).

### JavaScript

Buffer overflows in native addons or Node.js `Buffer` misuse:
```javascript
Buffer.allocUnsafe(size);          // uninitialized memory leak
buf.write(data, offset, length);   // offset+length > buf.length
buf.copy(target, targetStart);     // no bounds validation
// Native addon: napi_get_buffer_info then memcpy without checking
```

Also relevant in WebAssembly and Emscripten-compiled modules where C buffer
overflow patterns survive in the compiled WASM linear memory.

## Example Vulnerable Code

### Stack Buffer Overflow

```c
// VULNERABLE: classic stack-based buffer overflow in HTTP header parsing
void parse_header(int sock) {
    char header[128];
    char value[128];
    char line[512];

    recv(sock, line, sizeof(line), 0);
    // No length check — if value portion > 128 bytes, smashes the stack
    sscanf(line, "%[^:]: %s", header, value);
    process_header(header, value);
}
```

### Integer Overflow Leading to Heap Overflow

```c
// VULNERABLE: integer overflow in image parser
void process_image(uint16_t width, uint16_t height, uint8_t *pixels) {
    // width=65535, height=65535 → total wraps to small value (32-bit)
    uint32_t total = (uint32_t)width * height * 4;
    uint8_t *buf = malloc(total);      // allocates tiny buffer
    memcpy(buf, pixels, width * height * 4);  // copies 4GB into tiny buffer
}
```

## Example Safe Code

```c
void parse_header(int sock) {
    char line[512];
    ssize_t n = recv(sock, line, sizeof(line) - 1, 0);
    if (n <= 0) return;
    line[n] = '\0';

    char header[128];
    char value[128];
    // Use width specifiers to prevent overflow
    if (sscanf(line, "%127[^:]: %127s", header, value) != 2) {
        return;  // malformed
    }
    process_header(header, value);
}

void process_image(uint32_t width, uint32_t height, uint8_t *pixels) {
    // Check for integer overflow before allocation
    if (width > 0 && height > SIZE_MAX / width / 4) {
        return;  // overflow
    }
    size_t total = (size_t)width * height * 4;
    uint8_t *buf = malloc(total);
    if (!buf) return;
    memcpy(buf, pixels, total);  // same variable for alloc and copy
}
```

## Common Bypasses

| Technique | Description |
|-----------|-------------|
| NOP sled | Large NOP region before shellcode to increase hit probability |
| ROP chain | Chain existing code gadgets to bypass NX/DEP |
| Partial overwrite | Overwrite only low bytes of pointer to redirect within same page |
| Off-by-one null | Overwrite frame pointer LSB to pivot stack |
| Heap grooming | Arrange heap layout so overflow corrupts a specific adjacent object |
| Integer wrap | Use multiplication overflow to get a small malloc, large memcpy |
| Sign confusion | Negative length cast to huge unsigned value |
| Stack pivot | Overwrite saved frame pointer to redirect to attacker-controlled memory |
| Canary leak | Use a format string or info leak to read the stack canary first |
| Use-after-free chain | Overflow to corrupt a free list pointer, get arbitrary write via next malloc |

**Modern mitigations and their limits:**
- ASLR: defeated by info leak (format string, partial overwrite, side channel).
- Stack canaries: defeated by canary leak or by overwriting only the return address via precise offset.
- FORTIFY_SOURCE: only protects when the compiler can determine buffer sizes at compile time.
- Safe unlinking (glibc): bypass via House of Force, House of Spirit, tcache poisoning.

## Assessment Checklist

1. [ ] Does `strcpy`, `sprintf`, `gets`, or `strcat` operate on a fixed-size buffer with attacker-controlled input?
2. [ ] Does `memcpy`/`memmove` use a length value derived from attacker input without validation?
3. [ ] Is there an integer overflow in a size calculation before `malloc`/`calloc`?
4. [ ] Are array indices validated against the actual buffer size (not a larger constant)?
5. [ ] Does `strncpy`/`snprintf` guarantee null termination (check the `n` value)?
6. [ ] Does the binary have NX, ASLR, stack canaries, and RELRO enabled (`checksec`)?
7. [ ] Is there an adjacent info leak (format string, error message) that defeats ASLR or canaries?
