# CWE-134: Format String Vulnerability

## What It Is

A format string vulnerability occurs when an attacker controls the format argument to a
printf-family function. The attacker uses format specifiers like `%x` to read stack memory,
`%s` to read arbitrary strings, and `%n` to write arbitrary values to memory. This can
escalate from information disclosure to full arbitrary code execution.

## Code Patterns to Look For

### Decompiled C / Native Binaries

**Vulnerable patterns (user input IS the format string):**
```c
printf(user_input);                    // direct format string
fprintf(stderr, user_input);           // same with file stream
syslog(LOG_ERR, user_input);          // syslog is a printf variant
snprintf(buf, sizeof(buf), user_input); // snprintf is equally vulnerable
dprintf(fd, user_input);              // write to fd
```

**Safe patterns (user input is an argument, not the format):**
```c
printf("%s", user_input);    // safe — user_input cannot inject specifiers
syslog(LOG_ERR, "%s", msg);  // safe
```

In Ghidra/IDA, look for:
- Calls to `printf`, `sprintf`, `snprintf`, `fprintf`, `syslog`, `err`, `warn`, `warnx`
  where the format argument comes from a buffer that traces back to user input.
- Functions that receive a `char *msg` parameter and pass it directly to `printf(msg)`.
- Logging wrappers that forward to vfprintf/vsyslog without a fixed format.
- Error-handling paths that log raw HTTP request data, filenames, or usernames.

### JavaScript

Format strings are uncommon in JS, but relevant in:
```javascript
// Node.js util.format — no %n, but can leak values
util.format(userInput, ...args);
// Console with user-controlled first arg
console.log(userInput);  // %s, %d, %o can leak object internals
// sprintf-js / node-sprintf — if available, may have %n
sprintf(userInput, args);
```

The bigger risk in JS is template literal injection:
```javascript
eval(`console.log("${userInput}")`);  // code injection, not format string
```

## Example Vulnerable Code

### C (logging in a network daemon)

```c
// VULNERABLE: error message logged with user-controlled format string
void log_failed_login(char *username) {
    char msg[256];
    snprintf(msg, sizeof(msg), "Failed login: %s", username);
    // msg now contains user-controlled content, used AS the format string
    syslog(LOG_WARNING, msg);  // VULN: if username = "%x%x%x%n"
}
// Exploit: username = "AAAA%08x.%08x.%08x.%08x.%n"
```

### CGI binary

```c
void handle_error(char *page_name) {
    char buf[512];
    snprintf(buf, sizeof(buf), "Error: page '%s' not found", page_name);
    printf(buf);  // VULN: if page_name contains format specifiers
}
```

## Example Safe Code

```c
void log_failed_login(char *username) {
    // Pass user input as an argument, never as the format string
    syslog(LOG_WARNING, "Failed login: %s", username);
}

void handle_error(char *page_name) {
    // Always use a literal format string
    printf("Error: page '%s' not found", page_name);
}
```

## Common Bypasses

| Technique | Payload | Purpose |
|-----------|---------|---------|
| Stack leak | `%08x.%08x.%08x.%08x` | Dump stack values (info leak) |
| Arbitrary read | `%s` with address on stack | Dereference pointer, read string |
| Positional read | `%7$s` | Read the 7th argument as a string pointer |
| Arbitrary write | `%n` | Write count of chars printed so far to address |
| Positional write | `%7$n` | Write to address at 7th position |
| Short write | `%hn` | Write 2 bytes (easier to control value) |
| Byte write | `%hhn` | Write 1 byte (most precise) |
| Width padding | `%65535x%7$hn` | Pad output to control written value |
| GOT overwrite | Write to GOT entry | Redirect next library call to shellcode |
| __malloc_hook | Overwrite libc hook | Triggered on next malloc/free |
| .dtors / .fini_array | Overwrite destructor | Executes on program exit |

**Exploitation steps for arbitrary code execution:**
1. Leak stack values to find the offset where your input appears (`%p` * N).
2. Identify the positional parameter N where your input starts.
3. Place a target address (GOT entry of a called function) in your input.
4. Use `%Xc%N$hn` to write a 2-byte value to that address.
5. Repeat for the upper 2 bytes (or use `%hhn` for byte-at-a-time).
6. Overwrite the GOT entry to point to your shellcode or a one-gadget.

**Defeating mitigations:**
- RELRO (full): GOT is read-only. Target `__malloc_hook`, `__free_hook` (glibc < 2.34),
  `.fini_array`, or return addresses instead.
- ASLR: Leak a libc address first using `%p` or `%s`, then calculate offsets.
- FORTIFY_SOURCE: Blocks `%n` in format strings loaded from writable memory (bypass: some
  implementations don't cover all printf variants like syslog).

## Assessment Checklist

1. [ ] Is user-controlled data passed as the format string argument (first arg) to any printf-family function?
2. [ ] Are there logging/error-handling wrappers that forward user data as a format string?
3. [ ] Can the attacker reach the vulnerable code path (is it in error handling, debug mode, or normal flow)?
4. [ ] Does `%x` or `%p` in the input produce hex values in the output (confirms vulnerability)?
5. [ ] Is `%n` enabled (not blocked by FORTIFY_SOURCE)?
6. [ ] Is the binary compiled with Full RELRO (GOT read-only)?
7. [ ] Can the attacker use positional parameters (`%N$x`) to target specific stack offsets?
