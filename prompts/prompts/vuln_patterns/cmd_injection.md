# CWE-78: OS Command Injection

## What It Is

OS command injection occurs when an application passes unsanitized user input into a
system shell command. The attacker breaks out of the intended command context and executes
arbitrary OS commands with the privileges of the running process. In embedded devices and
appliances this almost always means root.

## Code Patterns to Look For

### Decompiled C / Native Binaries

```
system(buf);              // buf contains any user-derived data
popen(cmd, "r");          // cmd built via sprintf/snprintf/strcat
execl("/bin/sh", "sh", "-c", user_str, NULL);
snprintf(cmd, sizeof(cmd), "ping -c 1 %s", ip_param);  // no quoting
```

Key indicators in Ghidra/IDA decompilation:
- Call to `system`, `popen`, `execve`, `execl`, `execlp` where the argument
  traces back to `recv`, `read`, `getenv`, CGI param parsing, or HTTP header fields.
- `sprintf` or `snprintf` that concatenates user input into a string later passed to `system`.
- Shell metacharacters not stripped before use: `;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `\n`.

### JavaScript / Node.js

```javascript
const { exec, execSync } = require('child_process');
exec('nslookup ' + userInput);           // direct concat
execSync(`ping -c 1 ${req.query.host}`); // template literal
child_process.spawn('/bin/sh', ['-c', cmd]); // shell: true equivalent
```

Also check:
- `shell: true` option in `spawn()` / `execFile()`.
- Electron apps calling `shell.openExternal(url)` with attacker-controlled URL.
- Any wrapper that eventually calls `child_process` functions.

## Example Vulnerable Code

### C (CGI handler on embedded device)

```c
void handle_diagnostics(char *ip) {
    char cmd[256];
    // VULNERABLE: ip comes from HTTP POST parameter, no sanitization
    snprintf(cmd, sizeof(cmd), "ping -c 3 %s 2>&1", ip);
    FILE *fp = popen(cmd, "r");
    char result[4096];
    fread(result, 1, sizeof(result), fp);
    pclose(fp);
    printf("%s", result);
}
// Exploit: ip = "127.0.0.1; cat /etc/shadow"
```

### JavaScript

```javascript
app.get('/lookup', (req, res) => {
    // VULNERABLE: hostname spliced directly into shell command
    exec('nslookup ' + req.query.host, (err, stdout) => {
        res.send(stdout);
    });
});
// Exploit: host=google.com;id
```

## Example Safe Code

### C

```c
void handle_diagnostics(char *ip) {
    // Validate: IPv4 addresses only
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        printf("Invalid IP address");
        return;
    }
    // Use execve with argument array — no shell interpretation
    char *args[] = { "ping", "-c", "3", ip, NULL };
    // ... fork + execve(args[0], args, environ) ...
}
```

### JavaScript

```javascript
const { execFile } = require('child_process');
app.get('/lookup', (req, res) => {
    const host = req.query.host;
    if (!/^[a-zA-Z0-9.\-]+$/.test(host)) {
        return res.status(400).send('Invalid hostname');
    }
    // execFile does NOT invoke a shell
    execFile('nslookup', [host], (err, stdout) => {
        res.send(stdout);
    });
});
```

## Common Bypasses

| Technique | Payload Example | Notes |
|-----------|----------------|-------|
| Semicolon | `; id` | Most common separator |
| Pipe | `\| id` | Pipes stdout to next command |
| Ampersand | `& id` or `&& id` | Background or conditional exec |
| Backtick | `` `id` `` | Subshell expansion |
| Dollar-paren | `$(id)` | POSIX subshell expansion |
| Newline | `%0aid` | URL-encoded newline |
| Null byte | `%00` | Truncates C strings, bypasses extension checks |
| Tab/IFS | `${IFS}` | Replaces spaces when spaces are filtered |
| Brace expansion | `{cat,/etc/passwd}` | Bash brace expansion avoids spaces |
| Encoded chars | `%3b` (`;`), `%7c` (`\|`) | Bypass naive input filters |
| Wildcard | `/???/??t /???/??????` | `/bin/cat /etc/passwd` via globs |

**Filter bypass strategies:**
- If `;` is blocked, try `\n`, `\|`, `&&`, or `` ` ``.
- If spaces are blocked, use `${IFS}`, `$IFS`, `{cmd,arg}`, or `<` redirection.
- If keywords like `cat` are blocked, use `c'a't`, `c\at`, `/bin/c?t`, or `base64 -d`.
- Second-order: inject into a config file, crontab, or database field that is later
  evaluated by a shell script.

## Assessment Checklist

1. [ ] Does user input reach `system()`, `popen()`, `exec()`, or `child_process.exec()`?
2. [ ] Is the input concatenated into a command string (sprintf, snprintf, template literal, string +)?
3. [ ] Is a shell invoked (`/bin/sh -c`, `shell: true`, `cmd.exe /c`)?
4. [ ] Does input validation use a denylist instead of a strict allowlist (regex whitelist)?
5. [ ] Can the attacker inject shell metacharacters (`;`, `|`, `` ` ``, `$()`, `\n`)?
6. [ ] Does the process run as root or a privileged user?
7. [ ] Is there a second-order path where injected data is stored and later executed by a cron job, init script, or config reload?
