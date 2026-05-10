# CWE-22: Path Traversal

## What It Is

Path traversal (directory traversal) occurs when an application uses user-supplied input
to construct filesystem paths without adequate validation. The attacker uses sequences like
`../` to escape the intended directory and read, write, or delete arbitrary files. On
embedded devices this typically gives access to `/etc/shadow`, config files with credentials,
private keys, and firmware.

## Code Patterns to Look For

### Decompiled C / Native Binaries

```c
// Direct path concatenation
snprintf(filepath, sizeof(filepath), "/var/www/files/%s", filename);
fp = fopen(filepath, "r");

// No realpath check
open(user_path, O_RDONLY);

// Dangerous: user controls both directory and filename
snprintf(path, PATH_MAX, "%s/%s", upload_dir, user_filename);
rename(tmpfile, path);
```

In Ghidra/IDA, look for:
- `fopen`, `open`, `stat`, `access`, `unlink`, `rename`, `mkdir` where the path argument
  traces back to HTTP parameters, form data, or protocol fields.
- `snprintf` building a path from user input without `realpath()` validation after.
- File-serving handlers: look for the request URI being appended to a document root.
- Firmware update handlers: user-supplied filename used for extraction path.
- Zip/tar extraction without path sanitization (Zip Slip).

### JavaScript / Node.js

```javascript
// Path concatenation without validation
const filePath = path.join('/uploads', req.params.filename);
fs.readFileSync(filePath);

// Express static file serving with user-controlled path
app.get('/files/:name', (req, res) => {
    res.sendFile(req.params.name, { root: './uploads' });
});

// Zip extraction without path check (Zip Slip)
entry.extractTo(path.join(destDir, entry.fileName));
```

Also check:
- `path.resolve()` vs `path.join()` — resolve is safer but still needs validation.
- Missing check that the resolved path starts with the intended base directory.
- Electron `file://` protocol handlers that serve local files.

## Example Vulnerable Code

### C (embedded web server file handler)

```c
// VULNERABLE: serves arbitrary files from disk
void serve_file(int client_sock, char *request_uri) {
    char filepath[PATH_MAX];
    // No traversal check — attacker sends GET /../../etc/shadow
    snprintf(filepath, sizeof(filepath), "/var/www/html%s", request_uri);
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        send_404(client_sock);
        return;
    }
    // ... send file contents to client ...
}
// Exploit: GET /../../../../etc/shadow HTTP/1.1
```

### JavaScript

```javascript
// VULNERABLE: download endpoint with traversal
app.get('/download', (req, res) => {
    const filename = req.query.file;
    const filePath = path.join(__dirname, 'uploads', filename);
    res.download(filePath);
});
// Exploit: GET /download?file=../../../etc/passwd
```

## Example Safe Code

### C

```c
void serve_file(int client_sock, char *request_uri) {
    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "/var/www/html%s", request_uri);

    // Resolve symlinks and normalize path
    char resolved[PATH_MAX];
    if (realpath(filepath, resolved) == NULL) {
        send_404(client_sock);
        return;
    }
    // Verify resolved path is within the document root
    if (strncmp(resolved, "/var/www/html/", 14) != 0) {
        send_403(client_sock);
        return;
    }
    int fd = open(resolved, O_RDONLY);
    // ... send file contents ...
}
```

### JavaScript

```javascript
app.get('/download', (req, res) => {
    const filename = req.query.file;
    const basePath = path.resolve(__dirname, 'uploads');
    const filePath = path.resolve(basePath, filename);

    // Ensure resolved path is within the base directory
    if (!filePath.startsWith(basePath + path.sep)) {
        return res.status(403).send('Forbidden');
    }
    res.download(filePath);
});
```

## Common Bypasses

| Technique | Payload | Notes |
|-----------|---------|-------|
| Basic traversal | `../../../etc/passwd` | Simplest form |
| URL encoding | `%2e%2e%2f` or `%2e%2e/` | Bypass naive string filter |
| Double encoding | `%252e%252e%252f` | Bypass filters that decode once |
| UTF-8 overlong | `%c0%ae%c0%ae/` | Older parsers accept overlong sequences |
| Null byte | `../../../etc/passwd%00.png` | Truncates at null in C, passes extension check |
| Backslash (Windows) | `..\..\..\windows\win.ini` | Windows accepts both `/` and `\` |
| Dot stripping bypass | `....//....//etc/passwd` | If filter removes `../` once, `....//` becomes `../` |
| Symlink | Upload a symlink pointing to `/etc/shadow` | Bypass directory prefix check |
| Path normalization | `/var/www/html/uploads/../../../etc/passwd` | Absolute path with traversal |
| Zip Slip | Zip entry with `../../malicious.sh` path | Extraction writes outside target dir |
| Double URL decode | Server decodes `%252e` to `%2e`, app decodes to `.` | Multi-layer decoding |

**File write escalation paths:**
- Write to crontab (`/var/spool/cron/root`) for code execution.
- Overwrite `.ssh/authorized_keys` for persistent access.
- Write to web root for webshell deployment.
- Overwrite init scripts or systemd units for execution on reboot.
- Replace a configuration file to inject commands (e.g., sshd_config `ForceCommand`).

## Assessment Checklist

1. [ ] Is user input concatenated into a file path without sanitization?
2. [ ] Does the code call `realpath()` and verify the result is within the intended directory?
3. [ ] Does the filter strip `../` only once (vulnerable to `....//` bypass)?
4. [ ] Are URL-encoded sequences decoded before or after the traversal check?
5. [ ] Does the application handle symlinks (does it follow them or reject them)?
6. [ ] Can the attacker write files (upload, PUT, MOVE) or only read?
7. [ ] Is there a null byte injection path (C string truncation)?
