# CWE-287/306: Authentication Bypass

## What It Is

Authentication bypass occurs when an attacker accesses protected functionality without
providing valid credentials. This includes missing authentication checks on sensitive
endpoints, flawed credential verification logic, hardcoded credentials, and weaknesses in
session/token management. On embedded devices, auth bypass is the most common path to
pre-auth RCE.

## Code Patterns to Look For

### Decompiled C / Native Binaries

**Missing auth check on handler:**
```c
// Some handlers check auth, others don't — look for inconsistency
void handle_admin_backup(request *req) {
    // No call to check_session() or verify_auth() before sensitive action
    create_backup(req->params["filename"]);
    send_response(req, 200, "Backup created");
}
```

**Flawed string comparison:**
```c
// Timing side-channel: strcmp returns early on first mismatch
if (strcmp(provided_token, stored_token) == 0) { grant_access(); }

// Length check bypass
if (strlen(password) == 0) { deny(); }  // what about null byte in middle?

// Partial comparison
if (strncmp(cookie, "admin=", 6) == 0) { is_admin = 1; }
// Attacker sends: Cookie: admin=anything
```

**Hardcoded credentials:**
```c
if (strcmp(username, "admin") == 0 && strcmp(password, "super_secret_123") == 0)
    return AUTH_SUCCESS;
// Or backdoor accounts:
if (strcmp(username, "support") == 0)
    return AUTH_SUCCESS;  // no password check at all
```

In Ghidra/IDA, look for:
- HTTP handler dispatch tables: compare which handlers call auth functions and which don't.
- String references to "admin", "root", "password", "secret", "default", "backdoor".
- `strcmp` / `strncmp` with hardcoded second argument in auth paths.
- Functions that return 0/1 and are called before request processing (auth wrappers) -
  check if any handlers skip calling them.
- User-Agent or Referer checks used as authentication (trivially spoofable).
- Cookie parsing that trusts client-supplied role or privilege values.

### JavaScript / Node.js

```javascript
// Missing auth middleware on route
app.get('/admin/users', adminController.listUsers);  // no authMiddleware!

// JWT not verified
const payload = jwt.decode(token);  // decode != verify!
if (payload.role === 'admin') { ... }

// Loose comparison
if (req.body.password == storedHash) { ... }  // == not ===, type coercion

// Role in client-controlled JWT without server-side check
const token = jwt.sign({ userId: user.id, role: 'admin' }, secret);
// Server trusts role from token without checking DB

// Express middleware ordering — auth runs AFTER the route
app.get('/secret', handler);
app.use(authMiddleware);  // too late, /secret already matched
```

## Example Vulnerable Code

### C (CGI authentication bypass via User-Agent)

```c
// VULNERABLE: authentication bypass via User-Agent string
int check_auth(http_request *req) {
    // "Automated" tools skip auth — attacker spoofs this header
    char *ua = get_header(req, "User-Agent");
    if (ua && strstr(ua, "DEVICE-INTERNAL-AGENT")) {
        return AUTH_OK;  // bypass for "internal" requests
    }

    char *session = get_cookie(req, "session_id");
    if (!session || !validate_session(session)) {
        return AUTH_FAIL;
    }
    return AUTH_OK;
}
// Exploit: curl -H "User-Agent: DEVICE-INTERNAL-AGENT" http://target/admin/
```

### JavaScript (JWT none algorithm)

```javascript
// VULNERABLE: accepts "none" algorithm
app.use((req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        // jwt.verify with algorithms not restricted
        req.user = jwt.verify(token, secret);
        next();
    } catch (e) {
        res.status(401).send('Unauthorized');
    }
});
// Exploit: forge token with {"alg":"none"} header, empty signature
```

## Example Safe Code

### C

```c
int check_auth(http_request *req) {
    // No User-Agent bypass — all requests must authenticate
    char *session = get_cookie(req, "session_id");
    if (!session || !validate_session(session)) {
        return AUTH_FAIL;
    }
    return AUTH_OK;
}

// Use constant-time comparison for tokens
int verify_token(const char *provided, const char *stored, size_t len) {
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= provided[i] ^ stored[i];
    }
    return result == 0;
}
```

### JavaScript

```javascript
// Enforce algorithm, reject "none"
app.use((req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        req.user = jwt.verify(token, secret, { algorithms: ['HS256'] });
        next();
    } catch (e) {
        res.status(401).send('Unauthorized');
    }
});

// Auth middleware BEFORE routes
app.use('/admin', authMiddleware);
app.get('/admin/users', adminController.listUsers);
```

## Common Bypasses

| Technique | Description |
|-----------|-------------|
| Missing auth on endpoint | Some routes lack middleware — map all routes and compare |
| HTTP verb tampering | `POST /admin` blocked but `GET /admin` or `HEAD /admin` allowed |
| Path normalization | `/admin` blocked but `/Admin`, `/admin/`, `/./admin`, `/%61dmin` works |
| Hardcoded credentials | Default or backdoor accounts compiled into firmware |
| User-Agent spoofing | Auth bypass for "internal" or "automated" user agents |
| JWT "none" algorithm | Forge tokens with `alg: none` and empty signature |
| JWT key confusion | RS256 public key used as HS256 secret |
| JWT header injection | `kid` parameter used in SQL query or file path |
| Session fixation | Set session ID before auth, victim authenticates it |
| Type juggling | PHP `==` or JS `==` treats `"0" == 0 == false` |
| Parameter pollution | `?role=user&role=admin` — server takes last value |
| Race condition | Register same username as admin during account creation |
| Password reset abuse | Reset token is predictable or reusable |
| IP-based auth bypass | `X-Forwarded-For: 127.0.0.1` to appear as localhost |
| Referer/Origin check | Spoofable headers used as auth mechanism |

**Privilege escalation after auth:**
- IDOR: change `user_id=123` to `user_id=1` (admin).
- Mass assignment: POST `{ "role": "admin" }` in profile update.
- Insecure direct object reference in API endpoints.
- Session token does not encode privilege level — server looks up by ID, trusting the ID.

## Assessment Checklist

1. [ ] Do ALL sensitive endpoints/handlers have authentication checks?
2. [ ] Does the auth comparison use constant-time comparison (not strcmp)?
3. [ ] Are there hardcoded credentials, API keys, or backdoor accounts in the binary/source?
4. [ ] Does JWT verification enforce a specific algorithm (not accepting "none")?
5. [ ] Is authentication enforced consistently across HTTP methods (GET, POST, PUT, DELETE)?
6. [ ] Are path normalization variants tested (`/admin`, `/Admin/`, `/%61dmin`)?
7. [ ] Does the session/token contain the user's privilege level, or is it looked up server-side?
