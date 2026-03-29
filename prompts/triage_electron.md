# Electron File Triage Prompt

You are analyzing a single file from an Electron application for security vulnerabilities.

## Context
- **Application**: {{app_name}} v{{version}}
- **File**: {{file_path}}
- **Role**: {{role}} (main / preload / renderer / utility)
- **Bug bounty scope**: {{scope_summary}}

## Taxonomy Reference
Load and reference these files for pattern matching:
- `taxonomy/electron/sources.json` — where attacker input enters
- `taxonomy/electron/sinks.json` — dangerous operations by CWE
- `taxonomy/electron/sanitizers.json` — what breaks taint chains
- `taxonomy/electron/misconfigs.json` — dangerous BrowserWindow settings

## Analysis Steps

1. **Read the file** carefully, line by line.

2. **Identify sources** — Does this file receive external input?
   - IPC messages from renderer?
   - Custom protocol URLs?
   - Network responses?
   - File contents?
   - DOM input in renderer?

3. **Identify sinks** — Does this file perform dangerous operations?
   - Command execution (child_process)?
   - Code evaluation (eval, Function)?
   - shell.openExternal with user data?
   - innerHTML/DOM manipulation?
   - File system writes?
   - SQL queries?

4. **Check sanitization** — Are inputs validated before reaching sinks?
   - Type checking?
   - DOMPurify or similar?
   - Path normalization + prefix check?
   - URL protocol validation?

5. **Check configuration** — BrowserWindow security settings:
   - nodeIntegration: false?
   - contextIsolation: true?
   - sandbox: true?
   - webSecurity: true?

6. **Rate exploitability** (1-5):
   - **5**: Source AND sink in same file, no sanitization, reachable from external input
   - **4**: Source or sink present with clear data flow to/from other files
   - **3**: Dangerous patterns present but sanitization may exist
   - **2**: Minor concerns, unlikely exploitable in practice
   - **1**: No security-relevant patterns found

7. **Label the file**:
   - **SOURCE**: Receives attacker-controlled input
   - **SINK**: Performs dangerous operations
   - **PASSTHROUGH**: Passes data between source and sink (import/export bridge)
   - **SANITIZER**: Validates or cleans input
   - **IRRELEVANT**: No security relevance

## Output Format

```json
{
  "file": "path/to/file.js",
  "role": "main|preload|renderer|utility",
  "rating": 4,
  "label": "SINK",
  "sources_found": [
    {"pattern": "ipcMain.handle", "line": 42, "channel": "open-link"}
  ],
  "sinks_found": [
    {"pattern": "shell.openExternal", "line": 88, "cwe": "CWE-78"}
  ],
  "sanitizers_found": [],
  "misconfigs_found": [],
  "chains": [
    {
      "source": "ipcMain.handle('open-link', ...)",
      "sink": "shell.openExternal(url)",
      "sanitized": false,
      "notes": "URL from renderer passed directly to shell.openExternal without protocol validation"
    }
  ],
  "notes": "Free-text observations about this file's security posture"
}
```
