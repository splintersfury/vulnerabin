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

## Analysis Steps (Step-by-Step Reasoning)

For each step below, write out your reasoning BEFORE stating your conclusion. Do not jump to a verdict. Explain what you observe, what it means, and what remains uncertain. This step-by-step approach reduces false positives and forces you to surface assumptions.

1. **Read the file** carefully, line by line. State what the file does in plain language before looking for vulnerabilities.

2. **Identify sources** — Does this file receive external input?
   - IPC messages from renderer?
   - Custom protocol URLs?
   - Network responses?
   - File contents?
   - DOM input in renderer?
   - **Reasoning checkpoint**: State which inputs you believe are attacker-controlled and WHY. If the input comes from another internal module, trace back to the original external source or mark as UNKNOWN.

3. **Identify sinks** — Does this file perform dangerous operations?
   - Command execution (child_process)?
   - Code evaluation (eval, Function)?
   - shell.openExternal with user data?
   - innerHTML/DOM manipulation?
   - File system writes?
   - SQL queries?
   - **Reasoning checkpoint**: For each sink, explain what makes it dangerous in this specific context. shell.openExternal with a hardcoded https:// URL is not a finding.

4. **Check sanitization** — Are inputs validated before reaching sinks?
   - Type checking?
   - DOMPurify or similar?
   - Path normalization + prefix check?
   - URL protocol validation?
   - **Reasoning checkpoint**: State whether sanitization is PRESENT, ABSENT, or UNKNOWN (code not visible in this file). Do not assume absent means vulnerable.

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

Your output MUST conform to `taxonomy/schemas/triage_output.json`. The `reasoning` field is MANDATORY. Write your step-by-step reasoning there, not just the conclusion. If you skip reasoning, the output is invalid.

```json
{
  "target": "path/to/file.js",
  "rating": 4,
  "label": "SINK",
  "reasoning": "This file is the main process IPC handler. On line 42, ipcMain.handle('open-link') receives a URL from the renderer process. The renderer is loaded from a remote URL (line 15: mainWindow.loadURL), meaning a compromised or XSS'd renderer can send arbitrary IPC messages. The received URL is passed directly to shell.openExternal on line 88 with no protocol validation. This allows the renderer to open arbitrary URLs including file:// and custom protocol handlers. Sanitization status: ABSENT. No URL validation exists between the IPC handler and the shell.openExternal call. contextIsolation is true (line 8), but this does not prevent IPC messages from the renderer.",
  "sources_found": [
    {"pattern": "ipcMain.handle", "line_approx": 42, "channel": "open-link", "attacker_control": "full"}
  ],
  "sinks_found": [
    {"pattern": "shell.openExternal", "line_approx": 88, "cwe": "CWE-78"}
  ],
  "sanitizers_found": [],
  "misconfigs_found": [],
  "chains": [
    {
      "source": "ipcMain.handle('open-link', ...)",
      "sink": "shell.openExternal(url)",
      "sanitized": false,
      "flow": "renderer IPC message -> ipcMain.handle callback (line 42) -> url variable -> shell.openExternal(url) (line 88)",
      "notes": "URL from renderer passed directly to shell.openExternal without protocol validation"
    }
  ],
  "notes": "Free-text observations about this file's security posture"
}
```
