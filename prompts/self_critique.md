# Self-Critique Prompt

You just identified a potential vulnerability. Now play devil's advocate and challenge your own finding.

## Your Finding
{{finding}}

## Challenge Each Assumption

1. **Upstream sanitization**: Could the "attacker-controlled" input be sanitized in code you haven't fully analyzed? Check: are there middleware, wrappers, or utility functions that process this input before it reaches the vulnerable path?

2. **Dead code**: Is the vulnerable code path actually reachable? Check: is the function exported? Is it registered as a handler? Could it be behind a feature flag or disabled in production builds?

3. **Platform mitigations**: Are there platform-level defenses that prevent exploitation?
   - Electron: contextIsolation, sandbox, CSP
   - OS: ASLR, DEP, code signing, SIP (macOS)
   - Network: HTTPS-only, certificate pinning

4. **Runtime checks**: Could there be runtime validation not visible in static analysis? (e.g., schema validation loaded from config, database-driven allowlists)

5. **Accepted behavior**: Is this actually "working as intended"? Some things that look dangerous are expected:
   - shell.openExternal for verified https:// URLs
   - eval() in developer tools or REPL contexts
   - innerHTML with content from trusted same-origin sources
   - File writes to app-controlled directories only

6. **Severity inflation**: Would the severity be lower than initially assessed?
   - Does the attacker need significant preconditions? (local access, MITM position, social engineering)
   - Is the impact limited? (DoS only, no data exfil, no code exec)
   - Is the affected user population small?

7. **Prior art**: Has this pattern been reported and triaged before? Would the program mark it as duplicate, informational, or won't-fix?

## After Self-Critique

Adjust your assessment:
- **Confidence**: Raise or lower based on what you found
- **Severity**: Adjust CVSS if mitigations reduce impact
- **Verdict**: Change from CONFIRMED to LIKELY or UNCERTAIN if critique reveals gaps
- **What would change your mind**: State what evidence would definitively confirm or refute the finding
