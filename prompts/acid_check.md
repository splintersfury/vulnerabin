# ACID Validation Framework

You are performing ACID validation on a potential vulnerability finding. Every finding must pass this check before being reported.

## The Finding
{{finding_summary}}

## ACID Assessment

### A — Attacker-Controlled
Is the input genuinely controlled by an external attacker?

Questions to answer with evidence:
- What is the exact input source? (IPC message? URL parameter? File content? Network response?)
- Can an attacker realistically deliver this input? (Does it require physical access? Auth? Social engineering?)
- What is the attacker's control over the input? (Full control? Partial? Constrained by format?)
- Are there authentication or authorization checks before the input reaches this code?

Evidence required: Show the code path from external input to the vulnerable code.

### C — Chain-Complete
Does tainted data flow from source to sink without being neutralized?

Questions to answer with evidence:
- Trace every transformation the data undergoes between source and sink
- Does any intermediate function sanitize, validate, or escape the input?
- Are there type coercions that would reject malicious input? (e.g., parseInt on a string meant for command injection)
- Does the data pass through a serialization/deserialization boundary that strips dangerous content?
- Could the data be truncated or modified in transit?

Evidence required: Show the data flow line-by-line from source to sink, noting each transformation.

### I — Impact
What is the concrete security impact if this vulnerability is exploited?

Questions to answer:
- What can the attacker achieve? (RCE, data exfil, privesc, DoS, info disclosure?)
- What is the blast radius? (Single user? All users? Server-side?)
- Does the vulnerability chain with other findings to increase impact?
- What data or systems are exposed?
- CVSS 3.1 assessment: Attack Vector / Attack Complexity / Privileges Required / User Interaction / Scope / CIA Impact

### D — Defenses
What existing defenses must an attacker bypass?

Questions to answer:
- Content Security Policy (CSP) — does it block inline scripts, eval?
- Context isolation — is it enabled? Does it actually prevent the attack?
- Sandbox — is the renderer sandboxed?
- Input validation — are there checks we might have missed?
- Rate limiting, WAF, or other network defenses?
- OS-level mitigations (ASLR, DEP, code signing)?

## Self-Critique (mandatory)

Before finalizing, challenge your own finding:
1. Could the input be sanitized upstream in code you haven't analyzed?
2. Is there a configuration or runtime check that disables this code path?
3. Could this be a known, accepted behavior rather than a vulnerability?
4. Are you making assumptions about the attacker's capabilities?
5. Would a defender argue this is "by design"?

## Verdict

- **CONFIRMED**: All ACID criteria satisfied with code evidence. High confidence.
- **LIKELY**: ACID mostly satisfied. Some assumptions about code not fully analyzed.
- **UNCERTAIN**: Plausible but missing evidence for one or more ACID criteria.
- **FALSE_POSITIVE**: One or more ACID criteria clearly fails.

Confidence: **HIGH** / **MEDIUM** / **LOW**

## Output

Save the finding to `engagements/<folder>/findings/<N>-<slug>.md` with:
1. Title and CWE
2. ACID assessment (the four sections above)
3. Self-critique results
4. Verdict and confidence
5. Source→Sink chain with file:line references
6. Suggested next step (validate with PoC? look at related code? escalate?)
