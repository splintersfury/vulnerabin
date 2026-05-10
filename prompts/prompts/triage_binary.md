# Binary Function Triage Prompt

You are analyzing a single decompiled function from a native binary for security vulnerabilities.

## Context
- **Binary**: {{binary_name}}
- **Function**: {{function_name}} @ {{address}}
- **Architecture**: {{arch}}
- **Bug bounty scope**: {{scope_summary}}

## Function Context (from Ghidra)
- **Callers**: {{callers}} (who calls this function)
- **Callees**: {{callees}} (what this function calls)
- **String references**: {{strings}}
- **Size**: {{size}} bytes, {{instruction_count}} instructions

## Taxonomy Reference
Load and reference these files for pattern matching:
- `taxonomy/binary/sources.json` — where attacker input enters
- `taxonomy/binary/sinks.json` — dangerous operations by CWE
- `taxonomy/binary/sanitizers.json` — what breaks taint chains

## Analysis Steps (Step-by-Step Reasoning)

For each step below, write out your reasoning BEFORE stating your conclusion. Do not jump to a verdict. Explain what you observe, what it means, and what remains uncertain. This step-by-step approach reduces false positives and forces you to surface assumptions.

1. **Read the decompiled function** carefully. State what the function appears to do in plain language before looking for vulnerabilities.

2. **Identify sources** — Does this function receive external input?
   - Does it call recv(), read(), getenv(), copy_from_user()?
   - Do its parameters come from a caller that handles external input?
   - Check string references for CGI variable names, HTTP headers, etc.
   - **Reasoning checkpoint**: State which inputs you believe are attacker-controlled and WHY. If you are unsure, say so.

3. **Identify sinks** — Does this function perform dangerous operations?
   - system(), strcpy(), sprintf(), memcpy() with attacker-influenced size?
   - Does it write to kernel memory, open files, execute SQL?
   - **Reasoning checkpoint**: For each sink, explain what makes it dangerous in this specific context. A strcpy is not a finding if the source is a compile-time constant.

4. **Check sanitization** — Is input validated before reaching sinks?
   - Length checks (strlen before strcpy)?
   - Bounded operations (strncpy, snprintf with proper size)?
   - Input validation (isdigit, allowlist checks)?
   - Safe math (overflow-safe arithmetic before allocation)?
   - **Reasoning checkpoint**: State whether sanitization is PRESENT, ABSENT, or UNKNOWN (code not visible). Do not assume absent means vulnerable.

4.5. **Audit assumptions** (for SANITIZER / gate functions) — If this function acts as a
   security gate (access check, hash validation, permission verify), challenge its assumptions:
   - Load `taxonomy/binary/assumption_attacks.json` for known assumption-violation patterns
   - What does this check ACTUALLY verify vs what it ASSUMES?
   - Does it check a file on disk? (TOCTOU via hardlink/symlink, path != loaded binary)
   - Does it check a name/substring? (Process name spoofing, path manipulation)
   - Does it read shared memory twice? (Double-fetch, value can change between reads)
   - Does it validate a handle then use it later? (Handle recycling, object can change)
   - Does it validate a size then use it in arithmetic? (Integer overflow between check and use)
   - Does it pass user-controlled values to kernel APIs? (API side-effect abuse, ObfDereferenceObject = arbitrary decrement)
   - Is the check applied on ALL code paths, or only the obvious one? (Alternate entry point)
   - Reference: `prompts/vuln_patterns/toctou_assumption.md`

5. **Assess data flow** — Trace parameters through the function:
   - Which parameters are attacker-influenced? (based on callers)
   - Do those parameters flow to sink arguments?
   - Are there branches that skip the sink based on input validation?
   - **Reasoning checkpoint**: Write the chain explicitly: "Parameter X flows to local Y via [operation], then Y is passed to [sink] at line Z." If the chain has gaps, state them.

6. **Rate exploitability** (1-5):
   - **5**: Source AND sink in same function, no sanitization, attacker controls sink arg
   - **4**: Calls a source or sink with clear data flow from parameters
   - **3**: Dangerous patterns present but bounded/checked
   - **2**: Minor concerns, well-protected
   - **1**: No security-relevant patterns (utility, init, cleanup)

7. **Label the function**:
   - **SOURCE**: Receives external input (network, CGI, IOCTL, user-space)
   - **SINK**: Performs dangerous operation (exec, copy, format, alloc)
   - **PASSTHROUGH**: Routes data from source to sink (dispatcher, wrapper)
   - **SANITIZER**: Validates or bounds-checks input
   - **IRRELEVANT**: No security relevance (init, cleanup, math, UI)

## Output Format

Your output MUST conform to `taxonomy/schemas/triage_output.json`. The `reasoning` field is MANDATORY. Write your step-by-step reasoning there, not just the conclusion. If you skip reasoning, the output is invalid.

```json
{
  "target": "function_name",
  "address": "0x...",
  "rating": 4,
  "label": "SINK",
  "reasoning": "This function takes param_1 from its caller (FUN_dispatch, which reads from CGI QUERY_STRING via getenv). param_1 is passed to sprintf on line 30 to build a shell command string with no escaping or validation. The resulting buffer is passed to system() on line 45. No sanitization is present between the source and sink. Uncertainty: I have not confirmed that FUN_dispatch is reachable from the web server entry point, but the string references to 'Content-Type' suggest it is a CGI handler.",
  "sources_found": [
    {"pattern": "getenv", "symbol": "getenv", "line_approx": 12, "variable": "query_str", "attacker_control": "full"}
  ],
  "sinks_found": [
    {"pattern": "system", "line_approx": 45, "cwe": "CWE-78", "arg_source": "param_1"}
  ],
  "sanitizers_found": [],
  "data_flow": "param_1 (from caller) -> sprintf(cmd, ..., param_1) -> system(cmd)",
  "notes": "Command string built from parameter without any shell escaping"
}
```
