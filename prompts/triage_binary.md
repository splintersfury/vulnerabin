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

## Analysis Steps

1. **Read the decompiled function** carefully.

2. **Identify sources** — Does this function receive external input?
   - Does it call recv(), read(), getenv(), copy_from_user()?
   - Do its parameters come from a caller that handles external input?
   - Check string references for CGI variable names, HTTP headers, etc.

3. **Identify sinks** — Does this function perform dangerous operations?
   - system(), strcpy(), sprintf(), memcpy() with attacker-influenced size?
   - Does it write to kernel memory, open files, execute SQL?

4. **Check sanitization** — Is input validated before reaching sinks?
   - Length checks (strlen before strcpy)?
   - Bounded operations (strncpy, snprintf with proper size)?
   - Input validation (isdigit, allowlist checks)?
   - Safe math (overflow-safe arithmetic before allocation)?

5. **Assess data flow** — Trace parameters through the function:
   - Which parameters are attacker-influenced? (based on callers)
   - Do those parameters flow to sink arguments?
   - Are there branches that skip the sink based on input validation?

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

```json
{
  "function": "function_name",
  "address": "0x...",
  "rating": 4,
  "label": "SINK",
  "sources_found": [
    {"symbol": "getenv", "line_approx": 12, "variable": "query_str"}
  ],
  "sinks_found": [
    {"symbol": "system", "line_approx": 45, "cwe": "CWE-78", "arg_source": "param_1"}
  ],
  "sanitizers_found": [],
  "data_flow": "param_1 (from caller) → sprintf(cmd, ..., param_1) → system(cmd)",
  "notes": "Command string built from parameter without any shell escaping"
}
```
