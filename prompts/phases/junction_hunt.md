# Junction-Hunt Mode

See CLAUDE.md "Junction-Attack Hunt Mode" for the full playbook. Repeatable LPE methodology, paid out twice (Bitdefender P3 $1,000; Dell SupportAssistInstaller P2 triaged).

## Pattern

A SYSTEM-context process touches a path under `C:\ProgramData\<vendor>\…`, `%WINDIR%\Temp\…`, or `%LOCALAPPDATA%\Temp\<vendor>\…` whose parent does not exist after a fresh install. Default Windows ACLs let any standard user pre-create the missing parent as an NTFS junction → SYSTEM-context read/write redirected.

## Tooling on Driver-Target VM

```powershell
# Enumerate vendor SYSTEM services
Get-CimInstance Win32_Service | Where-Object { $_.StartName -eq 'LocalSystem' -and $_.PathName -match '<vendor>' }

# ProcMon filter: Path contains "<vendor>", Operation is Create/Read/Write
# Look for Result = "PATH NOT FOUND" or "NAME NOT FOUND" on a ProgramData/Temp path

# Pre-create the missing parent as a junction
cmd /c mklink /J "C:\ProgramData\<vendor>\<missing>" "C:\Windows\System32"
```

## Journal

```bash
python3 scripts/journal.py append <eng> --phase deep --actor human --event finding \
    --ref findings/<N>-junction-<service>.md --summary "Junction LPE in <service>" \
    --meta cwe=CWE-59 --meta technique=junction_attack --meta acid=LIKELY
```

## Why this beats generic /hunt for matching targets

A 1-2 hour focused pass with junction-hunt is much higher ROI than full `/hunt` triage when:
- Vendor ships a Windows installer
- ≥1 auto-starting LocalSystem service (or elevated wrapper)
- Bug-bounty program accepts LPE class
