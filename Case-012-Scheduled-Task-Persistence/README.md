# SOC Case 012 — Windows Scheduled Task Persistence Investigation

## Overview

Investigated Windows scheduled tasks for potential persistence mechanisms, suspicious execution paths, elevated privileges, and missing executables.

Identified an Intel Update Manager scheduled task configured to run daily as SYSTEM with highest privileges. The executable and installation directory were missing, and the last recorded execution attempt returned a file-not-found error.

**Final Verdict:** Likely Benign — Orphaned Scheduled Task  
**Severity:** Low  
**Date:** November 2, 2026

## Investigation Highlights

| Indicator | Finding |
|---|---|
| Scheduled tasks enumerated | 258 |
| Elevated root-level tasks identified | 6 |
| Suspicious task | Intel Update Manager |
| Execution account | SYSTEM |
| Run level | Highest |
| Executable | `iumsvc.exe` |
| Executable present | No |
| Last execution result | `0x80070002` |
| Task Scheduler Operational logging | Disabled |
| Missing executables in targeted scan | 1 |

## Key Evidence

**Scheduled task:** `IUM-F1E24CA0-B63E-4F13-A9E3-4ADE3BFF3473`

**Configured executable:**

```text
C:\Program Files (x86)\Intel\Intel(R) Update Manager\bin\iumsvc.exe
```

**Filesystem checks:**

```text
DirectoryExists  : False
ExecutableExists : False
```

**Execution result:**

```text
LastRunTime    : 11/2/2026 11:57:57 AM
LastTaskResult : 2147942402
```

Decimal `2147942402` equals hexadecimal `0x80070002`, indicating the system could not find the specified file.

## Investigative Approach

1. Enumerated scheduled tasks and reviewed their states.
2. Examined actions invoking scripting tools and potentially suspicious directories.
3. Investigated elevated scheduled tasks.
4. Checked relevant executable paths and digital signatures.
5. Verified the Intel Update Manager executable and directory were absent.
6. Reviewed the task's last-run result and scheduling configuration.
7. Checked Task Scheduler Operational logging availability.
8. Conducted a targeted scan for additional missing `.exe` files.

## Conclusion

The evidence is consistent with an orphaned Intel Update Manager scheduled task, potentially left behind after software removal or modification.

No confirmed malicious execution or attacker persistence was identified.

The task remains configured to run with SYSTEM privileges. Administrative review and potential cleanup are recommended.

## Logging Limitation

The Task Scheduler Operational log was disabled, preventing detailed historical execution analysis through that source.

The targeted scan also did not cover every possible scheduled-task action format.

## Recommended Remediation

- Confirm whether Intel Update Manager is still needed.
- Review the obsolete task for authorized removal.
- Consider enabling Task Scheduler Operational logging.
- Periodically audit scheduled tasks for outdated executable paths.

## Skills Demonstrated

Windows Task Scheduler analysis, PowerShell investigation, persistence hunting, executable verification, event-log analysis, error-code interpretation, and evidence-based incident documentation.

**Disposition:** Investigation complete; remediation recommended.
