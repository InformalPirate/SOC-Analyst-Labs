# SOC Case 012 — Windows Scheduled Task Persistence Investigation

**Case ID:** SOC-012  
**Investigation Date:** November 2, 2026  
**Category:** Persistence Investigation / Windows Scheduled Tasks  
**Platform:** Windows  
**Tools:** PowerShell, Windows Task Scheduler, Get-ScheduledTask, Get-ScheduledTaskInfo, Get-WinEvent  
**Severity:** Low  
**Final Classification:** Likely Benign — Orphaned Scheduled Task  
**Confidence:** High  
**Status:** Investigation Complete — Remediation Recommended

---

## 1. Executive Summary

A scheduled-task persistence investigation was conducted on a Windows endpoint to identify potentially suspicious task actions, elevated execution contexts, and references to missing executables.

The investigation identified a scheduled task associated with Intel Update Manager:

`IUM-F1E24CA0-B63E-4F13-A9E3-4ADE3BFF3473`

The task was configured to execute daily under the SYSTEM account with the highest available privileges.

Its configured executable, `iumsvc.exe`, and the associated installation directory were both absent from the filesystem.

The task's most recent recorded execution attempt returned Windows error `0x80070002`, indicating that the specified file could not be found.

A targeted scan of scheduled tasks identified no additional missing executables among actions using explicit absolute `.exe` paths.

The available evidence supports the assessment that the task is likely an orphaned remnant of a previous Intel Update Manager installation. No evidence of malicious execution or attacker-controlled persistence was identified.

## 2. Investigation Objectives

- Enumerate scheduled tasks and identify potentially suspicious execution methods.
- Examine tasks configured to run with elevated privileges.
- Validate executable paths and digital signatures where applicable.
- Identify scheduled tasks referencing nonexistent executables.
- Review available task execution results and event logs.
- Determine whether identified behavior supports malicious persistence or benign system activity.

## 3. Initial Enumeration

The scheduled-task baseline contained:

| State | Count |
|---|---:|
| Ready | 212 |
| Running | 4 |
| Disabled | 42 |
| **Total** | **258** |

The investigation examined task actions referencing scripting interpreters and commonly abused execution locations.

Observed entries included Windows maintenance tasks, Microsoft Defender tasks, Intel software components, Microsoft Edge Update tasks, and an existing user-authorized job-search automation.

The previously investigated Intel QUEENCREEK script task was not treated as a new compromise indicator without additional evidence.

## 4. Identification of Elevated Scheduled Tasks

A review of root-level scheduled tasks configured with the `Highest` run level identified six tasks, including Intel software services and Microsoft Edge Update components.

The Intel Update Manager task was selected for additional investigation because its configured executable could not be found.

**Task configuration:**

| Attribute | Value |
|---|---|
| Task name | `IUM-F1E24CA0-B63E-4F13-A9E3-4ADE3BFF3473` |
| Task state | Ready |
| Execution account | SYSTEM |
| Run level | Highest |
| Hidden | False |
| Trigger | Daily |
| Arguments | `--automatic` |

**Configured executable:**

```text
C:\Program Files (x86)\Intel\Intel(R) Update Manager\bin\iumsvc.exe
```

The elevated execution context warranted further examination, but SYSTEM execution alone was not considered evidence of malicious behavior.

## 5. Filesystem Verification

PowerShell filesystem checks returned:

```text
DirectoryExists  : False
ExecutableExists : False
```

Neither the configured Intel Update Manager installation directory nor the referenced executable existed at the expected location.

This finding is consistent with a scheduled task left behind following software removal or modification.

The investigation did not establish when or why the Intel Update Manager files were removed.

## 6. Execution Result Analysis

The following task information was retrieved:

```text
LastRunTime        : 11/2/2026 11:57:57 AM
LastTaskResult     : 2147942402
NextRunTime        : 11/3/2026 11:57:57 AM
NumberOfMissedRuns : 0
```

The decimal result `2147942402` corresponds to hexadecimal `0x80070002`.

**Error meaning:** The system cannot find the file specified.

This result is consistent with the missing executable identified during filesystem verification.

The recorded last-run timestamp establishes that Task Scheduler reported an execution attempt. It does not demonstrate successful execution of the absent Intel service.

## 7. Event Log Visibility

A query of the Windows Task Scheduler Operational event log returned no matching execution-history events.

A subsequent configuration check established:

```text
LogName            : Microsoft-Windows-TaskScheduler/Operational
IsEnabled          : False
RecordCount        :
MaximumSizeInBytes : 10485760
```

The Operational log was disabled at the time of investigation.

As a result, detailed task-start and action-execution events were unavailable through this log.

This represents a monitoring visibility limitation. The investigation did not establish why or when logging was disabled.

## 8. Additional Scheduled Task Scan

A follow-up PowerShell scan examined scheduled-task actions containing explicit absolute executable paths ending in `.exe`.

The corrected scan included null-value handling to avoid processing actions without executable fields.

**Result:** One missing executable was identified.

```text
TaskName          : IUM-F1E24CA0-B63E-4F13-A9E3-4ADE3BFF3473
State             : Ready
RunAs             : SYSTEM
MissingExecutable : C:\Program Files (x86)\Intel\Intel(R) Update Manager\bin\iumsvc.exe
```

No additional missing executables were identified within the scope of this targeted scan.

This result does not rule out broken or suspicious tasks using relative paths, scripts, environment variables, or other action types.

## 9. Analysis and Assessment

The following evidence supports a benign orphaned-task explanation:

1. The task references a recognizable Intel Update Manager installation path.
2. The executable and parent installation directory are absent.
3. The last recorded execution result indicates a missing file.
4. The task is visible rather than hidden.
5. The targeted scan did not identify additional missing executables.

The task's SYSTEM execution context and highest run level increase the importance of reviewing obsolete task configurations. However, elevated privileges do not independently establish malicious intent.

The investigation found no evidence that this task successfully launched malware, executed attacker-controlled code, or maintained active malicious persistence.

**Final Assessment:** Likely benign orphaned scheduled task.

**Confidence:** High, based on the consistency between filesystem and execution-result evidence.

## 10. Limitations

- Task Scheduler Operational logging was disabled.
- Historical installation and uninstallation records were not examined.
- The exact cause and date of Intel Update Manager removal were not established.
- The targeted missing-executable scan did not cover all possible task-action formats.
- No changes were made to the task configuration.
- The investigation did not establish whether the executable directory could be written to by an unprivileged user.

## 11. Recommended Remediation

**Recommendation 1 — Review the obsolete task**

Confirm whether Intel Update Manager is still required. If it is no longer needed, have an authorized administrator disable or remove the orphaned task through the normal change-control process.

**Recommendation 2 — Improve logging**

Consider enabling Windows Task Scheduler Operational logging to support future task-execution investigations, consistent with endpoint monitoring policies.

**Recommendation 3 — Maintain scheduled-task hygiene**

Periodically review scheduled tasks for obsolete software references, unexpected privilege levels, and unusual execution paths.

**Recommendation 4 — Preserve investigation evidence**

Retain relevant task configuration, filesystem verification results, and execution error codes as supporting evidence.

## 12. Final Disposition

**Classification:** Likely Benign — Orphaned Scheduled Task  
**Severity:** Low  
**Investigation Status:** Complete  
**Remediation Status:** Recommended, not performed  
**Malicious Persistence Confirmed:** No

The evidence supports a leftover Intel Update Manager scheduled task that attempts to execute a nonexistent service executable.

The investigation did not identify confirmed malicious activity. The case is closed for investigative purposes, with configuration cleanup and logging improvements recommended.

---

## 13. Skills Demonstrated

- Windows scheduled-task enumeration
- Persistence mechanism investigation
- Privileged execution-context analysis
- PowerShell-based filesystem validation
- Windows error-code interpretation
- Event-log availability assessment
- False-positive reduction
- Evidence-based incident classification
- Documentation of investigative limitations
- Security configuration recommendations

**Case Conclusion:** A suspicious-looking SYSTEM-level scheduled task was investigated and classified as a likely benign orphaned software component based on corroborating evidence.
