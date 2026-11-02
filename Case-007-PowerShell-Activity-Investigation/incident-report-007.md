# Case 007 — PowerShell Activity Investigation

**Case ID:** SOC-007  
**Investigation Date:** November 2, 2026  
**Analyst Role:** SOC Analyst (Training Lab)  
**Status:** Closed  
**Final Classification:** Likely Benign — No Confirmed Compromise

## 1. Executive Summary

An investigation was conducted into PowerShell activity recorded in the Windows PowerShell Operational event log.

The investigation focused on Event ID 4104 (script block logging), particularly code referencing the Windows Management Instrumentation (WMI) class `ROOT/StandardCimv2/MSFT_NetUDPSetting`.

Analysis of script block contents, event timestamps, process identifiers, and parent-process information indicated that the reviewed activity was consistent with legitimate Windows networking-management functionality.

No confirmed malicious activity was identified in the reviewed evidence.

## 2. Initial Detection

The PowerShell Operational log was confirmed to be enabled, with 1,957 records at the beginning of the investigation.

The 100 most recent records included:

| Event ID | Count |
|---|---:|
| 4104 | 82 |
| 4100 | 6 |
| 53504 | 4 |
| 40961 | 4 |
| 40962 | 4 |

Event ID 4104 was selected for further investigation because it records PowerShell script block activity.

## 3. Investigation and Evidence

### Script Block Analysis

A recorded script block contained:

```powershell
$script:ClassName = 'ROOT/StandardCimv2/MSFT_NetUDPSetting'
$script:ObjectModelWrapper = [Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter]
```

The `ROOT` component refers to a WMI namespace rather than Linux root privileges or evidence of elevated execution.

The `CimCmdletAdapter` reference and related code were consistent with PowerShell networking-management command definitions.

Additional recorded classes included:

- `MSFT_NetUDPEndpoint`
- `MSFT_NetTCPConnection`
- `MSFT_NetIPAddress`
- `MSFT_NetRoute`
- `MSFT_NetIPInterface`

### Process Investigation

A November 2 event was associated with PowerShell PID `16796`.

The process executable was located at:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

The recorded parent process ID was `2860`, which corresponded to:

`C:\WINDOWS\Explorer.EXE`

The process start times were consistent with Explorer launching the PowerShell session.

### Investigator-Generated Activity

Several script block events were identified as commands executed during the investigation itself.

This demonstrated the importance of distinguishing investigator-generated log entries from the original activity under review.

## 4. Investigation Timeline

| Timestamp | Observation |
|---|---|
| Oct. 31, 2026 — 6:13:19 PM | Explorer process PID 2860 started |
| Nov. 1, 2026 — 1:55 PM | Earlier event referencing `MSFT_NetUDPSetting` identified |
| Nov. 1, 2026 — approximately 10:17 PM | PowerShell process PID 16796 started |
| Nov. 2, 2026 — 8:42:33–8:42:37 AM | Multiple networking-related PowerShell script blocks recorded |
| Nov. 2, 2026 | Investigation completed |

## 5. Findings

The evidence was consistent with legitimate Windows PowerShell networking-management activity.

The reviewed script blocks resembled PowerShell module-generated code rather than clearly malicious instructions.

No confirmed evidence of credential theft, unauthorized privilege escalation, or malicious PowerShell execution was identified in the reviewed records.

The precise command responsible for loading the networking code was not conclusively established.

## 6. Final Assessment

**Classification:** Likely Benign  
**Disposition:** Closed — Training Investigation

The reviewed activity did not provide sufficient evidence to establish malicious execution or compromise.

This assessment applies to the evidence examined and does not constitute a comprehensive security assessment of the host.

## 7. Lessons Learned

1. PowerShell Event ID 4104 provides valuable visibility into script block activity.
2. WMI namespaces containing `ROOT` do not inherently indicate elevated privileges.
3. Process-tree analysis helps establish execution context.
4. Investigator-generated activity can contaminate log searches.
5. Script block content must be interpreted carefully: a function definition does not necessarily prove that the function was invoked.
6. Security conclusions should reflect the strength and limitations of the available evidence.
