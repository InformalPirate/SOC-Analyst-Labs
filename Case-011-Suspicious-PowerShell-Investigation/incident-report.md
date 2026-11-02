# SOC Case 011 — Suspicious PowerShell Activity Investigation

**Case ID:** SOC-011  
**Category:** Endpoint Security / PowerShell Script Block Analysis  
**Investigation Date:** November 2, 2026  
**Severity:** Low / Informational  
**Final Disposition:** Likely Benign  
**Confidence Level:** Moderate  
**Status:** Closed — No Confirmed Malicious Activity

---

## 1. Executive Summary

During a Windows endpoint security investigation, multiple PowerShell Event ID 4104 warning records were identified containing keywords commonly associated with suspicious PowerShell activity.

The investigation focused on two groups of events:

- Historical PowerShell activity recorded on November 12, 2022.
- Recent PowerShell activity recorded on November 1–2, 2026.

The historical activity involved a four-part PowerShell script consistent with Windows Network Diagnostics. The script contained the command `Invoke-Expression`, which triggered suspicious-keyword detection.

The recent events were associated with PowerShell commands executed during the analyst's own security investigations.

After examining script contents, timestamps, event records, process information, and available security logs, no confirmed malicious activity was identified.

The case was classified as **Likely Benign**, with moderate confidence due to limitations in historical logging and process attribution.

## 2. Investigation Objectives

The investigation aimed to:

1. Identify suspicious PowerShell script-block activity.
2. Determine why Event ID 4104 warnings were generated.
3. Examine potentially dangerous PowerShell commands.
4. Correlate script execution with other Windows events.
5. Identify the process associated with historical PowerShell activity.
6. Distinguish legitimate administrative activity from potential malicious execution.
7. Document findings and determine an appropriate incident disposition.

## 3. Environment and Tools

**Operating System:** Microsoft Windows

**Tools Used:**
- Windows PowerShell
- Get-WinEvent
- Windows Event Viewer
- Microsoft-Windows-PowerShell/Operational log
- Windows Security event log

**Relevant Event IDs:**

| Event ID | Description |
|---|---|
| 4104 | PowerShell script-block logging |
| 53504 | PowerShell IPC listening-thread initialization |
| 4688 | Windows process creation |
| 400 / 403 | PowerShell engine lifecycle events |

## 4. Initial Detection

PowerShell script-block logs were examined for commands and strings commonly associated with malicious scripting techniques.

The detection keywords included:

- EncodedCommand
- FromBase64String
- DownloadString
- Invoke-WebRequest
- Invoke-Expression
- IEX

These indicators can appear in malicious scripts involving obfuscation, downloaded code, or dynamic execution.

However, their presence alone does not establish malicious intent.

The investigation therefore required analysis of the surrounding script content and related events.

## 5. Historical PowerShell Activity

**Date:** November 12, 2022  
**Time:** 10:41 PM  
**Log:** Microsoft-Windows-PowerShell/Operational

Four PowerShell script-block events were identified.

| Record ID | Event ID | Severity |
|---|---|---|
| 31201 | 4104 | Warning |
| 31202 | 4104 | Warning |
| 31203 | 4104 | Warning |
| 31204 | 4104 | Warning |

All four records belonged to the same script block.

**Script Block ID:**

`dfe25421-2c1e-4d9e-8569-92110b666935`

**Observed Script Path:**

`C:\Users\Chris\AppData\Local\Temp\SDIAG_c42d1803-ca94-4130-a3fc-e4acb11990f5\UtilityFunctions.ps1`

The script contained functions associated with Windows network troubleshooting, including:

- GetWebNDFIncidentData
- GetUNCNDFIncidentData
- AddNetworkInfoToSession
- CreateCab

The script also collected network configuration information using commands such as:

`ipconfig /all`

`route print`

The collected information was associated with a diagnostic archive named:

`NetworkConfiguration.cab`

### Analysis

These functions and commands were consistent with legitimate Windows Network Diagnostics activity.

The script also contained `Invoke-Expression`, which can execute dynamically constructed PowerShell commands.

Although attackers sometimes abuse this command, the observed usage occurred within a diagnostic command-output collection function.

**Finding:** Suspicious keyword present, but the surrounding script behavior was consistent with legitimate network troubleshooting.

## 6. PowerShell Event Correlation

A timeline query was performed for November 12, 2022, between 10:39 PM and 10:43 PM.

The following events were identified:

| Time | Event ID | Record ID |
|---|---|---|
| 10:41 PM | 53504 | 31200 |
| 10:41 PM | 4104 | 31201 |
| 10:41 PM | 4104 | 31202 |
| 10:41 PM | 4104 | 31203 |
| 10:41 PM | 4104 | 31204 |

Event ID 53504 occurred immediately before the four script-block records in the event sequence.

Its message stated:

"Windows PowerShell has started an IPC listening thread on process: 11812 in AppDomain: DefaultAppDomain."

**Identified Process ID:** 11812

### Analysis

IPC stands for Inter-Process Communication.

This event indicated that PowerShell initialized an IPC listening thread within process 11812.

However, the event did not identify the executable associated with that process or its parent process.

The process ID was therefore treated as an investigative lead rather than proof of the script's origin.

A separate query for PowerShell engine lifecycle Events 400 and 403 did not return matching records within the investigated time window.

## 7. Historical Process Creation Investigation

The analyst attempted to correlate process ID 11812 with Windows Security Event ID 4688.

Event ID 4688 can provide information about newly created processes.

The investigation searched for matching process-creation records around November 12, 2022.

**Result:** No matching Event ID 4688 records were returned.

This initially prevented identification of the historical executable and its parent process.

To determine whether the missing evidence was caused by log retention, the analyst examined the Windows Security log's available history.

### Security Log Retention Results

| Field | Value |
|---|---|
| Log Name | Security |
| Available Records | 32,479 |
| Oldest Available Event | October 26, 2026 |
| Oldest Event Time | 1:58:32 PM |
| Oldest Event ID | 5379 |
| Historical Investigation Date | November 12, 2022 |

### Analysis

The Windows Security log did not contain records extending back to November 2022.

Therefore, the absence of Event ID 4688 evidence was attributable to insufficient historical log coverage.

This finding did not indicate log deletion, tampering, or malicious activity.

**Finding:** Historical process attribution could not be completed because the required Security event records were no longer available.

## 8. Recent PowerShell Threat Hunting

The analyst performed an additional search for suspicious PowerShell keywords within the previous seven days.

Four matching records were identified.

| Date | Record ID | Event ID |
|---|---|---|
| November 1, 2026 | 32542 | 4104 |
| November 1, 2026 | 32543 | 4104 |
| November 1, 2026 | 32546 | 4104 |
| November 2, 2026 | 32830 | 4104 |

The script previews contained PowerShell commands used to search event logs for suspicious keywords.

One example was:

`$pattern = 'EncodedCommand|FromBase64String|DownloadString|Invoke-WebRequest|Invoke-Expression|IEX\s*\('`

### Analysis

The detection query contained the same suspicious keywords that it was designed to identify.

When PowerShell logged the analyst's search command, the detection logic matched those keywords within the search expression itself.

This produced self-matching results.

The four recent events were consistent with the analyst's known security investigation activity.

**Finding:** The recent keyword detections were assessed as benign analyst-generated activity rather than evidence of malicious PowerShell execution.

## 9. Final Investigation Timeline

| Date / Time | Activity |
|---|---|
| November 12, 2022, 10:41 PM | PowerShell IPC event recorded for PID 11812 |
| November 12, 2022, 10:41 PM | Four PowerShell script-block fragments logged |
| November 1, 2026, 9:55 PM | Analyst PowerShell keyword search logged |
| November 1, 2026, 9:56 PM | Additional analyst keyword search logged |
| November 1, 2026, 10:01 PM | Historical script-block investigation logged |
| November 2, 2026, 4:13 PM | Recent PowerShell threat-hunting query logged |
| November 2, 2026 | Historical process correlation and Security log retention reviewed |

## 10. Indicators and Findings

**Potentially Suspicious Indicators:**

- PowerShell Event ID 4104 warning records.
- Presence of `Invoke-Expression`.
- PowerShell activity involving a temporary script directory.
- Historical PowerShell process with incomplete attribution.

**Benign Context Identified:**

- Script functions consistent with Windows Network Diagnostics.
- Network troubleshooting commands.
- Diagnostic archive creation.
- Four script fragments belonging to one script block.
- Recent warning records corresponding to known analyst activity.

**Evidence Not Established:**

- Malicious PowerShell execution.
- Command-and-control communications.
- Credential theft.
- Persistence mechanisms.
- Unauthorized process execution.
- Verified malicious parent-child process relationships.

The absence of these findings in the reviewed evidence does not prove that the endpoint was free of compromise.

## 11. Final Assessment

**Disposition:** Likely Benign

**Severity:** Low / Informational

**Confidence:** Moderate

The historical PowerShell script was consistent with legitimate Windows network troubleshooting.

The recent PowerShell warning events were consistent with commands executed during authorized security investigations.

No confirmed malicious execution was identified within the reviewed records.

However, the historical executable and parent process could not be independently verified because relevant Security log records were unavailable.

The investigation therefore concluded that the observed activity was likely benign, rather than definitively safe.

## 12. Recommendations

1. Maintain PowerShell script-block logging to improve visibility into script execution.
2. Correlate PowerShell events with process-creation telemetry when available.
3. Preserve important event records and script-block identifiers during investigations.
4. Improve log retention or centralized collection to support historical investigations.
5. Evaluate suspicious commands within their surrounding script context.
6. Reduce unnecessary alerts caused by analyst-generated keyword searches.
7. Investigate new evidence if it links the historical activity to unauthorized execution.

## 13. Lessons Learned

This investigation demonstrated several important SOC analyst concepts.

**Lesson 1 — Suspicious commands are not automatically malicious.**

PowerShell commands such as `Invoke-Expression` can appear in legitimate administrative scripts.

**Lesson 2 — Event correlation improves investigation accuracy.**

Examining adjacent event records helped establish the sequence of historical PowerShell activity.

**Lesson 3 — Process IDs require additional context.**

Identifying a process ID does not automatically reveal the executable, parent process, or reason for execution.

**Lesson 4 — Logging limitations affect investigation confidence.**

Historical event records may no longer be available, preventing definitive attribution.

**Lesson 5 — Detection rules can generate false positives.**

The analyst's own threat-hunting commands triggered keyword-based detections.

**Lesson 6 — Professional incident reports must acknowledge uncertainty.**

A defensible conclusion distinguishes confirmed facts from reasonable interpretations and unavailable evidence.

## 14. Skills Demonstrated

- Windows Event Log investigation
- PowerShell Event ID 4104 analysis
- PowerShell script-block reconstruction
- Suspicious command detection
- Event timeline correlation
- Historical process investigation
- False-positive identification
- Windows Security log retention analysis
- Incident classification
- Technical documentation
- Evidence-based SOC decision-making

## 15. Evidence Limitations

The investigation was conducted using available Windows event logs and PowerShell command output.

The following supporting evidence was not independently verified or preserved within this report:

- Original executable hashes
- Digital signature verification
- Complete historical process tree
- Raw EVTX evidence exports
- Independent authentication of the diagnostic script's origin

These limitations were considered when assigning the final confidence level.

---

## 16. Case Closure

**Case ID:** SOC-011

**Case Title:** Suspicious PowerShell Activity Investigation

**Final Status:** Closed

**Classification:** Likely Benign

**Confidence:** Moderate

**Summary:** Historical PowerShell warnings were consistent with Windows Network Diagnostics, while recent suspicious-keyword detections were consistent with authorized analyst activity. No malicious execution was confirmed in the reviewed evidence.

**Final SOC Decision:** Document findings, close the investigation as likely benign, and reopen if new corroborating evidence emerges.

---

*This investigation was performed as part of a hands-on SOC Analyst training portfolio using Windows endpoint telemetry and PowerShell security analysis.*
