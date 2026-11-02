# SOC Case 011 — Suspicious PowerShell Activity Investigation

## Case Overview

**Case ID:** SOC-011  
**Investigation Date:** November 2, 2026  
**Category:** Endpoint Security / PowerShell Analysis  
**Severity:** Low / Informational  
**Classification:** Likely Benign  
**Confidence:** Moderate  
**Status:** Closed — No Confirmed Malicious Activity

This investigation examined suspicious PowerShell script-block logging events on a Windows endpoint.

Multiple Event ID 4104 warnings contained commands and keywords commonly associated with malicious PowerShell activity, including `Invoke-Expression`.

Analysis revealed that historical events were consistent with Windows Network Diagnostics, while recent detections corresponded to the analyst's own authorized security investigations.

No confirmed malicious PowerShell execution was identified.

## Investigation Objectives

- Identify suspicious PowerShell script-block activity.
- Examine potentially dangerous commands.
- Reconstruct historical script-block events.
- Correlate PowerShell activity with Windows Security events.
- Investigate process attribution.
- Identify false positives.
- Document findings and investigation limitations.

## Tools and Technologies

- Windows PowerShell
- Windows Event Viewer
- `Get-WinEvent`
- Microsoft-Windows-PowerShell/Operational
- Windows Security Event Logs
- PowerShell Script Block Logging

## Key Windows Event IDs

| Event ID | Description |
|---|---|
| 4104 | PowerShell script-block logging |
| 53504 | PowerShell IPC listening-thread initialization |
| 4688 | Windows process creation |
| 400 / 403 | PowerShell engine lifecycle |

## Key Investigation Findings

### 1. Suspicious PowerShell Keywords

Investigated script blocks containing keywords associated with potentially suspicious activity:

- `EncodedCommand`
- `FromBase64String`
- `DownloadString`
- `Invoke-WebRequest`
- `Invoke-Expression`
- `IEX`

These keywords were treated as investigation leads rather than proof of malicious activity.

### 2. Historical PowerShell Activity

Identified four Event ID 4104 records from November 12, 2022, belonging to the same script block.

The script contained functions consistent with Windows Network Diagnostics, including:

- `GetWebNDFIncidentData`
- `GetUNCNDFIncidentData`
- `AddNetworkInfoToSession`
- `CreateCab`

Although the script contained `Invoke-Expression`, its surrounding behavior was consistent with network troubleshooting and diagnostic data collection.

### 3. Event Correlation

Correlated PowerShell Event ID 53504 with the four script-block records.

Identified process ID `11812` as an investigative lead.

However, the historical executable and parent process could not be independently verified.

### 4. Security Log Retention Limitations

Investigated Windows Security Event ID 4688 for historical process creation.

The available Security log only extended back to October 26, 2026.

Consequently, process attribution for the November 2022 activity could not be completed.

### 5. False-Positive Investigation

Identified four recent Event ID 4104 records from November 1–2, 2026.

These events contained suspicious keywords because the analyst's own PowerShell threat-hunting commands searched for those same terms.

The detections were assessed as benign, analyst-generated activity.

## Final Assessment

**Classification:** Likely Benign  
**Severity:** Low / Informational  
**Confidence:** Moderate  
**Status:** Closed

The historical script was consistent with legitimate Windows network troubleshooting.

Recent suspicious-keyword detections were consistent with authorized analyst activity.

No confirmed malicious execution was identified in the reviewed evidence.

Historical process attribution remained incomplete because relevant Security log records were unavailable.

## Skills Demonstrated

- PowerShell threat hunting
- Windows Event Log analysis
- Script-block reconstruction
- Suspicious command investigation
- Event timeline correlation
- Process attribution analysis
- False-positive identification
- Log retention assessment
- Incident classification
- Evidence-based SOC reporting

## Full Incident Report

[Read the Full SOC Case 011 Incident Report](incident-report.md)

---

*This investigation was conducted as part of a hands-on SOC Analyst cybersecurity training portfolio.*
