# SOC Case 004 — Windows Failed Login Investigation

## Case Overview

**Case ID:** SOC-004  
**Lab:** 12 — Detecting Suspicious Windows Login Attempts  
**Investigation Date:** November 1, 2026  
**Category:** Windows Authentication / Security Event Analysis  
**Environment:** Windows Workstation  
**Classification:** Suspected Local Authentication Issue  
**Disposition:** Inconclusive — No Confirmed Compromise  
**Status:** Closed — Training Investigation

This investigation examined multiple failed Windows authentication attempts recorded in the Windows Security event log.

A seven-day review identified **20 failed authentication events (Event ID 4625)**, including a concentration of 13 failures within approximately 19 minutes on October 26, 2026.

The investigated events were associated with `svchost.exe`. One event examined in detail showed an interactive logon attempt, the Local System security context, and the loopback IP address `127.0.0.1`.

The evidence suggested a possible local authentication issue, but the specific service and underlying cause could not be established.

## Investigation Objectives

- Identify failed Windows authentication attempts.
- Analyze authentication failures for suspicious patterns.
- Investigate potential brute-force activity.
- Examine logon types and authentication failure codes.
- Identify the processes associated with failed logons.
- Correlate authentication events with process creation records.
- Evaluate logging and audit-policy limitations.
- Document findings and determine an appropriate disposition.

## Tools and Technologies

- Windows PowerShell
- Windows Event Viewer
- Windows Security Event Logs
- Event ID 4625 — Failed Logon
- Event ID 4688 — Process Creation
- `Get-WinEvent`
- `auditpol`
- Windows Process Analysis

## Key Investigation Findings

### 1. Failed Authentication Pattern

A PowerShell investigation identified 20 failed authentication events within the seven-day search window.

| Date and Time | Failed Attempts |
|---|---:|
| October 26 — 1 PM | 13 |
| October 26 — 2 PM | 2 |
| October 26 — 9 PM | 1 |
| October 27 — 11 AM | 2 |
| October 28 — 12 AM | 1 |
| October 28 — 1 AM | 1 |
| **Total** | **20** |

The highest concentration occurred on October 26 between approximately 1:36 PM and 1:55 PM.

The repeated failures warranted investigation but did not independently establish a brute-force attack.

### 2. Authentication Event Analysis

A detailed Event ID 4625 record contained:

| Field | Observed Value |
|---|---|
| Logon Type | `2` — Interactive |
| Requesting Security ID | `S-1-5-18` — Local System |
| Caller Process | `svchost.exe` |
| Caller Process ID | `0x700` (1792) |
| Source Network Address | `127.0.0.1` |
| Failure Status | `0xC000006D` |
| Failure Substatus | `0xC000006A` |
| Authentication Package | Negotiate |

The failure substatus was consistent with an incorrect password.

The loopback address indicated local network context rather than an identified external source.

The specific account involved in the failed authentication was not established.

### 3. Process Investigation

All 13 authentication failures in the largest cluster identified `svchost.exe` as the caller executable.

Event ID 4688 records were examined to investigate historical process creation activity.

No matching process creation event was identified for the investigated process ID.

Available historical logging was insufficient to determine which Windows service initiated the authentication requests.

### 4. Audit Policy Investigation

The current Windows audit policy reported:

`Process Creation: No Auditing`

Historical Event ID 4688 records were present, indicating that process creation auditing had previously been active.

The audit configuration at the time of the original authentication failures could not be conclusively established.

### 5. Follow-Up Authentication Review

A follow-up search identified no additional Event ID 4625 records from October 29 onward in the retained Security log.

This observation did not establish that the endpoint was free of compromise.

## Final Assessment

**Classification:** Suspected Local Authentication Issue  
**Disposition:** Inconclusive — No Confirmed Compromise  
**Status:** Closed — Training Investigation

The evidence was consistent with a possible local Windows authentication issue.

However, the investigation could not determine:

- Which Windows service initiated the failed authentication attempts.
- Why incorrect credentials were being supplied.
- Whether cached credentials, application configuration, or another condition caused the failures.

The available evidence did not establish an external brute-force attack or confirmed malicious activity.

In a production SOC environment, additional investigation or escalation would depend on available telemetry, related alerts, and organizational procedures.

## Skills Demonstrated

- Windows Security Event Log analysis
- Failed login investigation
- Event ID 4625 interpretation
- Authentication failure code analysis
- Suspicious login pattern detection
- PowerShell-based event querying
- Windows process correlation
- Event ID 4688 analysis
- Windows audit policy inspection
- Evidence-based threat assessment
- Documentation of forensic limitations
- SOC incident reporting

## Full Incident Report

[Read the Full SOC Case 004 Incident Report](incident-report-004.md)

---

*This case documents a personal hands-on cybersecurity training investigation using local Windows event logs. It does not represent a production SOC incident.*
