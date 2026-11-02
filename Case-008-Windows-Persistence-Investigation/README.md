# SOC Case 008 — Windows Persistence Investigation

## Case Overview

**Case ID:** SOC-008  
**Investigation Date:** November 2, 2026  
**Category:** Windows Persistence / Scheduled Task Analysis  
**Severity:** Informational  
**Classification:** Likely Benign  
**Status:** Closed — No Confirmed Malicious Persistence

This investigation examined Windows startup registry entries and scheduled tasks to identify potentially suspicious persistence mechanisms.

Two scheduled tasks received additional analysis: `npcapwatchdog` and `USER_ESRV_SVC_QUEENCREEK`.

The Intel-related task warranted closer examination because it executed a multi-stage script chain using Windows Script Host and operated with elevated SYSTEM privileges.

No confirmed malicious persistence was identified in the reviewed artifacts.

## Investigation Objectives

- Identify applications configured for automatic startup.
- Examine scheduled tasks for suspicious behavior.
- Trace script and executable execution chains.
- Verify executable digital signatures.
- Collect SHA-256 file hashes.
- Review task triggers and execution privileges.
- Examine file permissions for potential unauthorized modification.
- Assess whether observed persistence mechanisms were malicious or legitimate.

## Tools and Technologies

- Windows PowerShell
- Windows Registry
- Windows Task Scheduler
- Windows Script Host
- Authenticode Signature Verification
- SHA-256 Hashing
- VirusTotal Reputation Lookup
- NTFS Access Control List Analysis

## Key Investigation Findings

### 1. Windows Startup Registry Analysis

Examined the following registry locations:

- `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`

Identified common startup applications, including Microsoft OneDrive, Microsoft Edge, Spotify, Windows Security, and Realtek utilities.

No obviously suspicious startup entries were identified in the two registry locations examined.

### 2. Npcap Watchdog Investigation

Investigated the scheduled task:

`npcapwatchdog`

The task referenced `CheckStatus.bat`, which inspected Npcap driver configuration and could invoke a repair script when necessary.

**Assessment:** Likely benign driver-maintenance activity consistent with the installed Wireshark environment.

The referenced repair script was not independently analyzed.

### 3. Intel Scheduled Task Investigation

Investigated the scheduled task:

`USER_ESRV_SVC_QUEENCREEK`

The task executed with SYSTEM privileges and used a multi-stage script execution chain.

**Observed execution chain:**

`Scheduled Task → Wscript.exe → task.vbs → cmd.exe → task.bat → task.exe`

Although legitimate software can use this behavior, script-based execution with elevated privileges warranted further investigation.

### 4. Executable Signature Verification

Verified the final Intel executable using Windows Authenticode.

**Results:**
- Signature status: Valid
- Publisher: Intel Corporation
- Certificate issuer: Sectigo Public Code Signing CA R36

The valid signature supported the executable's claimed publisher identity.

### 5. File Hash and Reputation Analysis

Collected the SHA-256 hash of the investigated executable and performed a VirusTotal reputation lookup.

The lookup did not report the file as malicious.

This result was treated as supporting evidence rather than proof of safety.

### 6. Scheduled Task Configuration

Identified the following task properties:

| Property | Finding |
|---|---|
| Trigger | User logon |
| Trigger delay | Four minutes |
| Execution account | SYSTEM |
| Run level | Highest |
| Last task result | 0 |
| Missed runs | 0 |

The task's reported execution result was successful.

### 7. File Permission Analysis

Reviewed NTFS permissions for the executable, supporting scripts, and containing directory.

The examined access control lists did not reveal obvious ordinary-user Write or Modify permissions.

This reduced concern about straightforward unauthorized modification but did not constitute a complete effective-permissions assessment.

## Final Assessment

**Classification:** Likely Benign  
**Severity:** Informational  
**Status:** Closed

The investigated scheduled tasks were consistent with legitimate software-maintenance activity.

The Intel executable had a valid digital signature, the reputation lookup did not indicate malicious reports, and the inspected permissions did not reveal obvious ordinary-user modification access.

No confirmed malicious persistence was identified.

**Investigation limitations:** Complete runtime analysis, reverse engineering, and exhaustive persistence coverage were outside the scope of this investigation.

## Skills Demonstrated

- Windows persistence investigation
- Registry startup analysis
- Scheduled task auditing
- Script execution-chain analysis
- Digital signature verification
- SHA-256 hashing
- File reputation analysis
- NTFS permission auditing
- Privileged execution assessment
- Evidence-based incident classification
- SOC incident documentation

## Full Incident Report

[Read the Full SOC Case 008 Incident Report](incident-report-008.md)

---

*This investigation was conducted as part of a hands-on SOC Analyst cybersecurity training portfolio.*
