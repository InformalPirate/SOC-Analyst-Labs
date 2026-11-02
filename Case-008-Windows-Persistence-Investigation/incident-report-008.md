# Incident Report 008 — Windows Persistence Investigation

**Case ID:** SOC-008  
**Investigation Date:** November 2, 2026  
**Category:** Windows Persistence / Scheduled Task Analysis  
**Severity:** Informational  
**Status:** Closed — Likely Benign  
**Environment:** Windows Endpoint

---

## 1. Executive Summary

A Windows persistence investigation was conducted to identify potentially suspicious startup registry entries and scheduled tasks.

Initial analysis of the `HKEY_CURRENT_USER` and `HKEY_LOCAL_MACHINE` Run registry locations identified common startup applications, including Microsoft OneDrive, Microsoft Edge, Spotify, Windows Security, and Realtek audio utilities.

A review of scheduled tasks identified several third-party entries. Two tasks were examined in greater detail: `npcapwatchdog` and `USER_ESRV_SVC_QUEENCREEK`.

The Intel-related task warranted additional investigation because it used Windows Script Host, launched a batch file, and executed with SYSTEM privileges.

The investigation identified no confirmed malicious persistence. Available evidence supports a likely benign classification for the investigated tasks.

## 2. Investigation Objectives

- Identify applications configured for automatic startup.
- Examine scheduled tasks outside standard Microsoft task folders.
- Trace script and executable execution chains.
- Verify executable authenticity using digital signatures.
- Collect SHA-256 evidence.
- Review task triggers, execution history, and privileges.
- Evaluate file permissions for potential unauthorized modification.

## 3. Tools and Techniques

- Windows PowerShell
- Windows Registry inspection
- Windows Task Scheduler cmdlets
- Windows Script Host and batch-script analysis
- Authenticode digital signature verification
- SHA-256 hashing
- VirusTotal reputation lookup
- Windows NTFS access control list inspection

## 4. Registry Startup Analysis

The following registry locations were examined:

`HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`

`HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`

Observed entries included common Windows and third-party applications.

The HKLM entries included:

- `SecurityHealth` — Windows Security notification component
- `RTHDVCPL` — Realtek audio utility
- `RtHDVBg` — Realtek audio background component

Properties such as `PSPath`, `PSParentPath`, and `PSProvider` were identified as PowerShell object metadata rather than executable startup entries.

**Finding:** No obviously suspicious startup entries were identified in the two registry locations examined.

## 5. Scheduled Task Discovery

Scheduled tasks outside the standard Microsoft task folders were enumerated.

Entries included software associated with Intel, Microsoft Edge, OneDrive, Google Updater, Realtek, Synaptics, HP, and Npcap.

A user-created job automation task was also present and recognized as authorized activity.

Two tasks were selected for closer examination.

### 5.1 Npcap Watchdog

**Task Name:** `npcapwatchdog`

**Configured Action:**

`C:\Program Files\Npcap\CheckStatus.bat`

The batch file was inspected and found to:

1. Locate the Npcap installation directory using registry queries.
2. Check the Npcap driver's startup configuration.
3. Invoke `FixInstall.bat` if the driver startup configuration required correction.
4. Exit without performing the corrective action when no change was required.

**Assessment:** Likely benign Npcap maintenance activity, consistent with the installed Wireshark environment.

The referenced `FixInstall.bat` script was not independently analyzed.

## 6. Intel Scheduled Task Investigation

**Task Name:** `USER_ESRV_SVC_QUEENCREEK`

### 6.1 Execution Chain

The scheduled task launched:

`C:\WINDOWS\System32\Wscript.exe`

With arguments referencing:

`C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.vbs`

Inspection of the VBScript showed that it launched `cmd.exe` to execute `task.bat` with its command window hidden.

The batch file contained a command launching:

`C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.exe`

**Observed Execution Chain:**

Scheduled Task → Wscript.exe → task.vbs → cmd.exe → task.bat → task.exe

This execution chain was consistent with a software-maintenance workflow but warranted verification because script interpreters can also be abused for malicious persistence.

### 6.2 Digital Signature Verification

The final executable was examined using PowerShell's `Get-AuthenticodeSignature` cmdlet.

**Results:**

- Signature Status: Valid
- Signer: Intel Corporation
- Certificate Issuer: Sectigo Public Code Signing CA R36
- Certificate Validity: July 2022 – July 2023

The certificate's expiration date did not cause Windows to report an invalid signature.

**Finding:** The valid Intel Corporation digital signature strongly supported the executable's claimed publisher identity.

### 6.3 Executable Metadata

File version-information fields were queried.

The following fields were blank:

- CompanyName
- FileDescription
- ProductName
- FileVersion

Missing version metadata was documented as an observation rather than evidence of malicious activity.

### 6.4 SHA-256 Hash

**Algorithm:** SHA-256

**File:** `C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.exe`

**Hash:**

`61E4A50800E7A6BF06D74940BDECDCC472A31DD8EA2834F538695B7B3F3E5BF8`

A VirusTotal hash search was performed. The user-facing result indicated that the file had not been reported as malicious.

**Finding:** No malicious reputation finding was reported during the lookup. This does not independently guarantee file safety.

## 7. Scheduled Task Configuration

### 7.1 Trigger

The task was configured with:

- Trigger Type: User logon
- Enabled: True
- Delay: `PT4M` (four minutes)

The delayed logon trigger was consistent with a possible software startup or maintenance operation.

### 7.2 Execution History

**Last Run:** November 2, 2026, 8:17:17 AM

**Last Task Result:** `0`

**Missed Runs:** 0

The result code indicated successful task completion as reported by Windows Task Scheduler.

### 7.3 Execution Privileges

The task principal was configured as:

- UserId: SYSTEM
- LogonType: ServiceAccount
- RunLevel: Highest

The task therefore operated with elevated system privileges.

Although this configuration can be used for legitimate maintenance, it increases the importance of protecting the task's executable and supporting scripts against unauthorized modification.

## 8. File Permission Analysis

Access control lists were examined for:

- `task.exe`
- `task.bat`
- `task.vbs`
- The containing `x64` directory

The inspected files granted FullControl to SYSTEM and Administrators, while ordinary Users were granted ReadAndExecute permissions.

The directory's displayed access rules likewise did not show an obvious ordinary-user Write or Modify grant.

**Finding:** No obvious ordinary-user-writable permissions were identified in the examined access control lists.

This was not an exhaustive effective-permissions or privilege-escalation assessment.

## 9. Indicators and Evidence

| Artifact | Evidence |
|---|---|
| Scheduled Task | USER_ESRV_SVC_QUEENCREEK |
| Script Host | C:\WINDOWS\System32\Wscript.exe |
| VBScript | Intel SUR QUEENCREEK task.vbs |
| Batch File | Intel SUR QUEENCREEK task.bat |
| Executable | Intel SUR QUEENCREEK task.exe |
| Signature | Valid — Intel Corporation |
| Execution Account | SYSTEM |
| Trigger | User logon, four-minute delay |
| Last Result | 0 |
| SHA-256 | 61E4A50800E7A6BF06D74940BDECDCC472A31DD8EA2834F538695B7B3F3E5BF8 |

These artifacts were documented for investigative reference and were not confirmed malicious indicators of compromise.

## 10. Conclusion

**Final Classification: Likely Benign**

The examined Intel scheduled task used a multi-stage script execution chain and operated with SYSTEM privileges. These characteristics warranted investigation but did not independently establish malicious behavior.

The final executable had a valid Intel Corporation digital signature, the reputation lookup did not indicate malicious reports, and the examined file permissions did not reveal obvious ordinary-user modification access.

The Npcap watchdog task was also consistent with legitimate driver-maintenance activity.

No confirmed malicious persistence was identified within the investigated artifacts.

**Limitations:** The investigation did not include reverse engineering, complete runtime behavior analysis, exhaustive scheduled-task coverage, or comprehensive Windows persistence auditing.

## 11. Lessons Learned

This investigation reinforced several practical SOC analyst skills:

- Registry object metadata must not be mistaken for actual startup entries.
- Legitimate software can use scheduled tasks, scripts, and elevated privileges.
- Execution chains should be followed to their final executable.
- Digital signatures and file hashes provide valuable supporting evidence.
- A clean reputation lookup does not guarantee a file is harmless.
- File permissions are especially important when scheduled tasks run as SYSTEM.
- Security conclusions should reflect the strength and limitations of the available evidence.

**Case Status:** Closed — Likely Benign  
**Confirmed Malicious Activity:** None identified
