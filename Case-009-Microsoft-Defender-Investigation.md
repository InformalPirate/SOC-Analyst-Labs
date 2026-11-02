# SOC Case 009 — Microsoft Defender Configuration and Threat Detection Investigation

**Case ID:** SOC-009  
**Investigation Dates:** November 1–2, 2026  
**Environment:** Windows endpoint  
**Data Source:** Microsoft-Windows-Windows Defender/Operational  
**Tools Used:** Windows PowerShell, Get-WinEvent, Get-MpComputerStatus, Get-MpPreference  
**Severity:** Low  
**Final Classification:** Likely Benign — Routine Security Maintenance  
**Status:** Closed with Residual Uncertainty

---

## 1. Executive Summary

An investigation was conducted into Microsoft Defender Antivirus operational events to identify potential malware detections, unauthorized security configuration changes, and disruptions to antivirus protection.

Analysis identified multiple Event ID 5007 configuration changes, including updates to Defender configuration hashes, user-interface settings, and internal feature-control registry values.

Several configuration-hash changes closely correlated with successful Microsoft Defender security intelligence updates.

Defender's current protection components were enabled, and a scheduled antivirus quick scan completed successfully. No malware detection or remediation events were found in the available Defender Operational log.

Five antivirus exclusions were identified for Blizzard Battle.net and World of Warcraft executables. The endpoint owner confirmed previously installing both applications but could not confirm when or why the exclusions were configured.

The investigation found no confirmed malicious activity. The overall behavior was assessed as likely benign, with some historical configuration changes remaining unexplained.

## 2. Investigation Objectives

- Determine whether Microsoft Defender recorded malware detections.
- Examine configuration-change events for possible security tampering.
- Verify the current status of antivirus protection components.
- Investigate scheduled antivirus scan activity.
- Correlate configuration changes with security intelligence updates.
- Identify and assess configured antivirus exclusions.

## 3. Evidence and Findings

### 3.1 Defender Configuration Changes — Event ID 5007

Nine configuration-change events were identified among the 100 most recent Defender Operational events.

Affected registry settings included:

- `HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash`
- `HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\ToastOrSsoTrigger`
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\Controls\203`
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\Controls\381`

The `WdConfigHash` values changed multiple times.

`ToastOrSsoTrigger` alternated between values `0x0` and `0x1`.

Two feature-control values, `203` and `381`, previously contained `0x1` and displayed blank new values in events recorded on November 1 at 11:18:08 AM.

The exact purpose and security impact of these feature-control changes could not be established from the available evidence.

### 3.2 Current Antivirus Protection Status

The following Microsoft Defender components were verified as enabled:

| Protection Component | Status |
|---|---|
| Antimalware Service | Enabled |
| Antivirus | Enabled |
| Real-Time Protection | Enabled |
| Behavior Monitoring | Enabled |
| IOAV Protection | Enabled |

No Event ID 5000 or 5001 records were found among the 1,000 most recent Defender Operational events.

**Interpretation:** Defender protections were enabled at the time of inspection. Historical protection status could not be conclusively established.

### 3.3 Antivirus Scan Activity

**November 1, 2026 — 12:08:23 AM**

Event ID 1000 recorded a scheduled quick scan starting under `NT AUTHORITY\SYSTEM`.

**November 1, 2026 — 12:19:29 AM**

Event ID 1001 recorded successful completion of the same scan.

Recorded duration: 11 minutes, 6 seconds.

**November 1, 2026 — 10:11:23 PM**

Event IDs 1000 and 1002 recorded another scheduled scan starting and being stopped.

The recorded stop reason was:

> Scheduled scan was skipped because the last successful scan was within the last 7 days

**Interpretation:** The scan stop was explained by Defender's scheduling logic. No evidence indicated malicious interruption.

### 3.4 Security Intelligence Updates — Event ID 2000

Defender recorded successful security intelligence updates.

| Timestamp | Activity |
|---|---|
| Nov 1, 5:19:00 PM | Security intelligence updated to 1.463.79.0 |
| Nov 1, 5:19:01 PM | Defender configuration hash changed |
| Nov 2, 9:33:27 AM | Security intelligence updated to 1.463.84.0 |
| Nov 2, 9:33:29 AM | Defender configuration hash changed |

The updates were incremental (`Delta`) updates executed under `NT AUTHORITY\SYSTEM`.

Defender engine version remained `1.1.26100.4`.

**Interpretation:** The close timing strongly supports an association between these configuration-hash changes and routine security intelligence updates. Direct causation was not independently verified.

### 3.5 Malware Detection and Remediation Events

The available Defender Operational log was searched for:

- Event ID 1116 — Malware detection
- Event ID 1117 — Remediation action
- Event IDs 1118 and 1119 — Additional remediation-related events

No matching events were returned.

**Interpretation:** No malware detections or remediation events were identified in the available log. This does not establish that the endpoint has never experienced malware activity.

### 3.6 Antivirus Exclusions

Five path exclusions were identified:

```text
C:\Program Files (x86)\Blizzard App\Battle.net Launcher.exe
C:\Program Files (x86)\Blizzard App\Battle.net.exe
C:\Program Files (x86)\World of Warcraft\World of Warcraft Launcher.exe
C:\Program Files (x86)\World of Warcraft\Wow-64.exe
C:\Program Files (x86)\World of Warcraft\Wow.exe
```

No process or file-extension exclusions were displayed.

The endpoint owner confirmed personally installing Battle.net and World of Warcraft, but did not recall whether the exclusions were manually configured.

**Interpretation:** The exclusions are consistent with previously installed gaming applications. Their origin, creation date, and necessity remain unverified.

## 4. Investigation Timeline

| Date and Time | Event |
|---|---|
| Nov 1, 12:08 AM | Scheduled Defender quick scan started |
| Nov 1, 12:19 AM | Quick scan completed |
| Nov 1, 11:18 AM | Internal Defender feature-control settings changed |
| Nov 1, 5:19 PM | Security intelligence updated; configuration hash changed |
| Nov 1, 10:11 PM | Scheduled scan skipped due to recent successful scan |
| Nov 2, 9:33 AM | Security intelligence updated; configuration hash changed |
| Nov 2 | Protection status and antivirus exclusions reviewed |

## 5. Risk Assessment

**Severity: Low**

Evidence supporting a benign assessment:

- Current antivirus protections were enabled.
- A scheduled quick scan completed successfully.
- The stopped scan had a documented scheduling explanation.
- Security intelligence updates completed successfully.
- Two configuration-hash changes closely coincided with updates.
- No malware detection events were found.
- Identified exclusions corresponded to software the owner recognized.

Remaining uncertainties:

- The exact purpose of two internal feature-control changes was not established.
- The origin and creation dates of antivirus exclusions were not confirmed.
- Current protection status does not prove uninterrupted historical protection.

## 6. Recommended Actions

1. Retain the relevant Defender Operational logs for future comparison.
2. Review antivirus exclusions periodically and remove those no longer required.
3. Continue monitoring for unexpected protection-state changes and malware detections.
4. Reopen the investigation if new evidence of unauthorized Defender configuration changes appears.

## 7. Final Disposition

**Classification:** Likely Benign — Routine Security Maintenance  
**Severity:** Low  
**Containment Required:** No immediate containment indicated  
**Status:** Closed with Residual Uncertainty

The available evidence did not establish malware infection, successful antivirus evasion, or unauthorized security configuration changes.

The investigated activity was primarily consistent with routine Microsoft Defender operations.

## 8. Analyst Lessons Learned

This investigation demonstrated the importance of:

- Correlating security events by timestamp.
- Reading event messages before assigning severity.
- Distinguishing current protection status from historical security posture.
- Investigating antivirus exclusions rather than assuming they are malicious.
- Avoiding conclusions that exceed the available evidence.
- Documenting uncertainty in professional SOC reports.

**Case Conclusion:** No confirmed security compromise identified.
