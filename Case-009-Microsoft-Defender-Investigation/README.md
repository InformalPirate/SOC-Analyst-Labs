# SOC Case 009 — Microsoft Defender Configuration and Threat Detection Investigation

## Case Overview

**Case ID:** SOC-009  
**Investigation Dates:** November 1–2, 2026  
**Severity:** Low  
**Classification:** Likely Benign — Routine Security Maintenance  
**Status:** Closed with Residual Uncertainty

This investigation examined Microsoft Defender Antivirus activity on a Windows endpoint to identify potential malware detections, suspicious configuration changes, and possible interference with antivirus protection.

The investigation found activity primarily consistent with routine security maintenance. No confirmed malicious activity was identified, although several historical configuration changes remained unexplained.

## Tools and Technologies

- Windows PowerShell
- Windows Event Viewer
- `Get-WinEvent`
- `Get-MpComputerStatus`
- `Get-MpPreference`
- Microsoft Defender Operational Logs

## Investigation Highlights

### 1. Defender Configuration Changes

Identified nine Event ID 5007 configuration-change records among the 100 most recent Defender Operational events.

Some configuration-hash changes closely correlated with successful security intelligence updates.

Other internal feature-control changes could not be fully explained.

### 2. Antivirus Protection Status

Verified that the following protections were enabled at the time of inspection:

- Real-time protection
- Behavior monitoring
- Antivirus protection
- Antimalware service
- IOAV protection

### 3. Scheduled Antivirus Scans

Confirmed that a scheduled quick scan completed successfully.

Investigated a separate stopped scan and determined that Defender recorded a scheduling-related reason rather than evidence of malicious interruption.

### 4. Malware Detection Investigation

Searched the available Defender Operational log for malware detection and remediation events.

No matching events were identified.

This finding does not prove that the endpoint has never experienced malware activity.

### 5. Antivirus Exclusions

Identified five antivirus path exclusions associated with Blizzard Battle.net and World of Warcraft.

The software was recognized by the endpoint owner, but the origin and necessity of the exclusions remained unverified.

## Key Windows Event IDs

| Event ID | Description |
|---|---|
| 5007 | Defender configuration changed |
| 2000 | Security intelligence updated |
| 1000 | Antivirus scan started |
| 1001 | Antivirus scan completed |
| 1002 | Antivirus scan stopped |
| 1116 | Malware detection |
| 1117 | Malware remediation action |

## Final Assessment

**Classification: Likely Benign**

The reviewed evidence was primarily consistent with normal Microsoft Defender operations.

No confirmed malware infection, unauthorized configuration change, or antivirus evasion was established.

**Residual uncertainty:** The origins of certain configuration changes and antivirus exclusions could not be independently verified.

## Skills Demonstrated

- Endpoint security monitoring
- Windows Event Log analysis
- Microsoft Defender investigation
- Security event correlation
- Antivirus configuration auditing
- Threat detection analysis
- False-positive assessment
- Evidence-based incident documentation

## Full Incident Report

For the complete investigation, including technical evidence, timestamps, risk assessment, limitations, and recommendations:

[Read the Full SOC Case 009 Incident Report](incident-report.md)

---

*This investigation was conducted as part of a hands-on SOC Analyst cybersecurity training portfolio.*
