# 🛡️ SOC Analyst | Cybersecurity Portfolio

Welcome to my cybersecurity portfolio!

I'm an aspiring Security Operations Center (SOC) Analyst developing practical cybersecurity skills through hands-on investigations, Windows security analysis, and technical labs.

This repository documents my learning journey, investigative methods, and progress toward a career in cybersecurity.

## 🔍 Technical Skills I'm Developing

- **Security Monitoring:** Reviewing Windows security events and identifying suspicious activity.
- **Incident Investigation:** Analyzing alerts, developing hypotheses, and documenting findings.
- **PowerShell:** Investigating Windows processes, services, and system activity.
- **Windows Event Logs:** Examining authentication events and correlating timestamps.
- **Network Analysis:** Learning packet analysis using Wireshark.
- **Technical Documentation:** Writing structured security investigation reports.

## 📂 Featured Investigations

### Case 004 — Windows Failed Login Investigation

Investigated 20 failed Windows authentication events using PowerShell and Windows Security Event Logs. Findings were inconclusive, with no confirmed compromise.

[View Case 004 Investigation](Case-004-Windows-Failed-Logins/incident-report-004.md)

### Case 005 — Unexpected iCloud Background Processes

Investigated unexpected Apple iCloud processes running on a Windows workstation.

**Investigation included:**
- Process identification and parent-process analysis
- Executable path and software-signing inspection
- Startup mechanism investigation
- Windows authentication event correlation
- Evidence-based incident classification

**Conclusion:** Likely benign background activity. The exact process launch mechanism remained unresolved, and no malicious activity was confirmed.

[View Case 005 Investigation](Case-005-iCloud-Process-Investigation/README.md)

### Case 006 — Spotify Network Connection Investigation

Investigated an unfamiliar outbound TCP connection using PowerShell, process identification, digital signature verification, and reverse DNS analysis.

**Conclusion:** Likely benign Spotify network activity. No confirmed malicious activity; the remote endpoint's specific purpose remained unverified.

[View Case 006 Investigation](Case-006-Spotify-Network-Investigation/incident-report-006.md)

### Case 007 — PowerShell Activity Investigation

Investigated PowerShell Event ID 4104 script block activity using Windows Event Logs, process identification, and parent-child process analysis.

**Conclusion:** Likely benign Windows networking-management activity. No confirmed malicious activity; the exact initiating command remains unverified.

[View Case 007 Investigation](Case-007-PowerShell-Activity-Investigation/incident-report-007.md)

### Case 008 — Windows Persistence Investigation

Investigated Windows startup registry entries and scheduled tasks using PowerShell, execution-chain analysis, digital signature verification, SHA-256 hashing, and file permission analysis.

**Conclusion:** Likely benign Intel and Npcap scheduled-task activity. No confirmed malicious persistence identified.

[View Case 008 Investigation](Case-008-Windows-Persistence-Investigation/incident-report-008.md)

### SOC Case 009 — Microsoft Defender Configuration and Threat Detection Investigation

**Severity:** Low  
**Classification:** Likely Benign  
**Status:** Closed with Residual Uncertainty

Investigated Microsoft Defender configuration-change events, antivirus scan activity, security intelligence updates, malware detection logs, and antivirus exclusions using Windows PowerShell.

**Key Findings:**
- Verified active Defender protection components.
- Correlated configuration-hash changes with security intelligence updates.
- Confirmed successful scheduled antivirus scanning.
- Found no recorded malware detection events in the available Defender Operational log.
- Identified five antivirus exclusions associated with previously installed gaming applications.
- Documented unresolved configuration changes without assuming malicious activity.

**Skills Demonstrated:** Windows Event Log Analysis, Endpoint Security Monitoring, Threat Investigation, Event Correlation, PowerShell, Incident Documentation.

[View Case 009](Case-009-Microsoft-Defender-Investigation/README.md)

### SOC Case 010 — Network Connection & Process Investigation

**Severity:** Low  
**Classification:** Likely Benign / Security Configuration Finding  
**Status:** Closed — Hardening Recommended

Investigated active Windows TCP connections and correlated network activity with running processes using PowerShell. Analyzed Spotify's outbound connections, verified its digital signature, examined remote infrastructure through reverse DNS, and audited Windows Firewall inbound permissions.

**Key Findings:**
- Identified network activity associated with Chrome, Spotify, and Apple iCloud.
- Verified Spotify's valid digital signature.
- Investigated an established connection to `34.158.255.62:4070`.
- Identified two Spotify listening ports.
- Discovered broad inbound TCP and UDP firewall allow rules applying to Public and Private networks.
- Found no established TCP connection to Spotify's local port 57621 during the final check.
- Recommended reviewing and restricting unnecessary inbound firewall permissions.

**Skills Demonstrated:** Network Traffic Analysis, PowerShell, Process Investigation, Digital Signature Verification, DNS Analysis, Windows Firewall Auditing, Security Hardening, Incident Reporting.

[View Case 010](Case-010-Network-Connection-Investigation/README.md)

### SOC Case 011 — Suspicious PowerShell Activity Investigation

**Severity:** Low / Informational  
**Classification:** Likely Benign  
**Status:** Closed

Investigated suspicious PowerShell Event ID 4104 warnings, reconstructed script blocks, and correlated historical activity with available Windows event logs.

**Key Findings:**
- Identified PowerShell script blocks consistent with Windows Network Diagnostics.
- Investigated suspicious keywords including `Invoke-Expression`.
- Identified self-matching detections from authorized security investigations.
- Documented historical log-retention limitations that prevented complete process attribution.
- Found no confirmed malicious PowerShell execution in the reviewed evidence.

**Skills Demonstrated:** PowerShell Threat Hunting, Windows Event Logs, Script Block Analysis, Process Correlation, False-Positive Investigation.

[View Case 011 Incident Report](Case-011-Suspicious-PowerShell-Investigation/incident-report.md)

---
### SOC Case 012 — Windows Scheduled Task Persistence Investigation

**Severity:** Low  
**Classification:** Likely Benign — Orphaned Scheduled Task  
**Status:** Investigation Complete — Remediation Recommended

Investigated 258 Windows scheduled tasks for suspicious execution paths, elevated privileges, and potential persistence mechanisms.

**Key Findings:**
- Identified an Intel Update Manager task configured to run daily as SYSTEM with highest privileges.
- Confirmed the referenced executable and installation directory were missing.
- Correlated execution error `0x80070002` with the missing executable.
- Identified disabled Task Scheduler Operational logging as an investigation visibility limitation.
- Found no additional missing executables in the targeted scan.

**Skills Demonstrated:** Scheduled Task Analysis, Persistence Investigation, PowerShell, Windows Error Analysis, Security Logging, Incident Reporting.

[View Case 012 Investigation](Case-012-Scheduled-Task-Persistence/README.md) | [Full Incident Report](Case-012-Scheduled-Task-Persistence/incident-report.md)

---

## Career Goals
My goal is to become an entry-level SOC Analyst and continue developing skills in threat detection, incident response, Windows security, network analysis, and cybersecurity fundamentals.


This portfolio represents personal hands-on training and will grow as I complete additional investigations and labs.

---

*Learning through investigation. Documenting the evidence. Improving one lab at a time.*
