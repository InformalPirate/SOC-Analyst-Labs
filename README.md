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


## 🎯 Career Goals

My goal is to become an entry-level SOC Analyst and continue developing skills in threat detection, incident response, Windows security, network analysis, and cybersecurity fundamentals.

This portfolio represents personal hands-on training and will grow as I complete additional investigations and labs.

---

*Learning through investigation. Documenting the evidence. Improving one lab at a time.*
