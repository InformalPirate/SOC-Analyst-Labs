# Case 005 — Unexpected iCloud Background Processes

**Lab 13 | Windows Process Triage | Personal SOC Analyst Training**

## Scenario

While reviewing active Windows processes, I noticed Apple iCloud components running even though I believed I had disabled iCloud at startup. I investigated their paths, process relationships, software-signing information, startup mechanisms, and timing relative to Windows authentication events.

## Outcome

**Assessment:** Likely benign iCloud background activity. The processes started shortly after a successful Windows sign-in, but the exact activation mechanism was not established. No malicious activity was confirmed within the evidence reviewed.

## Files

- [Investigation report](incident-report-005.md) — findings, timeline, assessment, and limitations
- [PowerShell investigation script](investigation-commands.ps1) — reusable read-only commands
- [Lessons learned](lessons-learned.md) — analytical skills and next steps

## Skills demonstrated

Windows process enumeration; PID and parent PID analysis; executable path review; Authenticode signer inspection; startup mechanism triage; Windows Security Event ID 4624 and Logon Type 11; timeline correlation; evidence-based reporting.

## Reproduction

Run `investigation-commands.ps1` in PowerShell on a Windows machine. Access to Security events may require an elevated session. The script does not change system settings and uses dynamic process IDs rather than assuming the historical PIDs remain valid. Some queries may return no results depending on the machine and audit settings.

## Ethics and scope

This is a personal training investigation, not a production SOC incident. Process names, paths, and authentication events reflect one workstation at one point in time. Findings are not proof of malware absence. Do not publish raw event logs or screenshots containing usernames, device identifiers, account data, or other sensitive information without reviewing and sanitizing them.
