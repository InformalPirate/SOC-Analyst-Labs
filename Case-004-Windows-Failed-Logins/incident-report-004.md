SOC Incident Report 004 — Windows Authentication Failures
Case ID: SOC-004
Lab: 12 — Detecting Suspicious Windows Login Attempts
Investigation Date: November 1, 2026
Analyst: SOC Analyst Trainee
Environment: Windows Workstation
Tools Used: Windows PowerShell, Windows Event Logs, Windows Audit Policy Utility (auditpol)
Status: Investigation Completed
Classification: Suspected Local Authentication Issue
Disposition: Inconclusive — No Confirmed Compromise
________________________________________
1. Executive Summary
An investigation was conducted into multiple failed Windows authentication attempts recorded in the Security event log.
A total of 20 failed authentication events (Event ID 4625) were identified during the seven-day search window. The largest concentration occurred on October 26, 2026, when 13 failed logon attempts were recorded within approximately 19 minutes.
The investigated events were associated with the Windows Service Host executable (svchost.exe). The event examined in detail showed an interactive logon request, the Local System security context, and the loopback IP address 127.0.0.1.
No confirmed evidence of unauthorized remote access or malicious activity was identified in the examined records.
The exact Windows service responsible for the authentication failures could not be determined from the available evidence.
2. Investigation Objectives
•	Identify failed Windows authentication attempts.
•	Determine whether failures occurred in suspicious patterns.
•	Examine the processes associated with failed logons.
•	Investigate potential evidence of brute-force activity.
•	Correlate authentication events with process creation logs.
•	Document findings and determine an appropriate disposition.
3. Initial Detection
Windows Event ID: 4625
Event Description: An account failed to log on.
Log Source: Windows Security Event Log
A PowerShell query identified 20 failed authentication events across the following dates:
Date and Hour	Failed Attempts
October 26, 2026 — 1 PM	13
October 26, 2026 — 2 PM	2
October 26, 2026 — 9 PM	1
October 27, 2026 — 11 AM	2
October 28, 2026 — 12 AM	1
October 28, 2026 — 1 AM	1
Total	20
The highest concentration occurred on October 26 between 1:36:53 PM and 1:55:26 PM.
4. Technical Findings
4.1 Authentication Event Details
An Event ID 4625 entry recorded at 1:54:35 PM on October 26 contained the following information:
Field	Recorded Value
Event ID	4625
Logon Type	2 — Interactive
Requesting Security ID	S-1-5-18 (Local System)
Caller Process	C:\Windows\System32\svchost.exe
Caller Process ID	0x700 (1792 decimal)
Source Network Address	127.0.0.1
Failure Status	0xC000006D
Failure Substatus	0xC000006A
Authentication Package	Negotiate
Interpretation:
The event indicates a failed interactive authentication request associated with a local Windows service-host process.
The loopback IP address indicates local network context rather than an identified external source.
The failure substatus is consistent with an incorrect password.
The event did not identify the specific account whose authentication failed.
4.2 Failed Login Pattern
The 13 failures occurred in three groups:
Time Range	Failed Attempts
1:36–1:39 PM	6
1:48–1:49 PM	2
1:53–1:55 PM	5
All 13 events identified svchost.exe as the caller executable.
The repeated failures warranted investigation. However, the available evidence did not establish a password-guessing attack.
4.3 Process Creation Investigation
Windows Security Event ID 4688 was examined to identify historical process creation activity associated with process ID 0x700.
No matching process creation events were found during the investigated period.
The oldest retained Event ID 4688 record was dated October 26, 2026, at 1:46:38 PM, after the first failed authentication attempts.
The current Windows audit policy reported:
Process Creation: No Auditing
Historical Event ID 4688 records were nevertheless present, indicating that process creation auditing had been active at some point.
Limitation: The current audit configuration does not establish what was enabled during the original incident. The missing process creation records prevented identification of the responsible Windows service.
4.4 Subsequent Authentication Activity
An additional search for Event ID 4625 from October 29, 2026, onward returned no matching events.
No additional failed authentication events were identified in the retained Security log for that period.
This finding does not establish that all authentication activity was successful or that the system was free of compromise.
5. PowerShell Commands Used
Query failed authentication events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -MaxEvents 10
Group failed logins by hour
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddDays(-7)
} |
Group-Object {
    $_.TimeCreated.ToString('yyyy-MM-dd HH:00')
} |
Select-Object Name, Count
Check process creation audit policy
auditpol /get /subcategory:"Process Creation"
Examine historical process creation events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} -MaxEvents 5
6. Threat Assessment
Suspected Cause: Local Windows authentication issue.
Evidence Supporting This Assessment:
•	Failed authentication events were associated with svchost.exe.
•	The examined event used the Local System security context.
•	The source network address was the local loopback address.
•	No external source IP address was identified in the examined event.
•	No matching failed-login events were found after October 28.
Unresolved Questions:
•	Which Windows service initiated the authentication requests?
•	What caused the incorrect credentials?
•	Were the failures caused by application configuration, cached credentials, or another condition?
•	Would additional endpoint telemetry identify the original process and service?
Assessment: The evidence is consistent with a possible local authentication issue. The available logs do not establish the root cause or demonstrate malicious activity.
7. Conclusion and Disposition
The investigation identified a concentration of failed Windows authentication events associated with a Windows service-host process.
Although repeated authentication failures can indicate password-guessing attempts, the examined evidence did not establish an external brute-force attack.
Historical process creation evidence was insufficient to identify the responsible service.
Final Disposition: Training investigation closed as inconclusive, with no confirmed compromise.
In a production SOC, additional investigation or escalation would depend on the organization's procedures, available endpoint telemetry, and related alerts.
8. Skills Demonstrated
•	Windows Security Event Log analysis
•	Event ID 4625 investigation
•	Failed authentication pattern recognition
•	PowerShell-based log querying
•	Windows process identification
•	Event ID 4688 correlation
•	Windows audit policy inspection
•	Security event interpretation
•	Evidence-based incident documentation
•	Recognition of forensic visibility limitations
________________________________________
9. Lessons Learned
This investigation demonstrated that repeated authentication failures are not sufficient by themselves to confirm malicious activity.
A security analyst must evaluate the source, process context, authentication type, timing, and supporting telemetry before drawing conclusions.
The investigation also highlighted the importance of log retention, audit policy configuration, and documenting evidence gaps.
Lab Type: Personal cybersecurity training exercise using local Windows event logs.
Disclaimer: This report documents an educational investigation. It does not represent a production SOC incident or professional employment experience.
