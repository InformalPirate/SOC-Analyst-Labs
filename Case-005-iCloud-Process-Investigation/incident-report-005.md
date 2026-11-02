# SOC Training Investigation Report — Case 005

| Field | Detail |
|---|---|
| Case | 005 — Unexpected iCloud Background Processes |
| Lab | 13 — Windows Process Triage |
| Environment | Personal Windows workstation |
| Tools | PowerShell, CIM/WMI, Authenticode, Windows Security Event Log |
| Observation period | October 31–November 2, 2026 |
| Classification | Likely benign; launch mechanism unresolved |
| Status | Training investigation completed |

## 1. Executive summary

During a review of running processes, I identified three iCloud-related executables despite believing that iCloud startup had previously been disabled. I examined their executable paths and parent process IDs, checked the reported signer of `secd.exe`, searched several common startup mechanisms, and compared process start times with successful Windows authentication events.

The executables were located within the installed Apple iCloud WindowsApps package directory. The certificate signer shown for `secd.exe` was Apple Inc.; the signature validation **Status** was not preserved in the investigation notes. The three processes started within approximately 30 seconds of one another around 6:14 PM on October 31, shortly after two Event ID 4624, Logon Type 11 events at 6:13:12 PM.

**Assessment:** The evidence is consistent with legitimate iCloud activity occurring near Windows sign-in. No malicious behavior was confirmed in the checks performed. The exact mechanism responsible for process launch remains unknown.

## 2. Trigger and investigation question

**Trigger:** Unexpected iCloud-related processes appeared in a process listing, despite the investigator's recollection of disabling iCloud startup behavior.

**Question:** Are these processes authentic Apple software, and what explains their execution?

## 3. Evidence collected

### 3.1 Process inventory

| Process | PID at observation | Parent PID at observation | Observed path |
|---|---:|---:|---|
| `iCloudDrive.exe` | 9100 | 2860 | Apple iCloud package under `C:\Program Files\WindowsApps\` |
| `iCloudCKKS.exe` | 5956 | 2860 | Same package |
| `secd.exe` | 8932 | 944 | Same package |

The package directory in the observed output was `AppleInc.iCloud_15.10.39.0_x64__nzyj5cx40ttqa\iCloud`. At the time of the parent-process check, PID 2860 was reported as `explorer.exe` and PID 944 as `svchost.exe`. PID reuse is possible, so a current PID lookup alone is not definitive historical parentage.

The initial process listing showed `secd` with approximately **4,352.59 seconds of accumulated CPU time**. This value is not instantaneous CPU utilization and does not independently indicate malicious activity.

### 3.2 Software provenance

An Authenticode inspection of `secd.exe` displayed a signer certificate identifying **Apple Inc., Cupertino, California**. The output's signature **Status** value was not recorded, so this report does not claim that the signature was verified as `Valid`.

### 3.3 Startup and service checks

| Check | Observation | Limitation |
|---|---|---|
| `Win32_Service` search for Apple/iCloud names or paths | No matches | Does not cover all packaged-app activation mechanisms |
| `Win32_StartupCommand` search for Apple/iCloud | No matches | Covers conventional startup entries, not every launch route |
| Scheduled-task search for Apple/iCloud names/actions | No matches | Search terms and exposed task properties limit coverage |
| Service lookup using `secd.exe` PID 8932 | No matches | No service reported that PID at query time; not proof of how it launched |
| `Get-StartApps` | iCloud, iCloud Shared Albums, iCloud Passwords registered | App registration does not prove automatic startup |
| `Get-AppxPackage` | Package reported healthy installation status | Package health does not explain launch behavior |

The application manifest was discussed as a potential source of component registration information, but no manifest output was retained as a case finding.

### 3.4 Timeline correlation

| Local timestamp | Observation |
|---|---|
| October 31, 2026, 6:13:12 PM | Two successful Security Event ID 4624 records, both Logon Type 11 (CachedInteractive) |
| October 31, 2026, approximately 6:14 PM | Three iCloud-related processes started within approximately 30 seconds of each other |

The investigator recalled signing in around this time and not restarting the laptop afterward. The timing supports a sign-in-associated launch hypothesis, but does not identify the precise trigger. Two 4624 records do not necessarily represent two separate human sign-ins.

## 4. Analysis

The executable locations, Apple signer identity, installed application registration, and near-sign-in start times are consistent with ordinary iCloud background activity. The apparent `explorer.exe` and `svchost.exe` parent relationships are plausible in a Windows environment but do not independently establish the launch mechanism.

The absence of matches in conventional startup, service, and scheduled-task queries narrows the possibilities checked; it does **not** prove those mechanisms are universally absent or that the software was launched by a particular alternative mechanism.

No clear indicator of compromise was established by the available observations. The investigation was limited to process metadata, selected configuration searches, and authentication timestamps; it was not a comprehensive malware examination.

## 5. Conclusion and disposition

**Final classification:** Likely benign, with uncertainty.

**Disposition:** Close the educational investigation with the startup mechanism unresolved. In an operational environment, additional telemetry and organizational procedures would determine whether further investigation was warranted.

## 6. Recommended follow-up (not performed)

- Capture the Authenticode `Status` explicitly and confirm the executable path and signer.
- Inspect packaged-app startup/background registrations and relevant activation logs, if available.
- Collect process-creation telemetry during a controlled future sign-in to establish the actual launch chain.
- Avoid disabling software or changing audit policies without understanding the consequences and obtaining appropriate authorization.

## 7. Analyst lessons

- Unexpected behavior is a reason to investigate, not proof of compromise.
- An identified certificate signer is not the same as a verified signature status.
- A registered or healthy app is not necessarily configured to start automatically.
- Parent PIDs and event timestamps are useful context, but correlation alone is not causation.
- Negative query results must be interpreted within the query's scope.
- Explicitly documenting unresolved questions makes a report more credible.

---

*Educational exercise conducted on a personal Windows workstation. Not a production SOC incident or claim of professional work experience.*
