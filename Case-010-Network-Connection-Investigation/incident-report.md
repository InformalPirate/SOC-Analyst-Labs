# SOC Case 010 — Network Connection & Process Investigation

**Case ID:** SOC-010  
**Investigation Date:** November 2, 2026  
**Environment:** Windows endpoint  
**Severity:** Low  
**Classification:** Likely Benign Application Activity / Security Configuration Finding  
**Status:** Investigation Closed — Hardening Recommended  
**Tools:** Windows PowerShell, Windows Defender Firewall, TCP Connection Analysis, Authenticode Signature Verification, DNS Analysis

---

## 1. Executive Summary

A network connection and process investigation was conducted on a Windows endpoint to examine established TCP connections, identify the applications responsible, and assess potentially unnecessary inbound network exposure.

Initial analysis identified approximately 30 established TCP connections, primarily using HTTPS port 443.

Several processes were investigated, including Google Chrome, Spotify, and Apple iCloud's APSDaemon.

Further analysis focused on a Spotify process maintaining an established outbound connection to `34.158.255.62:4070`.

The Spotify executable possessed a valid digital signature identifying Spotify AB as its publisher. Reverse DNS analysis returned a hostname consistent with Google Cloud infrastructure.

The investigation also identified two Spotify listening sockets and two enabled Windows Firewall inbound allow rules covering TCP and UDP traffic on both Private and Public network profiles.

The firewall rules allowed any local or remote port and any remote address, subject to their application-specific matching conditions and other firewall policy.

No established TCP connection to Spotify's local listening port 57621 was observed during the final check.

**Final assessment:** No confirmed malicious activity or unauthorized access was identified. A potentially overpermissive application firewall configuration was documented for security-hardening review.

## 2. Investigation Objectives

- Enumerate established TCP connections.
- Identify the processes responsible for network activity.
- Investigate an unfamiliar remote port.
- Verify the associated executable's digital signature.
- Examine remote infrastructure using reverse DNS.
- Identify local listening ports.
- Review application-specific Windows Firewall rules.
- Determine whether an established inbound connection was present.
- Document findings and recommend appropriate security improvements.

## 3. Initial Network Connection Analysis

The investigation began with the following PowerShell command:

```powershell
Get-NetTCPConnection -State Established |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
Format-Table -AutoSize
```

Approximately 30 established TCP connections were observed.

The majority used remote port 443, consistent with HTTPS traffic.

Other observed remote ports included:

| Remote Port | Observation |
|---|---|
| 443 | Commonly used for HTTPS |
| 5228 | Commonly associated with Google services |
| 5223 | Commonly associated with Apple push notification services |
| 4070 | Selected for additional investigation |

The presence of an unfamiliar port was treated as an investigation lead, not evidence of malicious activity.

## 4. Process Identification

PowerShell process enumeration linked selected connections to the following processes:

| PID | Process | Executable |
|---|---|---|
| 8688 | APSDaemon | Apple iCloud installation |
| 11744 | chrome | Google Chrome installation |
| 8596 | Spotify | Spotify installation |
| 15792 | Spotify | Spotify installation |

The Spotify executable path was:

```text
C:\Users\Chris\AppData\Roaming\Spotify\Spotify.exe
```

The Apple process was located within the Microsoft Store iCloud application installation, and Chrome was located in its standard Program Files directory.

**Assessment:** The process names and executable locations were consistent with recognizable applications. Further verification was performed on Spotify because of its connection to remote port 4070.

## 5. Spotify Digital Signature Verification

The executable was examined using:

```powershell
Get-AuthenticodeSignature "C:\Users\Chris\AppData\Roaming\Spotify\Spotify.exe" |
Select-Object Status, SignerCertificate |
Format-List
```

Results:

| Property | Value |
|---|---|
| Signature status | Valid |
| Publisher | Spotify AB |
| Certificate issuer | DigiCert |
| Certificate validity start | September 10, 2026 |
| Certificate validity end | October 6, 2027 |

**Assessment:** The executable's valid signature supported its authenticity and integrity under Windows signature validation. A valid signature does not independently establish that every network connection made by the application is safe.

## 6. Remote IP and DNS Investigation

The Spotify process maintained an established connection to:

```text
34.158.255.62:4070
```

A reverse DNS lookup returned:

```text
62.255.158.34.bc.googleusercontent.com
```

The hostname was consistent with Google Cloud infrastructure.

**Assessment:** The connection was compatible with a legitimate application's use of cloud infrastructure, but the precise service behind port 4070 and its relationship to Spotify were not independently verified.

## 7. Spotify Network Socket Analysis

The investigated Spotify process, PID 15792, had the following established remote connections during a subsequent check:

| Remote Address | Remote Port | State |
|---|---|---|
| `2600:1901:1:292::` | 443 | Established |
| `34.158.255.62` | 4070 | Established |

Two local listening sockets were also identified:

| Local Address | Local Port | State |
|---|---|---|
| `0.0.0.0` | 57621 | Listen |
| `127.0.0.1` | 7768 | Listen |

The loopback listener on port 7768 was restricted to the local host.

The listener on port 57621 was bound to all local IPv4 interfaces, making it relevant to the firewall exposure assessment.

**Assessment:** Listening on all local IPv4 interfaces does not independently establish internet reachability.

## 8. Windows Firewall Investigation

Application-specific firewall analysis identified two enabled inbound allow rules associated with Spotify.

| Property | Rule 1 | Rule 2 |
|---|---|---|
| Display name | spotify.exe | spotify.exe |
| Enabled | True | True |
| Direction | Inbound | Inbound |
| Action | Allow | Allow |
| Protocol | TCP | UDP |
| Local port | Any | Any |
| Remote port | Any | Any |
| Remote address | Any | Any |
| Network profiles | Private, Public | Private, Public |
| Policy source | Local | Local |
| Primary status | OK | OK |

Both rules referenced the Spotify executable.

The endpoint's active network profile was Public, with internet connectivity over IPv4 and IPv6.

The Public Windows Firewall profile was enabled.

Its default inbound and outbound action properties were reported as `NotConfigured`, which did not establish that unsolicited inbound traffic was generally permitted.

**Assessment:** The Spotify rules were broad in protocol-specific port scope, remote-address scope, and network-profile coverage. They represented a potential least-privilege configuration concern, although other rule conditions and network controls were not exhaustively evaluated.

## 9. Inbound Connection Verification

A final PowerShell query checked for established TCP connections to Spotify's local listening port 57621:

```powershell
Get-NetTCPConnection -LocalPort 57621 -State Established -ErrorAction SilentlyContinue |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State |
Format-Table -AutoSize
```

No results were returned.

**Assessment:** No established TCP connections to local port 57621 were observed at the time of the check.

This result does not establish that the port was unreachable, that no previous connections occurred, or that no UDP traffic was present.

## 10. Risk Assessment

**Severity: Low**

### Evidence supporting a benign assessment

- Investigated processes corresponded to recognizable applications.
- Spotify's executable had a valid digital signature.
- The investigated remote IP had a reverse DNS hostname consistent with cloud infrastructure.
- No established TCP connection to Spotify's local port 57621 was observed during the final check.
- No evidence of malicious execution or unauthorized access was identified.

### Security configuration concern

Two enabled Spotify inbound firewall rules permitted TCP and UDP traffic across all ports and remote addresses on both Private and Public network profiles.

The rules were application-specific, but their scope may exceed the application's operational requirements.

### Investigation limitations

- The exact purpose of Spotify's remote port 4070 was not independently verified.
- No external reachability test was conducted.
- No packet capture or historical connection telemetry was analyzed.
- The necessity of Spotify's inbound firewall exceptions was not established.
- The investigation did not prove that the endpoint had never received unauthorized connections.

## 11. Recommended Remediation and Hardening

1. Review whether Spotify requires inbound TCP and UDP connectivity for the user's intended features.
2. If inbound access is unnecessary, consider disabling the Spotify-specific inbound allow rules after evaluating potential functionality impact.
3. If inbound access is required, consider restricting the rules to appropriate network profiles, ports, and remote address ranges where feasible.
4. Maintain Windows Firewall protection on Public networks.
5. Continue monitoring unexpected listening sockets and outbound network connections.
6. Document any approved firewall changes and verify application functionality afterward.

**Remediation status:** Recommended only. No firewall configuration changes were performed during this investigation.

## 12. Final Disposition

**Classification:** Likely Benign Application Activity / Security Configuration Finding  
**Severity:** Low  
**Confirmed Compromise:** No  
**Immediate Containment Required:** Not indicated by available evidence  
**Status:** Investigation Closed — Hardening Recommended

The investigated network activity was broadly consistent with legitimate application behavior.

No confirmed malicious activity was identified.

The principal security finding was a potentially overpermissive set of Spotify inbound firewall rules.

The case was closed with a recommendation to review and, where appropriate, reduce unnecessary inbound permissions.

## 13. Analyst Lessons Learned

This investigation demonstrated practical experience in:

- TCP connection enumeration.
- Network-to-process correlation.
- Process ID investigation.
- Digital signature verification.
- Reverse DNS analysis.
- Local listening socket analysis.
- Windows Firewall rule auditing.
- Network profile assessment.
- Least-privilege security principles.
- Evidence-based incident classification.
- Professional SOC documentation.

**Case Conclusion:** No confirmed compromise. Potential firewall-hardening opportunity identified.
