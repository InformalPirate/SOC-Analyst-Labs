# SOC Case 006 — Spotify Network Connection Investigation

## Case Overview

**Case ID:** SOC-006  
**Lab:** 14 — Suspicious Network Connections  
**Category:** Network Connection Analysis  
**Environment:** Windows Workstation  
**Classification:** Likely Benign — No Confirmed Malicious Activity  
**Status:** Closed — Training Investigation

This investigation examined an established outbound TCP connection from a Windows workstation to an unfamiliar external IP address using remote port 4070.

The connection was associated with Spotify. Further investigation identified an expected executable location, a valid digital signature, and a reverse DNS hostname consistent with Google Cloud infrastructure.

The endpoint user confirmed that Spotify was actively playing music during the investigation.

No confirmed malicious activity was identified.

## Investigation Objectives

- Identify the process responsible for an unfamiliar network connection.
- Investigate the destination IP address and remote port.
- Examine the associated executable's location.
- Verify the executable's digital signature.
- Perform reverse DNS analysis.
- Correlate network activity with application usage.
- Determine an appropriate incident classification.

## Tools and Technologies

- Windows PowerShell
- `Get-NetTCPConnection`
- `Get-Process`
- `Get-AuthenticodeSignature`
- `nslookup`
- TCP Connection Analysis
- DNS Investigation

## Key Investigation Findings

### 1. Initial Network Connection

Identified the following established TCP connection:

| Property | Observed Value |
|---|---|
| Local IP | `192.168.0.23` |
| Remote IP | `34.158.255.62` |
| Remote Port | `4070` |
| Process ID | `15792` |
| Protocol | TCP |
| Connection State | Established |

The unfamiliar remote port prompted further investigation.

### 2. Process Identification

Used PowerShell to identify the process associated with PID `15792`.

**Result:** `Spotify.exe`

The endpoint user confirmed that Spotify was running during the investigation.

### 3. Executable Verification

The Spotify executable was located in the expected per-user installation directory:

`%APPDATA%\Spotify\Spotify.exe`

Windows Authenticode verification returned:

- **Signature status:** Valid
- **Signer:** Spotify

The valid signature supported the executable's authenticity at the time of inspection.

### 4. Reverse DNS Investigation

Performed a reverse DNS lookup of:

`34.158.255.62`

**Result:**

`62.255.158.34.bc.googleusercontent.com`

The hostname was consistent with Google Cloud-associated infrastructure.

However, the precise service operating at that destination was not independently verified.

### 5. Connection Verification

A follow-up PowerShell query confirmed that the established connection remained associated with Spotify.

The connection was active while the application was in use.

## Final Assessment

**Classification:** Likely Benign  
**Confirmed Compromise:** No  
**Disposition:** Closed — Training Investigation

The investigated network activity was consistent with legitimate Spotify application usage.

Supporting evidence included:

- A recognizable application process.
- An expected executable installation path.
- A valid digital signature.
- Confirmed active application usage.
- A cloud-associated reverse DNS hostname.
- Consistent results during follow-up connection verification.

The exact purpose of remote port 4070 and the destination service remained unverified.

The investigation did not include packet-content analysis or independent validation of the remote service.

## Skills Demonstrated

- Network connection investigation
- TCP/IP analysis
- Process-to-connection correlation
- PowerShell investigation
- Executable path verification
- Digital signature analysis
- Reverse DNS investigation
- Application activity correlation
- False-positive assessment
- Evidence-based incident classification
- SOC technical documentation

## Full Incident Report

[Read the Full SOC Case 006 Incident Report](incident-report-006.md)

---

*This investigation was conducted as part of a hands-on SOC Analyst cybersecurity training portfolio.*
