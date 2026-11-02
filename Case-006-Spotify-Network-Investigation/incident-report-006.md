# SOC Incident Report 006 — Spotify Network Connection Investigation

**Case ID:** 006  
**Lab:** 14 — Suspicious Network Connections  
**Investigation Type:** Network Connection Analysis  
**Environment:** Windows Workstation  
**Tools Used:** PowerShell, Windows TCP Connection Utilities, DNS Lookup  
**Final Classification:** Likely Benign — No Confirmed Malicious Activity

---

## 1. Executive Summary

An investigation was conducted into an established outbound TCP connection from a Windows workstation to an unfamiliar external IP address using remote port 4070.

The connection was associated with a running Spotify process. Further examination identified an expected Spotify executable location, a valid digital signature, and a reverse DNS hostname associated with Google Cloud infrastructure.

The user confirmed that Spotify was actively playing music during the investigation.

Based on the available evidence, the activity was assessed as likely benign. The exact purpose of the remote endpoint was not independently established.

## 2. Initial Detection

During a review of established TCP connections, the following connection was identified:

| Field | Observed Value |
|---|---|
| Local IP | 192.168.0.23 |
| Remote IP | 34.158.255.62 |
| Remote Port | 4070 |
| Process ID | 15792 |
| Protocol | TCP |
| Connection State | Established |

The unfamiliar remote port was selected for further investigation.

## 3. Investigation and Evidence

### 3.1 Process Identification

PowerShell was used to identify the process associated with PID 15792.

```powershell
Get-Process -Id 15792 | Select-Object ProcessName,Id,Path
```

**Result:** The process was identified as `Spotify.exe`.

The user confirmed that Spotify was running during the investigation.

### 3.2 Executable Path Analysis

The executable was located at:

```text
C:\Users\<username>\AppData\Roaming\Spotify\Spotify.exe
```

This location is consistent with a standard per-user Spotify installation.

The location alone does not establish that an executable is trustworthy.

### 3.3 Digital Signature Verification

The following command was used:

```powershell
Get-AuthenticodeSignature "$env:APPDATA\Spotify\Spotify.exe" |
    Select-Object Status, @{Name='Publisher';Expression={$_.SignerCertificate.Subject}}
```

**Observed results:**

- Signature status: `Valid`
- Signer: Spotify
- Signer location: Stockholm, Sweden

The valid digital signature supported the authenticity and integrity of the executable at the time of inspection.

### 3.4 Reverse DNS Investigation

The external IP address was investigated using:

```powershell
nslookup 34.158.255.62
```

**Result:**

```text
Name:    62.255.158.34.bc.googleusercontent.com
Address: 34.158.255.62
```

The reverse DNS hostname was consistent with Google Cloud-associated infrastructure.

This did not establish which service operated the endpoint or prove that the destination was safe.

### 3.5 Connection Verification

A follow-up PowerShell query checked the remote connection and its owning process.

```powershell
Get-NetTCPConnection -RemoteAddress 34.158.255.62 |
    Select-Object State,RemotePort,OwningProcess,
    @{Name="ProcessName";Expression={
        (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    }}
```

**Observed results:**

- Process name: Spotify
- Connection state: Established

The connection remained active while Spotify was being used.

## 4. Analysis

The following evidence supported a likely benign assessment:

1. The network connection was associated with Spotify.
2. The executable was located in an expected installation directory.
3. Windows reported a valid digital signature.
4. The user confirmed active Spotify usage.
5. The reverse DNS result was consistent with cloud-hosted infrastructure.
6. A follow-up check continued to associate the established connection with Spotify.

No evidence collected during this investigation confirmed malicious activity.

## 5. Limitations

The investigation did not independently verify:

- The exact service hosted at the remote IP address.
- The specific purpose of port 4070 in this connection.
- The contents of the encrypted or application-level network traffic.
- Whether the destination was exclusively used for legitimate Spotify services.

The available findings support a likely benign classification but do not establish that the connection was conclusively safe.

## 6. Final Assessment

**Classification: Likely Benign**

**Confirmed compromise:** No

**Reasoning:** Multiple independent observations were consistent with expected Spotify application activity. No confirmed indicators of malicious behavior were identified in the evidence collected.

**Disposition:** Investigation documented and closed for training purposes, with unresolved endpoint attribution noted.

## 7. Lessons Learned

- An unfamiliar port does not automatically indicate malicious activity.
- Identifying the process behind a connection provides important investigative context.
- Executable paths and digital signatures are useful evidence but must be evaluated alongside behavior.
- Cloud-hosted infrastructure can support both legitimate and malicious services.
- Reverse DNS provides clues about infrastructure, not proof of safety.
- Good incident reports distinguish confirmed facts from assumptions and unresolved questions.

---

**Investigation Type:** Personal hands-on cybersecurity training  
**Portfolio:** SOC-Analyst-Labs
