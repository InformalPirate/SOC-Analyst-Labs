# SOC Case 010 — Network Connection & Process Investigation

## Case Overview

**Case ID:** SOC-010  
**Investigation Date:** November 2, 2026  
**Environment:** Windows Endpoint  
**Severity:** Low  
**Classification:** Likely Benign Application Activity / Security Configuration Finding  
**Status:** Investigation Closed — Hardening Recommended

This investigation examined active TCP connections, associated Windows processes, executable authenticity, and inbound firewall configurations to identify potentially suspicious network activity or unnecessary network exposure.

The investigation focused on an unfamiliar Spotify network connection and identified potentially overpermissive Windows Firewall rules.

No confirmed malicious activity or unauthorized access was identified.

## Investigation Objectives

- Identify established TCP connections and associated processes.
- Investigate unfamiliar remote ports and IP addresses.
- Verify executable authenticity using digital signatures.
- Analyze local listening sockets.
- Review Windows Firewall inbound rules.
- Assess potential network exposure.
- Document findings and recommend appropriate security improvements.

## Tools and Technologies

- Windows PowerShell
- `Get-NetTCPConnection`
- `Get-Process`
- `Get-AuthenticodeSignature`
- DNS and reverse DNS analysis
- Windows Defender Firewall
- TCP connection analysis

## Key Investigation Findings

### 1. Network Connection Analysis

Identified approximately 30 established TCP connections, primarily using HTTPS port 443.

Investigated network activity associated with Google Chrome, Spotify, and Apple iCloud.

### 2. Suspicious-Port Investigation

Examined a Spotify process maintaining an established outbound connection to:

`34.158.255.62:4070`

Reverse DNS returned a hostname consistent with Google Cloud infrastructure.

The precise purpose of the connection was not independently established.

### 3. Executable Verification

Verified the Spotify executable using Windows Authenticode signature analysis.

**Results:**
- Signature status: Valid
- Publisher: Spotify AB
- Certificate issuer: DigiCert

The valid signature supported the executable's authenticity but did not independently establish that all associated network activity was safe.

### 4. Local Listening Ports

Identified two Spotify listening sockets:

| Local Address | Port | State |
|---|---|---|
| `0.0.0.0` | 57621 | Listening |
| `127.0.0.1` | 7768 | Listening |

The listener bound to all IPv4 interfaces was selected for further firewall analysis.

### 5. Windows Firewall Security Finding

Identified two enabled Spotify inbound allow rules:

- TCP inbound allow rule
- UDP inbound allow rule
- All local and remote ports permitted
- Any remote address permitted
- Both Private and Public network profiles included

These application-specific rules represented a potential least-privilege configuration concern.

No established TCP connection to local port 57621 was observed during the final check.

## Risk Assessment

**Severity: Low**

The investigated network activity was broadly consistent with legitimate application behavior.

However, the scope of Spotify's inbound firewall permissions warranted additional review.

**Investigation limitations:**
- No external port-reachability test was performed.
- No historical packet capture was analyzed.
- The necessity of Spotify's inbound rules was not verified.
- No established inbound TCP connection was observed during the final check, but historical access could not be ruled out.

## Recommended Security Improvements

1. Review whether Spotify requires inbound network access.
2. Consider disabling unnecessary inbound firewall exceptions after checking application requirements.
3. Restrict required rules to appropriate ports, addresses, and network profiles where feasible.
4. Continue monitoring unexpected listening sockets and network connections.
5. Document and verify any future firewall configuration changes.

**Remediation status:** Recommendations documented; no firewall changes performed.

## Final Assessment

**Classification:** Likely Benign Application Activity / Security Configuration Finding  
**Confirmed Compromise:** No  
**Immediate Containment:** Not indicated  
**Status:** Closed — Hardening Recommended

No confirmed malicious activity was identified.

The primary finding was a potentially overpermissive set of Spotify inbound firewall rules.

## Skills Demonstrated

- Network connection investigation
- TCP/IP analysis
- Process-to-connection correlation
- Digital signature verification
- Reverse DNS investigation
- Windows Firewall auditing
- Network exposure assessment
- Least-privilege security analysis
- Incident documentation
- Evidence-based risk assessment

## Full Incident Report

[Read the Full SOC Case 010 Incident Report](incident-report.md)

---

*This investigation was conducted as part of a hands-on SOC Analyst cybersecurity training portfolio.*
