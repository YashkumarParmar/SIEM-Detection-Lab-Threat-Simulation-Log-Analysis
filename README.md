# SIEM-Detection-Lab-Threat-Simulation-Log-Analysis
## 🎯 Project Title & Brief Overview

> Built a cybersecurity lab using Kali Linux, Windows 10, Sysmon, and Splunk.  
> Simulated SMB enumeration, lateral movement, credential dumping, and encoded PowerShell attacks.
> Created Splunk dashboards and detection rules to monitor and alert on malicious activity.

---

## ⚙️ Technologies & Tools Used

| Component | Description |
|------------|-------------|
| **Machines** | Windows 11(Host Laptop)/ Kali Linux VM(Attacker)/ Windows 10(Target) |
| **SIEM Platform** | Splunk Enterprise (Free version for local setup) |
| **Log Collection** | Sysmon, SplunkUniversalForwarder |
| **Virtualization** | Oracle VirtualBox |

---

## 🌐 Lab Environment / Architecture

<img width="1408" height="768" alt="Diagram" src="https://github.com/user-attachments/assets/4158e718-f381-49da-9036-bb7a15aa9aeb" />


---

## 🚨 Attack Scenarios

### 1. Brute Force Credential Attack (Windows)
- Simulated failed login attempts generating Event ID 4625
- Built SPL detection rule triggering High severity alert on 5+ failures in 60 seconds
- Created 3-panel dashboard: attack timeline, failed login count, affected accounts
- **MITRE ATT&CK:** T1110 Brute Force
- **Incident Report:** IR-2026-001

### 2. Nmap Reconnaissance (Network)
- Executed SYN scan from Kali Linux against Windows target
- Detected 8 firewall DROP events in Splunk confirming reconnaissance activity
- Built real-time alert: Nmap Reconnaissance Detected (High severity)
- **MITRE ATT&CK:** T1046 Network Service Discovery
- **Incident Report:** IR-2026-002

### 3. Phishing Email Forensic Analysis
- Analyzed PayPal impersonation sample using emlAnalyzer and manual header inspection
- Extracted IOCs: typosquatted domain, mismatched Reply-To, originating IP, credential harvesting URL
- Investigated attacker infrastructure via VirusTotal, identified bulletproof hosting provider
- **MITRE ATT&CK:** T1566 Phishing
- **Incident Report:** IR-2026-003

### 4. VPN Log Analysis: Impossible Travel Detection
- Ingested VPN logs and investigated user account connecting from 3 states across 4 IPs within 60 minutes
- Identified simultaneous sessions consistent with credential compromise
- Documented full escalation report following Tier 1 SOC procedures
- **MITRE ATT&CK:** T1078 Valid Accounts
- - **Incident Report:** IR-2026-004

---

## 📊 Key Findings & Screenshots

---

## 🔎 Detection Rules

```splunk
# Windows Brute Force Detection
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name
| where count > 5

# SSH Brute Force Detection  
index="linux_auth" "Failed Password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5

# VPN Impossible Travel Detection
index=vpn_logs
| stats dc(source_state) as unique_states by UserName
| where unique_states > 1
```


---

## 📑 Full Report PDF

