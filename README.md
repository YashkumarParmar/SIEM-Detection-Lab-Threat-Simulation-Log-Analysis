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

---

## 🚨 Attack Scenarios

| Attack | Tool Used | Objective |
|------------|-------------|-------------|
| **SMB Enumeration** | SMBClient | Enumerate SMB shares and gather information about the target system |
| **Lateral Movement** | Impacket PsExec | Obtain remote command execution on the target machine |
| **Credential Dumping** | Mimikatz | Extract credentials from memory for privilege escalation |
| **Encoded PowerShell Attack** | PowerShell | Execute obfuscated commands to simulate defense evasion techniques |

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

